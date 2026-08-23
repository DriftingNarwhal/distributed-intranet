#!/usr/bin/env bash
# Scenario runner — Reference Test Harness Spec §2.3.
#
# Each scenario asserts an expected connection *tier*, not merely that a
# connection happened. A build that silently forces everything through the relay
# fallback is functionally working and defeats the point of tiers 1 and 2, so it
# must fail this suite rather than pass it (§2.4).
#
#   1 same-network       both peers on one LAN, no NAT        -> direct
#   2 asymmetric         NAT'd peer to a public relay         -> direct
#   3 symmetric-simple   two independent restricted NATs      -> hole-punched
#   4 asymmetric-cgnat   restricted NAT vs CGNAT, v4 only     -> none
#   5 symmetric-cgnat    two CGNAT chains, dual-stack         -> direct-ipv6
#   6 symmetric-cgnat    the same pair with no v6 path        -> none
#
# **Scenarios 4 and 6 expect no connection, and that is the correction rather
# than a regression.** An earlier version of this file asserted `relayed` for
# both, on the reasoning that "a connection is always eventually possible, even
# via the least efficient path". §5.2 was corrected on 2026-08-22 to say the
# opposite: there is no third tier, a circuit carries the DCUtR negotiation and
# is closed when the upgrade fails, and a pair that cannot punch reaches each
# other over IPv6 or not at all. A relayed connection that persists is now the
# defect, so asserting it would have kept the suite green against code that had
# stopped conforming — the failure §2.4 exists to catch, one level up.
#
# Scenario 5 is therefore the guarantee the protocol actually provides: the
# worst realistic case still succeeds, and it succeeds at **tier 1 over IPv6**,
# which is why asserting the tier rather than mere connectivity is the whole
# point (§2.4). Scenario 6 is its control — take the v6 path away and the same
# pair must not connect at all.
#
# Peer identities are deterministic (`--seed N`), so a peer's PeerId can be
# derived without the peer running. That is what lets a dialler construct a
# circuit address for a peer it has never contacted.

set -euo pipefail

SCENARIO="${1:-all}"
HERE="$(cd "$(dirname "$0")" && pwd)"
COMPOSE=(docker compose -f "$HERE/docker/compose.yml")
NETWORK=1
# Must exceed the dial command's own upgrade window (35s), which must in turn
# exceed the transport's circuit deadline (25s) — the later timer is the one that
# decides, and a scenario asserting `none` is waiting for the *transport* to
# close the circuit. Ordered wrong, this reports on the harness rather than on
# the node.
TIMEOUT=90
FAILURES=0

log()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$*"; FAILURES=$((FAILURES + 1)); }
pass() { printf '\033[32mPASS\033[0m %s\n' "$*"; }

# Derives a peer id inside the already-running relay.
#
# `docker compose run` cannot be used here: every service in this topology pins
# a static ipv4_address, so a second container for the same service collides
# with the running one ("Address already in use"). That failure is silent to the
# caller — it yields an empty peer id, which composes into an address ending in
# `/p2p/` and fails much later as "invalid multihash".
peer_id_for() {
  local id
  id="$("${COMPOSE[@]}" exec -T relay /usr/local/bin/intranet-harness \
        identity derive --seed="$1" --network="$NETWORK" | awk '/^peer-id:/ {print $2}')"
  if [[ -z "$id" ]]; then
    echo "peer_id_for: could not derive a peer id for seed $1" >&2
    exit 1
  fi
  printf '%s' "$id"
}

relay_peer_id() {
  "${COMPOSE[@]}" exec -T relay curl -fsS http://127.0.0.1:8080/peer-id \
    | sed 's/.*"peer_id":"\([^"]*\)".*/\1/'
}

relay_addr() { echo "/ip4/172.30.0.10/tcp/4001/p2p/$(relay_peer_id)"; }

# Starts a listener inside a container, in the background.
#   start_listener <service> <seed> [relay-addr]
start_listener() {
  local service="$1" seed="$2" relay="${3:-}" extra_listen="${4:-}"
  local args=(listen "--seed=$seed" "--network=$NETWORK"
              --listen=/ip4/0.0.0.0/tcp/4001 --hold-secs=180)
  # A v6 scenario needs the listener bound on v6 as well: binding only
  # 0.0.0.0 leaves the tier-1 path with nothing answering on it, and the
  # scenario would then fail for a reason that has nothing to do with the
  # topology it is testing.
  [[ -n "$extra_listen" ]] && args+=("--listen=$extra_listen")
  [[ -n "$relay" ]] && args+=("--relay=$relay")

  "${COMPOSE[@]}" exec -d "$service" /usr/local/bin/peer-entrypoint.sh "${args[@]}"
  # Give the reservation time to be granted before anyone dials the circuit.
  sleep 5
}

# Takes a peer's default IPv6 route away and puts it back, which is how
# scenario 6 expresses "the same pair with no v6 path".
#
# Asserted rather than assumed, in both directions. A silent failure here would
# leave scenario 6 running with the v6 path still up, and its expectation is an
# *absence* — so it would fail loudly and for entirely the wrong reason, which
# is the most expensive kind of test failure to diagnose.
#   v6_default <off|on> <service>...
v6_default() {
  local action="$1"; shift
  local service
  for service in "$@"; do
    local gw
    gw="$("${COMPOSE[@]}" exec -T "$service" printenv V6_GATEWAY_IP | tr -d '\r')"
    if [[ -z "$gw" ]]; then
      echo "v6_default: $service has no V6_GATEWAY_IP" >&2; exit 1
    fi
    case "$action" in
      off) "${COMPOSE[@]}" exec -T "$service" ip -6 route del default >/dev/null 2>&1 || true ;;
      on)  "${COMPOSE[@]}" exec -T "$service" ip -6 route replace default via "$gw" >/dev/null ;;
    esac
    local has
    has="$("${COMPOSE[@]}" exec -T "$service" ip -6 route show default | tr -d '\r')"
    case "$action" in
      off) [[ -z "$has" ]] || { echo "v6_default: $service still has a v6 default route" >&2; exit 1; } ;;
      on)  [[ -n "$has" ]] || { echo "v6_default: $service did not regain its v6 default route" >&2; exit 1; } ;;
    esac
  done
  echo "v6 default route: $action for $*"
}

#   dial_expect <service> <seed> <target-multiaddr> <expected-tier> [relay-addr] <label>
dial_expect() {
  local service="$1" seed="$2" target="$3" expected="$4" relay="$5" label="$6"
  log "$label — expecting tier: $expected"

  local args=(dial "--seed=$seed" "--network=$NETWORK"
              --listen=/ip4/0.0.0.0/tcp/4001
              "--peer=$target" "--expect-tier=$expected" "--timeout-secs=$TIMEOUT")
  [[ -n "$relay" ]] && args+=("--relay=$relay")

  if "${COMPOSE[@]}" exec -T "$service" /usr/local/bin/peer-entrypoint.sh "${args[@]}"; then
    pass "$label"
  else
    fail "$label (expected tier $expected)"
  fi
}

bring_up() {
  log "building and starting topology"
  "${COMPOSE[@]}" up -d --build
  log "waiting for relay health"
  for _ in $(seq 1 30); do
    if "${COMPOSE[@]}" exec -T relay curl -fsS http://127.0.0.1:8080/health 2>/dev/null \
        | grep -q ready; then
      pass "relay ready"
      return
    fi
    sleep 2
  done
  fail "relay never became ready"
  exit 1
}

tear_down() { "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true; }

scenario_1() {
  # Sanity floor: no NAT in path. Also confirms mDNS discovery does not itself
  # dial (§5.1) — the peer logs `(not dialled)` and connects only when told to.
  start_listener peer-a2 20
  dial_expect peer-a 21 "/ip4/172.31.1.11/tcp/4001/p2p/$(peer_id_for 20)" \
    direct "" "1 same-network baseline"
}

scenario_2() {
  # One side NAT'd, one directly reachable: exercises direct dial on its own.
  dial_expect peer-a 22 "$(relay_addr)" direct "" "2 asymmetric"
}

scenario_3() {
  # Two independent restricted-cone NATs — the expected case for two home
  # networks. Both sides reserve through the relay, since DCUtR negotiates
  # between peers and needs both reachable.
  local relay; relay="$(relay_addr)"
  start_listener peer-b 30 "$relay"
  dial_expect peer-a 31 "$relay/p2p-circuit/p2p/$(peer_id_for 30)" \
    hole-punched "$relay" "3 symmetric-simple (restricted NAT both sides)"
}

scenario_4() {
  # Restricted NAT versus a CGNAT chain, IPv4 only — peer-a has no v6 address
  # at all, so this pair has no second path to fall to.
  #
  # Hole-punching must fail here, and the circuit that carried the negotiation
  # must then be closed rather than used (§5.2). The assertion is an absence, so
  # it costs the full timeout; that is the price of testing a rule whose whole
  # content is that something does *not* happen.
  local relay; relay="$(relay_addr)"
  start_listener peer-c 40 "$relay"
  dial_expect peer-a 41 "$relay/p2p-circuit/p2p/$(peer_id_for 40)" \
    none "$relay" "4 asymmetric double-NAT, v4 only (no connection expected)"
}

scenario_5() {
  # The worst realistic case that must still succeed — two CGNAT chains with
  # globally-routable IPv6 either side — and it must succeed at **tier 1**.
  #
  # No relay is involved and none is needed: v6 has no translation layer, so the
  # dialler is given peer-d's v6 address directly and connects to it. Asserting
  # `direct-ipv6` rather than `direct` is deliberate — a v4 path that somehow
  # worked here would satisfy the weaker assertion and prove the opposite of
  # what the scenario is for.
  start_listener peer-d 50 "" "/ip6/::/tcp/4001"
  dial_expect peer-c 51 "/ip6/fd00:31:5::10/tcp/4001/p2p/$(peer_id_for 50)" \
    direct-ipv6 "" "5 symmetric double-NAT, dual-stack (IPv6 at tier 1)"
}

scenario_6() {
  # Scenario 5's control: the same pair, the same NATs, no v6 path. §5.2 says
  # they reach each other over IPv6 or not at all, so with v6 removed the
  # expected outcome is no connection.
  #
  # The route is taken away rather than the addresses, and put back afterwards,
  # so this scenario leaves the topology as it found it and can run in any
  # order. The alternative — a second pair of peers behind a second pair of
  # gateways, identical but for one route — would double the CGNAT half of the
  # topology to express one difference.
  local relay; relay="$(relay_addr)"
  v6_default off peer-c peer-d
  start_listener peer-d 60 "$relay"
  dial_expect peer-c 61 "$relay/p2p-circuit/p2p/$(peer_id_for 60)" \
    none "$relay" "6 symmetric double-NAT, v4 only (no connection expected)"
  v6_default on peer-c peer-d
}

main() {
  command -v docker >/dev/null || { echo "docker is required but not installed" >&2; exit 127; }
  trap tear_down EXIT
  bring_up

  case "$SCENARIO" in
    1) scenario_1 ;;
    2) scenario_2 ;;
    3) scenario_3 ;;
    4) scenario_4 ;;
    5) scenario_5 ;;
    6) scenario_6 ;;
    all) scenario_1; scenario_2; scenario_3; scenario_4; scenario_5; scenario_6 ;;
    *) echo "unknown scenario '$SCENARIO' (expected 1-5 or 'all')" >&2; exit 2 ;;
  esac

  log "scenarios complete"
  if (( FAILURES > 0 )); then
    printf '\033[31m%d scenario(s) failed\033[0m\n' "$FAILURES"
    exit 1
  fi
  printf '\033[32mall scenarios passed\033[0m\n'
}

main "$@"
