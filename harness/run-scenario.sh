#!/usr/bin/env bash
# Scenario runner — Reference Test Harness Spec §2.3.
#
# Each scenario asserts an expected connection *tier*, not merely that a
# connection happened. A build that silently forces everything through the relay
# fallback is functionally working and defeats the point of tiers 1 and 2, so it
# must fail this suite rather than pass it (§2.4).
#
#   1 same-network       both peers on one LAN, no NAT       -> direct
#   2 asymmetric         NAT'd peer to a public relay        -> direct
#   3 symmetric-simple   two independent restricted NATs     -> hole-punched
#   4 asymmetric-cgnat   restricted NAT vs CGNAT chain       -> relayed
#   5 symmetric-cgnat    two independent CGNAT chains        -> relayed
#
# Scenario 5 is the guarantee the protocol must provide — a connection is always
# eventually possible, even via the least efficient path — and is exactly what
# was hardest to test manually before.
#
# Peer identities are deterministic (`--seed N`), so a peer's PeerId can be
# derived without the peer running. That is what lets a dialler construct a
# circuit address for a peer it has never contacted.

set -euo pipefail

SCENARIO="${1:-all}"
HERE="$(cd "$(dirname "$0")" && pwd)"
COMPOSE=(docker compose -f "$HERE/docker/compose.yml")
NETWORK=1
TIMEOUT=60
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
  local service="$1" seed="$2" relay="${3:-}"
  local args=(listen "--seed=$seed" "--network=$NETWORK"
              --listen=/ip4/0.0.0.0/tcp/4001 --hold-secs=180)
  [[ -n "$relay" ]] && args+=("--relay=$relay")

  "${COMPOSE[@]}" exec -d "$service" /usr/local/bin/peer-entrypoint.sh "${args[@]}"
  # Give the reservation time to be granted before anyone dials the circuit.
  sleep 5
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
  # Restricted NAT versus a CGNAT chain: hole-punching must fail *where
  # expected* and fall through to a relay circuit.
  local relay; relay="$(relay_addr)"
  start_listener peer-c 40 "$relay"
  dial_expect peer-a 41 "$relay/p2p-circuit/p2p/$(peer_id_for 40)" \
    relayed "$relay" "4 asymmetric double-NAT (CGNAT one side)"
}

scenario_5() {
  # Worst realistic case, and the one that must always succeed.
  local relay; relay="$(relay_addr)"
  start_listener peer-d 50 "$relay"
  dial_expect peer-c 51 "$relay/p2p-circuit/p2p/$(peer_id_for 50)" \
    relayed "$relay" "5 symmetric double-NAT (CGNAT both sides)"
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
    all) scenario_1; scenario_2; scenario_3; scenario_4; scenario_5 ;;
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
