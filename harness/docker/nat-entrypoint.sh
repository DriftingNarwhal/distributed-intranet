#!/bin/bash
# NAT gateway — Reference Test Harness Spec §2.2.
#
# Environment:
#   UPSTREAM_SUBNET  dotted prefix of the upstream network, e.g. "172.30.0."
#   UPSTREAM_GW      next hop toward public-net; needed only on the home
#                    gateways of a CGNAT chain (see below)
#   NAT_MODE         "restricted" (default) or "symmetric"
#
# Interfaces are DERIVED at runtime by matching addresses against
# UPSTREAM_SUBNET rather than passed in as fixed names. Docker does not attach
# networks in declaration order, and the order it does use is not stable between
# invocations of the same service — gw-c-home was observed with lan-c on eth0 in
# one run and on eth1 in the next. Any static PRIVATE_IF/UPSTREAM_IF pair is
# therefore wrong about half the time, and wrong *silently*: masquerading toward
# the LAN instead of upstream still forwards traffic, so scenarios would pass at
# tier 1 and prove nothing (§2.4).
#
# NAT_MODE is what makes the scenario matrix meaningful rather than uniform:
#
#   restricted  Endpoint-independent mapping. The same internal source reuses
#               one external port across destinations, so a peer learns a
#               stable external address and DCUtR hole-punching can succeed —
#               the expected common case for two home routers (§2.3 scenario 3).
#
#   symmetric   Endpoint-dependent mapping. A different external port is chosen
#               per destination, so the address a peer learns via a relay is not
#               the address its peer must punch to. Hole-punching correctly
#               fails and the connection must fall through to a relay circuit
#               (§2.3 scenarios 4 and 5).
#
# Getting this distinction right is the whole point of the environment: a
# simulation where every NAT behaves the same cannot show that tier 2 succeeds
# where it should and fails where it should.

set -euo pipefail

NAT_MODE="${NAT_MODE:-restricted}"
UPSTREAM_SUBNET="${UPSTREAM_SUBNET:?UPSTREAM_SUBNET is required}"

# Derive the two interfaces from their addresses. Exactly one must sit on the
# upstream subnet and exactly one must not; anything else means the topology is
# not what this script assumes, and continuing would build a NAT that quietly
# translates the wrong direction.
PRIVATE_IF=""
UPSTREAM_IF=""
for _if in $(ls /sys/class/net); do
  [ "${_if}" = "lo" ] && continue
  _addr="$(ip -o -4 addr show dev "${_if}" 2>/dev/null | awk '{print $4}' | cut -d/ -f1)"
  [ -z "${_addr}" ] && continue
  case "${_addr}" in
    "${UPSTREAM_SUBNET}"*) UPSTREAM_IF="${_if}" ;;
    *)                     PRIVATE_IF="${_if}"  ;;
  esac
done

if [ -z "${UPSTREAM_IF}" ] || [ -z "${PRIVATE_IF}" ]; then
  echo "nat-gateway: could not classify interfaces against '${UPSTREAM_SUBNET}'" >&2
  ip -o -4 addr show >&2
  exit 1
fi

echo "nat-gateway: private=${PRIVATE_IF} upstream=${UPSTREAM_IF} mode=${NAT_MODE}"

# ip_forward is set by compose's `sysctls:` key. /proc/sys is mounted read-only
# in the container, so setting it again here is not merely redundant, it aborts
# the gateway under `set -e` and leaves the scenario with no NAT in the path.
[ "$(cat /proc/sys/net/ipv4/ip_forward)" = "1" ] || {
  echo "nat-gateway: ip_forward is not enabled" >&2; exit 1; }

# The home gateway of a CGNAT chain sits between two `internal: true` networks,
# so Docker installs no default route on it at all and upstream traffic has
# nowhere to go. The CGNAT scenarios (4 and 5) cannot work without this.
if [ -n "${UPSTREAM_GW:-}" ]; then
  echo "nat-gateway: routing default via ${UPSTREAM_GW}"
  ip route del default 2>/dev/null || true
  ip route add default via "${UPSTREAM_GW}"
fi

# Default-deny forwarding. Established and related flows are allowed back, and
# anything originating on the private side may go out; unsolicited inbound from
# upstream is dropped, which is the behaviour being simulated.
iptables -P FORWARD DROP
iptables -F FORWARD
iptables -t nat -F

iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -i "${PRIVATE_IF}" -o "${UPSTREAM_IF}" -j ACCEPT

case "${NAT_MODE}" in
  restricted)
    # MASQUERADE keeps the source port stable where it can, giving
    # endpoint-independent mapping.
    iptables -t nat -A POSTROUTING -o "${UPSTREAM_IF}" -j MASQUERADE
    ;;
  symmetric)
    # --random forces a fresh port selection per flow, which is what makes the
    # mapping endpoint-dependent and defeats hole-punching.
    iptables -t nat -A POSTROUTING -o "${UPSTREAM_IF}" -j MASQUERADE --random
    ;;
  *)
    echo "nat-gateway: unknown NAT_MODE '${NAT_MODE}'" >&2
    exit 1
    ;;
esac

echo "nat-gateway: ready"
iptables -t nat -L POSTROUTING -n
ip route
exec sleep infinity
