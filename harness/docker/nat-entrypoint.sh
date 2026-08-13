#!/bin/bash
# NAT gateway — Reference Test Harness Spec §2.2.
#
# Environment:
#   PRIVATE_IF   interface facing the private network      (default eth0)
#   UPSTREAM_IF  interface facing the upstream network     (default eth1)
#   NAT_MODE     "restricted" (default) or "symmetric"
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

PRIVATE_IF="${PRIVATE_IF:-eth0}"
UPSTREAM_IF="${UPSTREAM_IF:-eth1}"
NAT_MODE="${NAT_MODE:-restricted}"

echo "nat-gateway: private=${PRIVATE_IF} upstream=${UPSTREAM_IF} mode=${NAT_MODE}"

sysctl -w net.ipv4.ip_forward=1 >/dev/null

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
exec sleep infinity
