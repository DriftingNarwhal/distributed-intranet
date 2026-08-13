#!/bin/bash
# Peer entrypoint — routes this container's traffic through its NAT gateway.
#
# Docker installs its own default route on whichever network it attaches first.
# A peer that keeps that route reaches `public-net` directly and never traverses
# the NAT at all, which would make every scenario pass at tier 1 and silently
# invalidate the entire matrix. Replacing the default route is therefore not
# setup detail — it is what puts the NAT in the path.
#
# Environment:
#   GATEWAY_IP  the NAT gateway's address on this peer's private network
#   Remaining arguments are passed to the harness CLI.

set -euo pipefail

if [[ -n "${GATEWAY_IP:-}" ]]; then
  echo "peer: routing default via ${GATEWAY_IP}"
  ip route del default 2>/dev/null || true
  ip route add default via "${GATEWAY_IP}"
fi

echo "peer: routes"
ip route

exec /usr/local/bin/intranet-harness "$@"
