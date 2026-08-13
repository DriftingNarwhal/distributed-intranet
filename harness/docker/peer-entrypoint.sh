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
#   Remaining arguments are passed to the harness CLI, except for the single
#   argument `idle`, which sets up routing and then holds the container open.
#
# `idle` exists because run-scenario.sh drives peers with `docker compose exec`,
# which needs an already-running container. A peer whose command is a CLI
# invocation execs it, exits, and every scenario then fails at its first step.

set -euo pipefail

if [[ -n "${GATEWAY_IP:-}" ]]; then
  echo "peer: routing default via ${GATEWAY_IP}"
  ip route del default 2>/dev/null || true
  ip route add default via "${GATEWAY_IP}"

  # Assert rather than assume. The LAN bridges are no longer `internal: true`
  # (Docker's isolation rule is incompatible with routing through a gateway
  # container), so this route is the only thing keeping the NAT in the path. If
  # it were missing, peers would reach public-net directly, every scenario would
  # pass at tier 1, and the matrix would prove nothing (§2.4).
  actual="$(ip route show default | awk '{print $3}')"
  if [[ "${actual}" != "${GATEWAY_IP}" ]]; then
    echo "peer: default route is '${actual}', expected '${GATEWAY_IP}'" >&2
    exit 1
  fi
fi

echo "peer: routes"
ip route

if [[ "${1:-}" == "idle" ]]; then
  echo "peer: idle, awaiting exec"
  exec sleep infinity
fi

exec /usr/local/bin/intranet-harness "$@"
