# Conformance harness

CLI-based protocol conformance tooling for the specs in `../specs`. Speaks only
the vocabulary of those documents — identities, networks, groups, capabilities,
invites, connections, tiers — and deliberately contains no application concepts.

## Verification status — read this first

The tooling here is in two parts, and they are **not** equally verified.

| Part | Status |
|---|---|
| `intranet-harness` CLI | **Verified.** Builds and runs; every subcommand exercised locally. |
| Relay + health/peer-id endpoints | **Verified.** Relay started, both endpoints queried, `{"status":"ready"}` and the peer id returned. |
| Tier assertion (`dial --expect-tier`) | **Verified in both directions.** A correct expectation exits 0; a wrong one exits 1 with a conformance failure. |
| Direct connection, tier 1 | **Verified.** Two real nodes over loopback, plus IPv6-before-IPv4 preference. |
| Relay resource limits | **Verified.** 17 tests in `intranet-transport`. |
| **Docker NAT topology (`docker/`)** | **UNVERIFIED — never executed.** |
| **Scenarios 1–5 (`run-scenario.sh`)** | **UNVERIFIED — never executed.** |

Docker is not installed in the development container this was written in, so the
NAT environment has been authored but never run. Treat `docker/compose.yml`,
the NAT gateway, and `run-scenario.sh` as a first draft that should be expected
to need debugging on first execution, not as passing tests. Specific things most
likely to need adjustment:

- **Interface naming.** The gateways assume `eth0` is upstream and `eth1` is
  private, based on Docker attaching networks in declaration order. This is not
  guaranteed; if a scenario fails immediately, check `ip addr` inside a gateway
  and correct `PRIVATE_IF`/`UPSTREAM_IF`.
- **Default route replacement.** `peer-entrypoint.sh` deletes Docker's default
  route and installs one via the gateway. If that fails silently, peers reach
  `public-net` directly, every scenario passes at tier 1, and the matrix proves
  nothing. Confirm the printed route table shows the gateway.
- **Whether `MASQUERADE --random` actually defeats hole-punching.** Scenarios 4
  and 5 depend on symmetric NAT behaviour. If DCUtR succeeds where `relayed` is
  expected, the emulation is not symmetric enough and needs explicit
  per-destination port mapping rather than `--random`.
- **Reservation timing.** `start_listener` sleeps 5s for a relay reservation to
  be granted. Under a slow build this may be too short.

Spec §8 already flags exact NAT-type emulation as an open implementation task;
the above is the concrete form that takes.

## Running the verified parts

```bash
cargo test --workspace                      # 177 tests
cargo run -p intranet-harness -- --help
```

Useful commands:

```bash
# Identity and unlinkability (§1.2)
intranet-harness identity new
intranet-harness identity derive --seed 1 --network 1
intranet-harness identity unlinkability --seed 7

# Governance (§2.7)
intranet-harness governance finality        # prints k and T, both required
intranet-harness governance genesis --network 1
intranet-harness governance grinding-check --padding 20

# Transport (§5.2)
intranet-harness relay --seed 1 --network 1 --listen /ip4/0.0.0.0/tcp/4001
intranet-harness listen --seed 2 --network 1 --relay <relay-multiaddr>
intranet-harness dial --seed 3 --network 1 --peer <addr> --expect-tier direct
```

`dial` exits non-zero when the connection succeeds through the **wrong** tier,
which is the assertion that matters: a build forcing everything through the
relay fallback still connects and would otherwise look healthy.

## Running the NAT scenarios (once Docker is available)

```bash
./run-scenario.sh all     # or: ./run-scenario.sh 5
```

| # | Topology | Expected tier |
|---|---|---|
| 1 | Both peers on one LAN, no NAT | `direct` |
| 2 | NAT'd peer to public relay | `direct` |
| 3 | Two independent restricted-cone NATs | `hole-punched` |
| 4 | Restricted NAT vs CGNAT chain | `relayed` |
| 5 | Two independent CGNAT chains | `relayed` |

Scenario 5 is the one that must always succeed: a connection is always
eventually possible, even via the least efficient path.

## Not yet built

- Relay rate-limit verification *inside* the NAT environment (§2.5). The limits
  themselves are enforced and unit-tested; driving them through a live relay
  with many synthetic identities is not wired up.
- Governance partition scenarios (§3) — fork reconciliation and finality are
  tested in-process in `intranet-governance`, but not across partitioned
  containers with real gossip.
- Everything downstream of transport: storage, app hosting, real-time, search.
