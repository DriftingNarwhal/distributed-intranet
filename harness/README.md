# Conformance harness

CLI-based protocol conformance tooling for the specs in `../specs`. Speaks only
the vocabulary of those documents — identities, networks, groups, capabilities,
invites, connections, tiers — and deliberately contains no application concepts.

## Verification status — read this first

The NAT environment has now been executed. It previously had not been, and
getting it to run took seven fixes; see *What the first execution found* below,
because several of them were defects in the implementation rather than in the
harness.

| Part | Status |
|---|---|
| `intranet-harness` CLI | **Verified.** Builds and runs; every subcommand exercised locally. |
| Relay + health/peer-id endpoints | **Verified, but see below.** Both endpoints answer and the peer id is returned. This is *not* evidence the relay is usable: it reported ready while granting reservations that no client could accept. |
| Tier assertion (`dial --expect-tier`) | **Verified in both directions.** A correct expectation exits 0; a wrong one exits 1 with a conformance failure. |
| Direct connection, tier 1 | **Verified.** Two real nodes over loopback, plus IPv6-before-IPv4 preference. |
| Relay resource limits | **Unit-tested only.** 17 tests in `intranet-transport`; the limits are not wired into `RelayNode`'s event loop and are not exercised by a live relay. |
| Everything above transport | **Verified.** Governance, storage, epoch keying, search, app registry and real-time are covered by the workspace suite; none of it needs Docker. |
| Docker NAT topology (`docker/`) | **Executed and working.** All 12 containers come up; peers reach the relay through their NATs, including both CGNAT chains. |
| Scenarios 1, 2, 4, 5 | **Passing.** |
| **Scenario 3 (hole-punching)** | **FAILING.** See *Outstanding*. |

Both halves of the gate in `../CLAUDE.md` are clean: `cargo test --workspace`
passes 430 tests and `cargo clippy --workspace --all-targets` reports no
warnings, including over the fixes described below. Note that clippy is absent
from a source-tarball rustc with no rustup; on Debian/Ubuntu
`sudo apt install rust-clippy` supplies a matching version.

## What the first execution found

The environment had never been run, and nothing in it worked end to end. The
fixes are in the files listed; the reasoning is preserved in comments at each
site rather than repeated here.

1. **Every NAT gateway exited immediately.** `nat-entrypoint.sh` set
   `net.ipv4.ip_forward` via `sysctl -w`, but `/proc/sys` is read-only in the
   container and `set -e` turned that into an exit. Compose already sets it via
   `sysctls:`; the script now asserts it instead.
2. **Every peer exited immediately.** The peer services ran `--help` behind an
   entrypoint that `exec`s the CLI, while the scenarios drive them with
   `docker compose exec`, which needs a running container. Peers now take an
   `idle` command that sets up routing and holds.
3. **`PRIVATE_IF`/`UPSTREAM_IF` were unreliable.** Docker does not attach
   networks in declaration order — and the order it uses is **not stable between
   invocations of the same service**. `gw-c-home` was observed with `lan-c` on
   `eth0` in one run and on `eth1` in the next. No static pair can be correct, so
   the gateway now derives both interfaces at runtime by matching addresses
   against `UPSTREAM_SUBNET`, and exits loudly if it cannot classify them.
4. **The CGNAT home gateways had no default route.** Sitting between two
   `internal: true` networks, they got no gateway from Docker at all, so upstream
   traffic had nowhere to go. They now take `UPSTREAM_GW`.
5. **`internal: true` is incompatible with routing through a gateway container.**
   Docker implements it with a host rule dropping anything on the bridge whose
   destination is outside the bridge subnet — which is every packet a NAT exists
   to translate. Peers could reach their gateway's LAN address and nothing
   beyond it. It has been removed from the private networks. Isolation now rests
   entirely on `peer-entrypoint.sh` replacing the default route, which is why
   that script now *asserts* the replacement rather than assuming it.
6. **`peer_id_for` collided with the running relay.** It used `docker compose
   run` against a service pinning a static `ipv4_address`. The second container
   failed with "Address already in use", the function returned an empty string,
   and that composed into an address ending in `/p2p/` which failed much later as
   "invalid multihash". It now execs in the running relay and fails loudly on an
   empty id.
7. **`RelayNode` never called `add_external_address`** — the one that mattered.
   libp2p builds the addresses it hands back in a reservation from the swarm's
   *external* addresses and never infers them from listen addresses. The relay
   therefore accepted every reservation and returned an empty address list, and
   every client rejected it with `NoAddressesInReservation`. Tiers 2 and 3 were
   dead while tier 1 kept working and `/health` still reported ready. This is
   why the relay row above is hedged.

Two further defects were in `dial.rs` itself, both of which made the tier
assertion report the wrong answer:

- It returned on the **first** connection rather than the target's. Since
  reserving opens a direct connection to the relay, every scenario passing
  `--relay` reported that connection instead — a false `direct` pass regardless
  of how the target was actually reached. It now filters on the peer id taken
  from the last `/p2p/` of the candidate address.
- It had no path to report a settled `relayed` connection, waiting instead for a
  `HolePunchFailed` event that a transport-level failure never emits. A working
  tier-3 circuit would sit open until the overall timeout and be reported as no
  connection at all. There is now an `--upgrade-secs` window (default 15s) after
  which a relayed connection is accepted as the settled tier.

Building also requires a `.dockerignore` at the repo root excluding `target/`;
without it the build context is roughly 14 GB.

## Outstanding

**Scenario 3 — hole-punching between two restricted-cone NATs — does not work.**
DCUtR dials the peer at its NAT's *ephemeral* external port and gets
`ConnectionRefused`.

**The libp2p half of that has now been ruled out.** It was the candidate flagged
here as "more likely and more serious", so it was tested first, on loopback where
there is no NAT to blame:

- `crates/intranet-transport/tests/port_reuse.rs` — ordinary outbound dials
  originate from the listening port, including a second concurrent dial to a
  different peer.
- `crates/intranet-transport/tests/reservation_port.rs` — the connection opened
  to obtain a *relay reservation* does too, which is the one whose observed
  address DCUtR advertises.

Port reuse is also the libp2p default (`PortUse::Reuse`), and DCUtR advertises
its own candidate set fed from `NewExternalAddrCandidate`, i.e. exactly the
addresses peers report observing. Running a relay and a member on loopback shows
`external-candidate` carrying the member's *listening* port.

So the remaining explanation is the NAT emulation: `MASQUERADE` is not preserving
the source port, or is not admitting the return path a restricted-cone NAT would.
**The next run should read the `external-candidate:` line a peer now prints.** If
it carries a port other than 4001, the NAT is remapping and the fix is in
`nat-entrypoint.sh` — `--to-ports 4001` on the SNAT rule, or `SNAT` in place of
`MASQUERADE`, would preserve it. If it carries 4001, the mapping is right and the
problem is the inbound path instead: Linux conntrack admits a peer's SYN only if
it matches an existing flow's reply direction, which is a narrower behaviour than
a real restricted-cone NAT and may simply not survive TCP simultaneous open.

Note this is the *opposite* of what was originally predicted here: the concern was
that `MASQUERADE --random` might not be symmetric enough to defeat hole-punching,
whereas hole-punching currently fails even in `restricted` mode.

The failure is also **not deterministic in its shape**. Across runs, scenario 3
reports either `relayed` (connected through the wrong tier) or no connection
within 60s — the relayed connection to the peer sometimes drops before the
upgrade window elapses. Whatever tears it down is not yet understood and may be
the same root cause.

Scenarios 4 and 5 pass, so the fallback path the protocol guarantees does hold:
scenario 5, the worst realistic case and the one that must always succeed, ends
in a working relayed circuit.

## Diagnosing a scenario

Logging is now wired up. `RUST_LOG` reaches the transport layer, and swarm
events the node has no opinion on are traced rather than silently discarded —
that silence is why defect 7 below was invisible.

```bash
RUST_LOG=intranet_transport=trace,libp2p_dcutr=debug,libp2p_relay=debug \
  ./run-scenario.sh 3
```

Peers also print two lines that matter more than the rest:

- `external-candidate: <addr>` — the address a peer reports seeing this node at,
  and precisely what DCUtR will hand to a remote peer to dial. **If this is not a
  port the node listens on, tier 2 cannot work**, and no other output will say so.
- `external-confirmed: <addr>` — an address confirmed reachable. libp2p does not
  promote candidates on its own, since one peer observing an address does not make
  it reachable by another.

## Scope of what passing means

A green run here validates **connectivity and tier selection**. It is not an
end-to-end test. The scenarios assert which path a connection took; no
governance entry, stored object or application message crosses these circuits.
Nothing above the transport layer participates.

## Running the verified parts

```bash
cargo test --workspace                      # 430 tests
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

## Running the NAT scenarios

```bash
./run-scenario.sh all     # or: ./run-scenario.sh 5
```

| # | Topology | Expected tier | Status |
|---|---|---|---|
| 1 | Both peers on one LAN, no NAT | `direct` | pass |
| 2 | NAT'd peer to public relay | `direct` | pass |
| 3 | Two independent restricted-cone NATs | `hole-punched` | **fail** |
| 4 | Restricted NAT vs CGNAT chain | `relayed` | pass |
| 5 | Two independent CGNAT chains | `relayed` | pass |

Scenario 5 is the one that must always succeed: a connection is always
eventually possible, even via the least efficient path.

The suite tears the topology down on exit, including on failure, which makes
diagnosis awkward — bring it up with `docker compose -f docker/compose.yml up -d`
and drive the peers by hand instead.

## Not yet built

- Relay rate-limit verification *inside* the NAT environment (§2.5). The limits
  are unit-tested but are not wired into `RelayNode`, so a live relay does not
  enforce them at all.
- Governance partition scenarios (§3) — fork reconciliation and finality are
  tested in-process in `intranet-governance`, but not across partitioned
  containers with real gossip.
- Harness CLI coverage for the layers built after transport. Storage, search,
  the app registry and real-time are covered by the workspace test suite but are
  not yet drivable from the command line, so they cannot participate in a
  multi-container scenario.
- Gossip actually moving governance entries and capability advertisements over
  the transport layer. Both sides exist; nothing yet joins them, which is why
  the partition scenarios above are not runnable.
