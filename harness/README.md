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
| Relay resource limits | **Enforced by a live relay.** `RelayLimits` now configures the relay behaviour, and `relay_enforcement.rs` drives a real `RelayNode` and asserts a reservation past the ceiling is refused. Two gaps remain, below. |
| Everything above transport | **Verified.** Governance, storage, epoch keying, search, app registry and real-time are covered by the workspace suite; none of it needs Docker. |
| Docker NAT topology (`docker/`) | **Executed and working.** All 12 containers come up; peers reach the relay through their NATs, including both CGNAT chains. |
| Scenarios 1, 2, 4, 5 | **Passing.** |
| **Scenario 3 (hole-punching)** | **FAILING.** See *Outstanding*. |

Both halves of the gate in `../CLAUDE.md` are clean: `cargo test --workspace`
passes 440 tests and `cargo clippy --workspace --all-targets` reports no
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

**Scenario 3 — hole-punching — still fails, but two causes have been found and
fixed, and the remaining failure is narrower.**

### Fixed: reserving after a wildcard bind lost port reuse

**Status:** the scenarios still pass `--listen=/ip4/0.0.0.0/tcp/4001`, and that is
now fine — the ordering requirement lives in `MemberNode::reserve_via_relay`, not
in the call site, so a wildcard bind is handled wherever it appears. Verified
against both a loopback and a routable relay. The `external-candidate:` line a
peer prints is the direct check: it should carry the node's listening port, and
if it ever carries an ephemeral one this has regressed.

The wait was also tightened after the first fix. Waiting for *any* listener is
insufficient in principle: libp2p reuses a port only when the listener's
loopback-ness matches the remote's, so a wildcard bind reporting `127.0.0.1`
before its routable interface could satisfy a naive wait while registering
nothing the dial could use. It now waits for a listener matching the relay.


The earlier note here said libp2p had been "ruled out" as a cause. That was
**too strong**, and the tests behind it had a gap worth naming: `port_reuse.rs`
and `reservation_port.rs` bind *concrete* addresses, which register the
listening port synchronously. The scenarios bind `0.0.0.0`, which does not —
libp2p discovers interfaces asynchronously and registers each address as it
arrives. Reserving in the same breath as binding therefore found nothing to
reuse and fell back to an ephemeral source port. The two tests were correct and
structurally could not reach the bug.

It is a wildcard-plus-ordering bug, not a port-reuse bug: `PortUse::Reuse` is
libp2p's default and the relay client's reservation dial does request it.

Reproduced and fixed in `crates/intranet-transport/tests/wildcard_reservation.rs`,
which pins all four cases — concrete bind, wildcard reserving immediately (the
bug), wildcard after settling by hand, and wildcard through the new API. The bug
case is *asserted*, so if libp2p ever registers wildcard binds synchronously the
test fails and says the workaround is obsolete rather than becoming dead weight.

The fix is `MemberNode::reserve_via_relay`, which waits for listeners to
register before reserving and replays any events it consumed. It lives in the
transport layer rather than in the harness because the requirement is a property
of the protocol: any deployment binding a wildcard address and then reserving
hits it. Fixing only the scenarios — by passing concrete IPs — would have hidden
that.

### Fixed: the relayed connection was torn down mid-upgrade

libp2p's `idle_connection_timeout` defaults to **10 seconds**. A relayed
connection awaiting a DCUtR upgrade carries no traffic, so it is idle by
definition and was being closed at almost exactly the moment an upgrade would
complete. `MemberNode` now sets 60 seconds — comfortably longer than an upgrade,
still inside the 120-second maximum circuit duration a relay enforces (§5.3).

This also explains the nondeterminism recorded here previously: scenario 3
alternated between `relayed` and "no connection within 60s" because the 10-second
teardown was racing the 15-second `--upgrade-secs` window. It was a race with our
own defaults, not anything in the NAT.

### The upgrade path itself is not the problem

`crates/intranet-transport/tests/hole_punch.rs` runs the whole tier-2 flow —
relay, two reservations, a circuit dial, DCUtR — with both peers trivially
dialable, and it passes:

```
dialer connected tier=relayed
dialer connected tier=direct-ipv4
dialer hole-punch succeeded
```

So DCUtR negotiation, the upgrade, and our attribution of it to the right
connection all work. Whatever remains in the NAT environment is environmental.

That test also documents a real constraint found while writing it: `RelayNode`
refuses to advertise a loopback address as external, which is right in
production but means **a loopback-only relay is unusable** — it hands back
reservations containing no addresses. The test binds a routable interface
instead.

### Outstanding: one side's punch completes, the other never surfaces

The reported symptom is that the target logs a successfully established
`direct-ipv4` connection while the initiator never surfaces a direct connection
at all. That rules out a plain dropped SYN — the target could not have reached
`ConnectionEstablished` if nothing arrived — and it also rules out the previous
theory here: `nf_conntrack_tcp_be_liberal=1` was tried and produced byte-for-byte
the same result, so conntrack marking the reply SYN INVALID is not what is
happening. The setting is left in place as harmless, but it is not the fix.

Two things that were obscuring the evidence have been fixed:

- **`dial` returned as soon as DCUtR reported failure.** Only our *own* dial's
  outcome reaches us; a punch has both peers dialling at once. If ours fails
  while the peer's succeeds, their connection arrives as an ordinary inbound one
  — moments after we had already returned `relayed`. That alone could produce
  exactly the reported asymmetry. `dial` now waits out the upgrade window
  instead, which costs nothing when the punch has genuinely failed.
- **Dial failures were discarded.** `OutgoingConnectionError` never reached the
  event stream, so "the punch failed" came with no account of *why*. It is now
  reported as `dial-failed: peer=… error=…`, and refused, timed out and never
  left are three different faults with three different fixes.

The next run should therefore show, on the initiator, either a late direct
connection it previously never waited for, or a concrete dial error. Either is
decisive; before, neither was observable.

### Superseded: one side's SYN is being dropped

The reported symptom is asymmetric — the target logs a real direct connection
while the initiator reports the punch as failed. That asymmetry is the useful
clue: A's SYN reached B, so B's gateway admitted it, while B's SYN did not reach
A, so A's gateway dropped it.

This theory has been **tested and disproved** — see above. Retained only so it is
not proposed again.

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
  and precisely what DCUtR will hand to a remote peer to dial. It should now
  carry the node's *listening* port; if it ever carries an ephemeral one again,
  port reuse has regressed and tier 2 cannot work.
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
cargo test --workspace                      # 440 tests
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

- **Refusing service to identities that are not current members.** A live relay
  now enforces its ceilings, and because a PeerId here is derived from a
  per-network identity (§1.2) those ceilings cannot be shrugged off by rotating a
  peer ID, as they could in a generic libp2p deployment. But nothing yet stops an
  attacker presenting freshly generated keypairs that were never admitted, so the
  cost the per-identity limit assumes is not actually being charged.
- **Per-invite metering for pre-admission identities** (§5.3). `RelayGuard`
  models it and is unit-tested, but a relay cannot apply it until it learns which
  invite a connecting node used — a protocol addition, not a wiring one.
- **Any IPv6 scenario.** The topology is IPv4 only — every network in
  `docker/compose.yml` is an IPv4 subnet and the peers bind `/ip4/...`. So the
  matrix cannot tell us whether §5.2's tier-1 IPv6 preference works, and cannot
  exercise the case that matters most for real deployments: a peer behind CGNAT,
  where IPv4 hole-punching may be impossible but a globally-routable IPv6 address
  needs no traversal at all. The ordering itself is unit-tested
  (`dial.rs`, and `conformance.rs` over loopback), but end to end it is unproven.
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
