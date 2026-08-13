# Distributed intranet

A protocol for many independent, mutually-unlinkable peer-to-peer networks, each
with its own membership, governance, encryption, storage, and search. No
required central authority: bootstrap relays exist only to solve cold start, and
nothing in steady-state operation depends on one.

The design lives in [`specs/`](specs/) across six documents. **They are
authoritative** — the code implements them, and where an implementation choice
was not covered by them it is flagged in a comment at the point of the choice
rather than decided silently.

## Status

Every specification document has an implementation. **438 tests, clippy clean.**

| Spec | Status |
|---|---|
| 01 Core protocol — identity, governance, epoch keying, transport | Implemented |
| 02 Storage & replication | Implemented |
| 03 App hosting — name registry, manifests, publishing policy | Implemented, **except the execution sandbox** |
| 04 Real-time transport — calls, streams, VOD | Implemented |
| 05 Search & indexing | Implemented |
| 06 Reference test harness | CLI implemented; NAT scenarios executed, **4 of 5 passing** |

### The two things that are not done, and why

**Hole-punching does not work, and tier 2 is unverified.** The Docker NAT
scenarios have now been run. Scenarios 1, 2, 4 and 5 pass; **scenario 3, the
only one asserting a hole-punched connection, fails** — DCUtR dials the peer's
ephemeral NAT port rather than one mapped to its listener.

Two causes have since been found and fixed in the transport layer — reserving a
relay circuit straight after a wildcard bind lost port reuse, and a 10-second
idle timeout tore the relayed connection down mid-upgrade. Both were protocol
bugs rather than harness ones. With those fixed the traversal itself works and a
real direct connection is made, but DCUtR still reports the upgrade as failed;
see [`harness/README.md`](harness/README.md).

First execution needed seven fixes, and the expectation that bugs would be
confined to the harness was wrong — the most serious was in `intranet-transport`:
`RelayNode` never registered an external address, so it granted every reservation
with an empty address list and no client could accept one. Tiers 2 and 3 were
dead while tier 1 worked and the relay's health check reported ready. Two more
were in the harness's own tier assertion, which reported `direct` for connections
it had not actually made to the target. Treat "the tests pass" here with the
corresponding caution: passing scenarios validate connectivity and tier
selection, not end-to-end behaviour.

**The app execution sandbox is not implemented and not stubbed.** Nothing in
`intranet-app` will tell a caller an app is safe to run — it settles which bytes
are the app and whether it is servable, and stops there. Webview isolation,
platform-enforced CSP, and capability prompts are an embedding job against a
real browser engine, and depend on target platform.

## Layout

```
specs/     the six design documents — authoritative
crates/    the implementation, one crate per layer
harness/   Docker NAT topology and scenario runner
```

Crates, roughly bottom-up:

| Crate | What it owns |
|---|---|
| `intranet-crypto` | Canonical encoding, hashing, signing, key agreement, timestamps |
| `intranet-identity` | Master seeds, per-network derivation, devices, PeerIds |
| `intranet-governance` | Capabilities, groups, the log, fork choice, finality, votes |
| `intranet-invite` | Invites and the explicit-intake waiting room |
| `intranet-ledger` | Capability advertisements, HRW placement, reliability audit |
| `intranet-transport` | libp2p stack, connection tiers, relay resource limits |
| `intranet-epoch` | MLS group keying, epoch key retention until finality |
| `intranet-storage` | Chunking, envelope encryption, pointers, append-sets, repair |
| `intranet-search` | Tokenisation, postings, the distributed inverted index |
| `intranet-app` | App name registry, manifests, publishing policy |
| `intranet-realtime` | Call topology, blind relaying, live streams, VOD |
| `intranet-harness` | The conformance CLI |

## Building and testing

```bash
cargo test --workspace      # 438 tests
cargo clippy --workspace --all-targets
cargo run -p intranet-harness -- --help
```

Rust 1.85+ (edition 2024). No services, no network access, and no external
state are needed for the test suite.

Both stay clean. `clippy` needs a toolchain that ships it; a source-tarball rustc
with no rustup does not. On Debian/Ubuntu, `sudo apt install rust-clippy`.

## Running the NAT scenarios

Requires Docker, and a `.dockerignore` excluding `target/` — without one the
build context is roughly 14 GB.

```bash
./harness/run-scenario.sh all     # or: ./harness/run-scenario.sh 5
```

Scenario 3 currently fails; the other four pass. Read
[`harness/README.md`](harness/README.md) first — it separates what is verified
from what is not, and records what the first execution found.

## Principles the code follows

These recur throughout and explain a lot of otherwise-surprising choices.

- **Fail closed.** Anywhere authorization or key availability is uncertain, the
  operation is refused rather than downgraded. Unregistered capabilities,
  unknown groups, and empty key deliveries are errors, not permissive defaults.
- **Authorization is a computation, not a query.** Every "may they?" is answered
  by replaying the governance log, never by asking a trusted party.
- **Determinism where it is load-bearing.** Entry hashes, replica placement,
  quorum outcomes, and pointer tie-breaks must resolve identically on every
  node. Encoding is hand-written per type and placement arithmetic is integer,
  because both would otherwise depend on things the protocol does not control.
- **Local-only signals never feed cross-node computation.** Reliability
  observations are private per observer, so they may bias local source and relay
  selection but can never influence placement — enforced by the type signatures,
  not by convention.
- **Honest guarantees.** Where a limit is unavoidable it is stated rather than
  overclaimed: revocation blocks future access but cannot un-know a key already
  held; serving converges rather than blocking instantly; VOD opt-out prevents a
  platform record but not a viewer's own copy.

## Working on this

Read the specs before making architectural decisions — they cross-reference each
other heavily, and several sections exist specifically to correct an earlier,
subtly wrong version of themselves. Those corrections are usually load-bearing.

Where the specs leave something open, the code says so inline. Searching for
`Flagged` finds every such decision.
