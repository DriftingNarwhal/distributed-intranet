# Distributed Intranet

**Protocol v1.0** · a specification and reference implementation for many
independent, mutually-unlinkable peer-to-peer networks — each with its own
membership, governance, encryption, storage, search, calls and app hosting.

There is no required central authority. Bootstrap relays exist only to solve cold
start between two peers behind NAT, and nothing in steady-state operation depends
on one: a relay that vanishes costs a reconnection, not a network.

The design lives in [`specs/`](specs/): six platform documents, plus one
application-layer document that consumes them (`07`, draft — a chat application,
and the amendments it asks of the platform). **They are
authoritative** — the code implements them, and where an implementation choice
was not covered by them it is flagged in a comment at the point of the choice
rather than decided silently.

## Why this exists

To be the backbone of applications that have no server to trust — two goals,
which are the same goal from different angles.

**Privacy that does not rest on an operator's good behaviour.** Most "private"
software is private in the sense that a company promises not to look. There is
nobody in that position here: no server, no operator, no account. A network's
content is encrypted to a key only its members hold, and who holds it is decided
by the members. Note the scope carefully, because it is easy to overread —
**this makes a network private from everyone outside it, not its members private
from each other.** Members can read what their network publishes; that is what
membership means. What nobody gets is a vantage point above the network.

**Censorship resistance as a structural property rather than a policy.**
Content is served by whoever has it, so there is no host to pressure, no domain
to seize, and no one node whose removal takes anything down — a publisher can go
offline for good and their content stays servable by everyone who fetched it.
Moderation still exists, but it belongs to each network's own members through
its governance log, and it reaches only that network. There is no operator above
them to overrule it, and no lever outside it to pull.

**"Serverless" here means no servers, not someone else's.** The word usually
means managed infrastructure with the operations hidden; this is the literal
reading. Peers talk to peers. The only always-on component is a bootstrap relay,
which holds no state, is never trusted with keys, and can disappear at any time
without costing an established network more than a reconnection.

## What this actually is

A "network" here is a self-governing group — a household, a club, a workplace, a
fandom — that shares content among its own members and nobody else. The protocol
gives each one:

- **Its own membership and governance.** Who is a member, who may do what, and
  how those decisions are made is a per-network choice, recorded in a
  hash-chained log every member can replay and verify independently. There is no
  administrator to trust, because authorization is a computation over that log
  rather than a question you ask someone.
- **Its own encryption.** Content is encrypted to the network's current epoch
  key, rotated when membership changes. Rotation is cheap by design: it re-wraps
  a small number of keys, never re-encrypts content.
- **Unlinkability between networks.** One person's identity in one network cannot
  be correlated with their identity in another — not by key, and not by libp2p
  PeerId, which is derived per network for exactly this reason. (IP-level and
  timing correlation remain out of scope.)
- **Storage that spreads.** Content is chunked, content-addressed, and served by
  whoever has it. Anyone who fetches something automatically becomes a source for
  it, so a popular file does not pin its publisher's upload.
- **Search without a search engine.** Publishing indexes as a side effect;
  queries resolve against a distributed inverted index over the DHT. No crawler,
  and no query ever leaves the network.
- **Calls and live streams.** Small calls go direct; larger ones move to a relay
  that carries encrypted media it cannot read. Streams propagate viewer-to-viewer
  so a broadcaster's upload cost stays roughly flat as the audience grows.

## What you can build on it

Three shapes, in rough order of how most consumers would use it:

1. **A native app using the protocol as a backend.** The common case, and what
   the specs expect: your own client, distributed however you like, using the
   core and storage layers for identity, membership, encrypted storage and
   transfer. You never touch app hosting.
2. **A published in-network app.** HTML/CSS/JS bundles published *to* a network
   and rendered by a protocol-aware client, updatable by republishing. Opt-in per
   network — a network that does not allow the `app-bundle` content type cannot
   host them at all. See the sandbox boundary under Status.
3. **A new layer on top.** The specs are written to be consumed: append-sets,
   mutable pointers, the capability ledger and the governance log are general
   primitives, and two consumers already share each of them.

## What this is not

- **Not a blockchain.** The governance log borrows tamper-evidence and
  independent verifiability, and deliberately discards mining, tokens and
  permissionless consensus. Every actor has a verified identity before they act,
  so there are no strangers to establish trust among.
- **Not anonymity software.** It unlinks your identities across networks. It does
  not hide your IP address or your timing from a network observer, and does not
  claim to.
- **Not a global network.** There is no shared namespace, no cross-network
  discovery, and no directory of networks. Each one is its own island by design.
- **Not a finished product.** It is a protocol with a reference implementation
  and a conformance harness — the thing you build a product against.

## Status

**Protocol: v1.0, stable.** Every specification document has an implementation,
and every layer is reachable over the network. **591 tests, clippy clean.**

| Spec | Status |
|---|---|
| 01 Core protocol — identity, governance, epoch keying, transport | Implemented |
| 02 Storage & replication | Implemented |
| 03 App hosting — name registry, manifests, publishing policy | Implemented; execution sandbox is an embedder concern, see below |
| 04 Real-time transport — calls, streams, VOD | Implemented; media uses the fallback delivery path, see below |
| 05 Search & indexing | Implemented |
| 06 Reference test harness | CLI implemented; NAT scenarios executed, **all 5 passing** |
| 07 Chat application (draft) | Specified; implementation in progress out of tree. Asks five amendments of the platform — see its §7 |

### Two things to know before you build on it

**The app execution sandbox is deliberately outside the protocol.** App Hosting
Spec §3.2 specifies the isolation a published app must run under; §3.2.1 states
why providing it belongs to a client rather than to a protocol implementation. It
is a property of a particular browser engine on a particular platform, and the
choice of a webview exists precisely to inherit hardened browser sandboxing
rather than reinvent it. Concretely: nothing in `intranet-app` will tell you an
app is safe to run — it settles which bytes are the app and whether it is
servable, and stops. **A client that fetches an `app-bundle` and executes it
without its own sandbox has skipped a step the protocol was never in a position
to take.**

**Call media uses the fallback delivery path.** Real-Time Spec §1.5 requires call
media to be delivered unreliably and unordered: a frame past its playout deadline
is worthless, and a reliable ordered channel turns one lost packet into a
multi-frame gap through head-of-line blocking. What ships is request/response over
a reliable stream, which §1.5 permits only as a fallback. It is correct and
behaves well under negligible loss — which is what the tests exercise — and
degrades badly under real loss. This is **blocked upstream, not merely
unimplemented**: quinn supports QUIC datagrams, but `libp2p-quic` disables them at
construction and exposes no datagram API, so closing it needs a libp2p change
rather than a local one.

### How much to trust "the tests pass"

The NAT scenarios took four fixes to pass, three of them protocol bugs rather
than harness ones: reserving a relay circuit straight after a wildcard bind lost
port reuse; a 10-second idle timeout tore the relayed connection down mid-upgrade;
the NAT gateways answered the hole-punch SYN with an RST instead of dropping it,
which removes the retransmit hole-punching depends on; and a successful upgrade
was attributed from DCUtR's own dial rather than from the connection, so a real
tier-2 upgrade was reported as tier 1.

The first execution needed seven fixes, and the expectation that bugs would be
confined to the harness was wrong. The most serious was in `intranet-transport`:
`RelayNode` never registered an external address, so it granted every reservation
with an empty address list and no client could accept one — tiers 2 and 3 were
dead while tier 1 worked and the relay's health check reported ready. Two more
were in the harness's own tier assertion, which reported `direct` for connections
it had not actually made to the target.

Passing scenarios validate connectivity and tier selection, not end-to-end
behaviour. [`harness/README.md`](harness/README.md) separates what is verified
from what is not, and records the evidence behind each fix.

## Layout

```
specs/     01-06 the platform, authoritative; 07 an application layer on top
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
cargo test --workspace      # 591 tests
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

All five pass. Roughly two minutes for the in-process suite versus minutes more
for the Docker matrix, which is why the harness spec (§8) puts the first on every
commit and the second on a slower cadence.

## Running a relay

A network needs at least one bootstrap relay to solve cold start between two
members who are both behind NAT. Relays are deliberately cheap: they hold no
state, are never trusted with keys, and establish connections rather than
carrying traffic, so circuits are capped at 120 seconds and 8 MB by default.

**[DI-Relay](https://github.com/DriftingNarwhal/DI-Relay)** is a deployable
relay built on `intranet_transport::RelayNode`, with step-by-step Railway
instructions. It is a thin wrapper on purpose — the relay logic stays here, where
the conformance suite exercises it against a live relay rather than a model of
one.

For a local run without deploying anything:

```bash
cargo run -p intranet-harness -- relay --seed 1 --network 42
```

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
- **Relays establish connections; they do not carry traffic.** A bootstrap relay
  helps two peers find each other and gets out of the way, which is why circuits
  are capped at 120 seconds and 8MB and why a relay holds no state across
  restarts. Peers that can never hole-punch — two behind CGNAT — are expected to
  reach each other over IPv6, which needs no traversal at all. Tier 3 exists so
  the network stays correct, not so anyone lives on it.
- **Honest guarantees.** Where a limit is unavoidable it is stated rather than
  overclaimed: revocation blocks future access but cannot un-know a key already
  held; serving converges rather than blocking instantly; VOD opt-out prevents a
  platform record but not a viewer's own copy.

## Working on this

Read the specs before making architectural decisions — they cross-reference each
other heavily, and several sections exist specifically to correct an earlier,
subtly wrong version of themselves. Those corrections are usually load-bearing.

Where the specs leave something open, the code says so inline. Searching for
`Flagged` finds every such decision — each one is a choice the specs did not
make, recorded at the point it was made rather than buried in a commit message.

The specs are versioned as a set. At v1.0 the remaining open questions in each
document are genuinely deferred rather than unresolved: application-level
questions nobody needs yet (concurrent-edit merge semantics), tuning that wants
real deployment data (tokenisation rules, ranking formula), and enforcement
surfaces for capabilities no app has requested. Anything that blocked
implementation has been closed.
