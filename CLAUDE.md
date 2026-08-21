This project implements a distributed intranet protocol. Full architecture and design
decisions are specified in specs/01-core-protocol-spec.md through specs/06-reference-test-harness-spec.md.
Read all six before making architectural decisions — they're interdependent and
cross-reference each other extensively.

specs/07-chat-application-spec.md is different in kind: the first application-layer spec,
consuming the platform rather than defining it. Read it only when working on something it
touches — but do read its §7, which lists the amendments it asks of the platform, two of
which change types the core specs own (governance entry variants, and an app-layer policy
map in NetworkPolicy). Six are implemented — E2, E4, E9, E11, E12 and E14 — and E10, E13 and E15 are not. E13 is load-bearing rather than convenient: every direct message is its own network and a relay is never shared between two of them (§7, and the client's D29), so without cross-network bootstrap two NATed people cannot converse at all.
Treat them as authoritative; if an implementation choice isn't covered by them, flag it
rather than guessing.

Several spec sections exist specifically to correct an earlier, subtly wrong version of
themselves — those corrections are usually load-bearing, so prefer the current text over
what an older summary or comment might imply.

## Implementation

Rust workspace, one crate per layer, in `crates/`. See README.md for the map and for what
is and is not verified. Every layer is implemented. The Docker NAT scenarios have now been
executed and all 5 pass, so tier 2 is verified in the container. Note what that does and
does not establish: the scenarios validate connectivity and tier selection, not end-to-end
behaviour. Three of the four fixes it took were protocol bugs rather than harness ones, so
do not read a passing matrix as evidence the transport is exercised. One finding is worth
carrying: a NAT gateway must `DROP` unsolicited inbound packets, never reject them — a
hole-punch SYN is addressed to the gateway's own address and so hits `INPUT`, and an RST
removes the retransmit that hole-punching depends on. A gateway that rejects is broken,
not stricter.
The app execution sandbox is deliberately outside the protocol, not missing: App Hosting
§3.2.1 states the boundary — the protocol decides which bytes are the app and whether it
is servable, a client decides whether to execute them and under what isolation. Do not
add a sandbox here.

Governance log propagation is wired: a pull-based request/response sync protocol over
libp2p (`intranet-transport::sync`, `intranet-governance::wire`), chosen because §2.7
allows the log no new transport primitive beyond §5.1 and because a broadcast has no
history — entries appended during a partition would never reach the other side. A heal
is a reconnect and a reconnect is a sync, so there is no separate catch-up path.
Entries must be delivered ancestors-first (`GovernanceLog::ancestors_first`), since
`insert` refuses an entry whose parent it has not seen and a dropped entry is
indistinguishable from one never sent. The wire codec is hand-written and deliberately
untrusted: every decoded entry is re-verified against its author's signature, so a codec
bug is a rejected entry rather than silent divergence.

MLS group state is live and must be persisted: `GroupSession::save`/`restore`
(Core §3.3.1). Without it a restarted member keeps its epoch keys, can still read, and can
never rotate, welcome or revoke again — a founder in that state cannot key anybody in, and
the §3.1 revocation guarantee quietly stops being available. openmls keeps that state in an
in-memory provider by default, which is why this is easy to get wrong and invisible in
tests that never restart anything. The blob holds the group's secret tree and the member's
signature private key, so it is secret in the same sense `EpochKey::expose_for_delivery` is:
seal it at rest. Note the save path reads `MemoryStorage::values` directly rather than
calling `serialize`, which openmls gates behind its `test-utils` feature.

The capability ledger gossips over the same machinery (`intranet-ledger::wire`,
`/intranet/capability-ledger/1.0.0`), but reconciles differently: it is a set keyed by
node, refreshed wholesale, so its digest is `(node, issued_at)` rather than branch tips.
The timestamp is load-bearing — without it a peer could tell only whether it had heard
of a node, never whether its copy was current, and refreshes would never propagate.
An advertisement is only accepted from a current member, so the ledger depends on the
governance log and a fresh node rejects advertisements until its log catches up; a
governance sync that accepts anything re-triggers a ledger sync to correct that.

Note what placement determinism actually claims: `placement::rank` is deterministic
given a candidate set, but the candidate set is each node's own gossiped cache filtered
by local staleness. Two nodes agree once their ledgers agree, not before — Storage §3.4's
repair loop is what corrects the gap. Don't strengthen the docs beyond that.

Content moves over `/intranet/chunk/1.0.0` (`intranet-storage::wire`, `ChunkStore`).
Requests are signed over the CID *and* bound to the connection: a signature proves the
named identity made the request, not that whoever delivered it is that identity, so the
serving node also checks `requester.peer_id() == peer`. Arriving bytes are verified
against the CID that was *asked for*, never one derived from the bytes themselves, which
is why in-flight requests are tracked. Only a verification failure feeds
`reliability_signal` — not-held and refused are not the peer's fault. Provider discovery uses Kademlia
provider records keyed on the CID digest, and `FetchPlan` (`intranet-storage::fetch`) holds
the §4.4 policy — rarest-first, per-chunk source selection, bounded concurrency, retry
elsewhere on failure — as testable state rather than a loop in the event loop.

Two consequences worth knowing before debugging a fetch that finds nothing. libp2p keeps
Kademlia in **client mode** until a node has a confirmed external address, so on a LAN or
on loopback nothing answers provider queries and every lookup returns "nobody"; use
`set_dht_server_mode(true)`, and note that in production the publicly addressable nodes
(relays, per §5.5) carry the records. And a holder that has not advertised upload capacity
is dropped by `select_sources` as not having volunteered, so the ledger must be populated
before a fetch can use a source the DHT found — the layering is governance, then ledger,
then fetch. Kademlia also has no un-publish: `forget_chunk` stops republishing but records
already pushed persist until TTL, which is why `NotHeld` is an explicit response counting
against nobody.

Discovery is optional per node (Core §5.1.1): `MemberBehaviour`'s `kad` and `mdns` are
`Toggle`d, and `MemberNode::with_discovery(.., Discovery::Off)` builds a node without
either. It is for a network whose members are known by construction — a pairwise network
has nobody to discover — and a client runs one node per network, so a user's conversations
would otherwise each carry a routing table. `find_providers` and `enumerate_collection`
return `Option`, and `None` means *there was no query to run*: returning a query id that
never resolves would be indistinguishable from content that genuinely has no holders, the
same confusion `set_dht_server_mode` exists to prevent above. Announcing is a no-op rather
than an error, and so is `add_address` — without a routing table there is no address book,
so such a node dials by address and never by peer id. This is what the node *is*, fixed at
construction; how live a node is over time is the client's business and is deliberately
not this axis.

Append-set collections (Storage §2.5) run over `/intranet/append-set/1.0.0` carrying opaque
payloads, so the one primitive serves both search postings and — later — the app name
registry without either shape leaking into the other. Enumeration is two steps: find
providers, then ask each. Search postings ride it as **one signed object per publish
announced under every matched term** (§3.1's efficiency note), not one object per term.
Delisting is enforced by the *reader*: the announcing node has every reason not to, so
`LocalIndex::insert` re-checks against replayed governance state.

Note an event-loop invariant: `next_swarm_event` drains `pending` only on entry, so any
event pushed there from inside its loop is delivered on the *next* call — which never
comes if the arm falls through and nothing else happens. Push to `pending` only in an arm
that returns immediately afterwards; otherwise return the event directly.

Calls run over two protocols, and their separation is load-bearing:
`/intranet/call-signal/1.0.0` (signed, carries key envelopes and topology proposals) and
`/intranet/call-media/1.0.0` (unsigned — frames are AEAD-sealed, so authenticity comes
from opening them, and a per-frame signature would put an asymmetric op on the latency
path). A blind relay speaks media and **not** signalling, which is what makes §2.2's
"architecturally incapable of decrypting" true rather than a promise: key envelopes never
travel a channel the relay carries. A relay is told only the call id and its participant
set, and forwards only for calls it agreed to carry and only to participants — without
both checks it is an open reflector. Routing metadata sits outside the AEAD because the
relay must read it, so a malicious relay can misroute; the nonce binds the call, so a
misrouted frame simply fails to open.

A relay fans out: `MediaEnvelope`'s recipient is `Recipient::{One, Participants}`, and the
`Participants` form has the sender emit **one** envelope per frame which the relay
replicates (§2.2.1). Four things about it are easy to undo by accident. The fan-out form
carries no recipient list — the set is what the relay was told, which is what stops a
sender aiming a relay at a non-participant. Every forwarded copy is readdressed to `One`,
so a participant never holds a fan-out envelope and a forwarding loop has nowhere to start.
The claimed `from` is checked against the connection, because a media frame carries no
signature and a relay cannot check the claim against the frame — under fan-out an unbound
sender is worth N−1 sends rather than one. And the envelope's domain tag is `v2`; adding
the discriminant under `v1` would have let an old envelope's first recipient byte parse as
one, wrongly, twice in every 256.

Limits live in `media_limits.rs`, separate from `relay_limits.rs` because the roles are
distinct (§4.4) and mixing them blurs exactly that. `MediaRelayGuard` owns the participant
sets, so `authorize` is the only way to learn a frame's recipients and it charges the byte
allowance in the same call — there is no path that forwards what the guard did not meter,
which is the same structural answer `relay_limits` uses. Bytes are charged for what
*leaves* the node (frame size × recipients); charging the inbound size under-meters by
exactly the fan-out factor. The node holds no clock, so the allowance is refilled by an
explicit `refill_media_allowance(now)` — a caller that never calls it spends the burst and
then refuses everything, which is fail-closed but a real obligation. `relay_call` returns
`Result` and refusing is ordinary, not an error: the call renegotiates onto another relay.

Call media delivery is specified in §1.5 as **unreliable and unordered** (QUIC datagrams
or equivalent): a frame past its playout deadline is worthless, and a reliable ordered
channel turns one lost packet into a multi-frame gap through head-of-line blocking. The
current implementation uses request/response over a reliable stream, which §1.5 permits
only as a fallback — it is the honest state, not the target. Replacing it is blocked upstream:
quinn supports datagrams but `libp2p-quic` disables them at construction
(`datagram_receive_buffer_size(None)`, commented "Disable datagrams") and exposes no
datagram API, so this needs a libp2p change rather than a local one.
Signalling (§1.4) and live-stream chunks (§3.2) are both correctly reliable; do not
collapse the three into one delivery model.

The app name registry needed no transport of its own: ownership is a governance entry
(App Hosting §4.3) and the directory is an append-set collection, and both already
propagate. The split is the design — the log is authoritative, the index is a
best-effort hint — so `browse` confirms every listing against replayed state and
discards any that disagrees. A browser must merge its **own** locally-held collection
entries before enumerating: enumeration finds other providers, so skipping local ones
both hides what this node published and lets a hostile local entry escape validation.

Every layer is reachable over the network, and the specs are v1.0. The one implementation
divergence from the specs is call media delivery (above); everything else matches.

- `cargo test --workspace` and `cargo clippy --workspace --all-targets` must both stay clean.
  Note that clippy is absent from some environments (a source-tarball rustc with no rustup);
  a run that skips it has checked only half the gate, so say so rather than reporting clean.
- Decisions the specs left open are marked `Flagged` in a comment at the point of the
  decision. Grep for it rather than re-deriving them.
- Determinism is load-bearing in several places (entry hashes, HRW placement, quorum
  outcomes, pointer tie-breaks). Canonical encoding is hand-written per type and placement
  arithmetic is integer on purpose; don't replace either with a derive or floating point.
- Local-only signals (`reliability_signal`) must never reach a cross-node computation.
  The type signatures enforce this — keep it that way.
- Key material types deliberately implement no `Debug` or serialization. Use the
  `fingerprint()` methods for logging and tests rather than deriving `Debug`.
