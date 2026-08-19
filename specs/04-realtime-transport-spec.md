# Real-Time Transport Specification

**Project:** Distributed Intranet
**Document status:** v1.0 — stable. A reference implementation exists (see the repository root); where the two differ, this document is normative and the divergence is recorded in the implementation.
**Depends on:** Core Protocol Spec (identity, capability ledger, governance policy), Storage & Replication Spec (mutable pointers, swarm-based serving, content addressing)
**Consumed by:** any future application-layer specs built on this platform

---

## 0. Purpose and Scope

This document specifies real-time communication: voice/video calls between a few-to-few set of participants, and live streaming/broadcasting from one participant to a potentially large audience. It covers:

1. **Calls** — direct mesh vs. relay-mediated, based on a policy-configurable participant threshold.
2. **Blind relay design** — how relay nodes forward encrypted media without being able to decrypt it, and how relay selection draws on the capability ledger.
3. **Live streaming** — a distinct problem from calls: one-to-many, latency-tolerant by seconds, solved with a live-propagating swarm rather than mesh or a fixed relay set, so a broadcaster's upload cost doesn't scale with audience size.
4. **VOD conversion** — how a finished live stream becomes ordinary swarm-servable content with no separate mechanism.

Out of scope: the actual calling/streaming UI, and anything client-application-specific — this document defines the transport layer any future communications-style application would consume.

---

## 1. Calls: Mesh vs. Relay

### 1.1 The Core Tradeoff

Direct mesh (every participant connects to every other participant directly) costs each participant N−1 simultaneous upload streams. That's cheap at 2 participants, tolerable at 3–4, and degrades quickly beyond that — upload bandwidth is typically the scarce resource on a residential connection, which is the same reason mainstream call platforms all switch to a relay/SFU model past a small group size.

### 1.2 Policy-Configurable Threshold

Consistent with how this project handles other tunable values (replication factor, governance model — Storage Spec §3.1, Core Protocol Spec §2.6), the mesh/relay switchover is a **network-level policy setting**, not a protocol constant, defaulting to somewhere in the **4–5 participant** range:

- **Below threshold:** direct mesh. No relay node is involved at all — lowest latency, simplest path, and no third party ever touches the media even in encrypted form.
- **At or above threshold:** relay-mediated (§2). The call transparently transitions if a call grows past the threshold mid-session (e.g. a 1:1 call that additional people join) — participants renegotiate from mesh to relay-mediated without ending the call.

### 1.3 Call Media Encryption

Call media is end-to-end encrypted between participants using keys derived from the call participants' per-network identities (Core Protocol Spec §1.2) — independent of, and in addition to, whatever transport-layer connection security libp2p already provides (Core Protocol Spec §5.1's Noise). This is what makes blind relaying (§2) possible at all: the relay is architecturally incapable of decrypting what it forwards, not merely asked not to.

### 1.4 Mesh↔Relay Renegotiation and Relay Failover — Resolved

Both the mid-call mesh-to-relay transition (§1.2) and relay failover (§2.4) follow the same renegotiation mechanism, since both are really the same underlying event: "the call's active transport topology needs to change without interrupting the conversation."

1. **Reuse existing call signaling — no new infrastructure.** Participants already need a lightweight, session-scoped signaling channel to establish the initial mesh connections; renegotiation reuses that same channel rather than introducing separate infrastructure for it.
2. **Trigger → propose → converge.** Whichever participant's client first detects a trigger condition (participant count crosses the configured threshold, §1.2; or the active relay becomes unreachable) computes a relay candidate ranking using the selection criteria already defined in §2.3 — evaluated collectively across all current participants' vantage points, not just the proposer's own, since a call involves multiple parties with potentially different network positions — and broadcasts a proposal over the session channel.
3. **Lightweight tie-break for near-simultaneous proposals.** If two participants propose within the same short window, all clients deterministically converge on whichever proposal was received first (falling back to the lexicographically lower candidate ID if timing is genuinely ambiguous). This is intentionally much lighter-weight than the governance log's ordering mechanism (Core Protocol Spec §2.7) — a wrong pick here costs only a quick reselect, not a lasting inconsistency in durable network state, so reusing the heavier mechanism would be unwarranted overhead for an ephemeral, per-call decision.
4. **Make-before-break handover.** Every participant establishes their connection to the newly selected relay (or, for relay-to-mesh transitions, their direct peer connections) *before* tearing down the prior transport — standard gapless-handover practice, avoiding any audio/video interruption during the transition. This applies identically whether the transition is mesh→relay, relay→relay failover, or (in principle) relay→mesh if a call's participant count drops back below threshold.

### 1.5 Call Media Delivery Semantics — Previously Unspecified

**This section closes a genuine gap rather than restating something implied elsewhere.** §5.1 of the Core Protocol Spec lists TCP and QUIC as transports, and §6 below previously described the only remaining open question as codec and segment duration, "implementation-level tuning". But *how call media frames are delivered* — reliably or unreliably, ordered or unordered — was never stated, and it is not tuning: it changes what happens to a conversation under packet loss, which is the condition the entire relay design exists to survive.

**Interactive call media requires unreliable, unordered, latency-prioritized delivery.** A media frame has a playout deadline. A frame that arrives after its deadline is not merely late, it is worthless — it will never be rendered — and the cost of having waited for it is paid by every frame behind it. Reliable ordered delivery inverts the correct behaviour on both counts:

- **Retransmission is actively harmful, not merely wasted.** Re-sending a dropped frame consumes capacity to deliver something that can no longer be used, on a link that is by hypothesis already losing packets.
- **Head-of-line blocking is the real damage.** On a reliable ordered channel, one lost frame stalls delivery of every subsequent frame until it is recovered. A single lost packet therefore turns into a multi-frame audible gap, where dropping it would have cost one frame and been very likely imperceptible.

The correct behaviour is to drop late and lost frames and keep going. Concealment of the resulting gaps is a codec concern (§6) and genuinely is implementation-level.

**Suitable mechanisms.** QUIC is already a required transport (Core Protocol Spec §5.1), and QUIC datagrams are the natural fit: unreliable, unordered, and not subject to a stream's head-of-line blocking, while still using the connection's existing congestion control and encryption. Any equivalent unreliable path is conformant. What is **not** conformant as a production media path is a reliable ordered stream, whether that is a raw TCP stream, a multiplexed sub-stream, or a request/response protocol carrying one frame per exchange.

**A reliable ordered channel is an acceptable fallback in exactly two situations**, and implementations should say which one they are in rather than leaving it to be discovered: when no unreliable path is available between two particular peers, where degraded media beats no media; and in test or reference settings where loss is negligible and the property under test is something else. Neither is a substitute for the real path, and an implementation that ships only the fallback should be described as having an incomplete media transport rather than a complete one.

**This applies to call media only, and the contrast with live streaming is deliberate.** §3.2's live-stream chunks are ordinary content-addressed chunks distributed by a propagating swarm, and their delivery is correctly *reliable*: a viewer needs each chunk whole, chunks are re-served by other viewers, and finished broadcasts become VOD (§4) as ordinary immutable content. Streaming buys resilience with a small buffer, which a broadcast can afford and a conversation cannot. Call **signalling** (§1.4) is likewise reliable — a lost `Leave` or a lost topology proposal is a correctness problem, not a dropped frame — which is a further reason signalling and media are separate channels (§2.2).

---

## 2. Blind Relay Design (Calls)

### 2.1 Recap: A Distinct Capability From Bootstrap Relay

As established in the Core Protocol Spec (§4.4), **media relay** (`relay_media_willing` in the capability ledger) is a separate declared capability from **bootstrap/connection relay** (`relay_bootstrap_willing`, used for NAT traversal during initial peer connection, Core Protocol Spec §5.2). A node may offer either, both, or neither, per network. This document only concerns the media-relay role.

### 2.2 What "Blind" Means Concretely

A media relay node forwards encrypted call traffic between participants without holding any key capable of decrypting it (§1.3). Practically:

- The relay sees ciphertext packets and routing metadata (which participant's stream goes where) — nothing else.
- The relay cannot inject, modify, or selectively suppress content undetected, since packets are authenticated as well as encrypted (tampering is detectable by the receiving participant, not just confidentiality-protected).
- This means a relay role can be filled by a lower-trust member of the network — trust in "will forward my packets faithfully / won't just drop the call" is a much smaller ask than trust in "won't listen to my call," and the design should never require the latter.

### 2.2.1 Fan-Out: One Envelope In, N−1 Out — Previously Unspecified

§1.1 gives the relay one job: stop each participant paying (N−1) × bitrate in upload. §2.2 described what a relay may *see* without ever saying how many envelopes it forwards for each one it receives, and an implementation that reads only §2.2 will naturally build the per-recipient form — a sender emitting one envelope per recipient, the relay forwarding each to the one participant it names. That form is faithfully blind and faithfully limited, and it reduces sender upload by nothing at all: the sender still emits N−1 envelopes per frame, now with an extra hop on each. **A relay that does not fan out is worse than mesh, not better**, and this section exists because the reference implementation shipped exactly that.

**A media envelope's recipient field is therefore one of two forms:**

- **A named participant.** The envelope is for that participant. This is the mesh form, where the sender addresses each peer directly and no relay is involved; it remains valid on the relay path and is what a relay produces when it forwards.
- **The call's participants.** The envelope is for every participant of the call except its sender. Only a relay acts on this form: the sender emits **one** envelope per frame regardless of participant count, and the relay replicates it.

Five rules govern the second form, and an implementation missing any one of them has reopened something the first form closed:

1. **The sender does not name the recipients, and cannot.** The fan-out set is the participant list the relay was *told* when it agreed to carry the call (§2.3) — never a list carried in the envelope. This is strictly safer than the per-recipient form, where a sender in a carried call names its own target: a sender cannot reach a non-participant through a relay because it has no field in which to ask.
2. **A relay fans out only for a call it agreed to carry, and only when the sender is a participant of that call.** Both checks are load-bearing. Without the first, a relay is an open reflector with an amplification factor. Without the second, anyone who learns a carried call's id can have the relay spray a frame at every participant.
3. **The claimed sender must be the peer that connected.** A media envelope carries no signature — §2.2 puts authenticity in the AEAD, where it costs nothing per frame — so the sender field is a claim, and the relay is the one node in the path that cannot check a claim against the frame it is attached to. It checks the claim against the connection instead, exactly as a chunk request and a signalling message already do. This is not a new obligation invented for fan-out; it is one that fan-out makes worth stating, because an unbound sender field is worth one forwarded frame under the named form and N−1 sends under this one. The check binds the *forwarding* decision only: a participant receiving a relayed frame sees the relay's connection and the original sender's identity, which is what relaying means, and the AEAD is what authenticates it there.
4. **The relay rewrites the recipient field to the named form on each forwarded copy.** What a participant receives is addressed to that participant. This is what makes a forwarding loop impossible — a participant never receives a fan-out envelope, so it never has one to fan out — and it keeps a receiver's check on "is this for me" the same on both paths.
5. **Recipient routing stays outside the AEAD, and rewriting it changes nothing a receiver trusts.** The relay was always able to misroute (§2.2); rewriting is that same bounded power, and a misdelivered frame still fails to open because the nonce binds the call. A relay that rewrites cannot forge, redirect into another call, or learn anything it could not already see.

**A relay that is also a participant hears the frame as well as forwarding it**, and forwards to the participant set minus both the sender and itself. A participant with spare upload carrying the call for the others is a sensible topology rather than an exotic one — §2.1's point that a relay may be a lower-trust member does not exclude a member already in the call — and the degenerate case where it is the *only* other participant still delivers, with nothing to forward.

**Amplification is bounded by the relay's own agreement, not by the protocol.** One inbound envelope becomes N−1 outbound, which is the entire point and is also the shape of an amplifier. The bound is that a relay chose both the call and the participant set it accepted; a node unwilling to carry a large call declines it at that point, which is where the decision belongs. **Flagged: no participant ceiling is specified**, here or in §1 — a relay that wants one enforces it locally when it agrees to carry, and two relays choosing differently costs nothing, since this is a per-node resource decision with no cross-node consistency requirement (§2.3's reasoning applies unchanged).

**Wire compatibility.** The recipient field gains a discriminant, so envelopes in the two forms are distinguishable and neither can be read as the other. This is a wire break rather than an additive change, and it is versioned as one — the media envelope's domain tag advances, so an envelope in the older form fails to decode rather than parsing as a valid fan-out with a recipient read out of the wrong bytes.

### 2.3 Relay Selection

When a call needs a relay (§1.2), candidate nodes are drawn from the capability ledger's `relay_media_willing = true` entries for that network, and selected using the same category of signals as swarm-serving in the Storage spec (latency/hop count, available `bandwidth_cap`, current load, and the selecting node's local `reliability_signal` observations) — reusing an established selection pattern rather than inventing a new one for this document. Given the sustained-bandwidth, latency-sensitive nature of media relay specifically (as distinguished in Core Protocol Spec §4.4), latency and jitter should be weighted more heavily here than in static-content swarm selection, where they barely matter.

**This is one of only two places in the entire design where `reliability_signal` may be used** — the other being swarm source selection (Storage Spec §4.3). Both qualify for the same reason: they are local, per-node choices with no cross-node consistency requirement, so it doesn't matter that two participants might rank candidates differently from their own vantage points (§1.4 already resolves disagreement between participants through proposal and tie-break, not through everyone computing an identical answer). This is exactly what distinguishes relay selection from live-stream first-tier assignment (§3.3), which *is* a deterministic cross-node computation and therefore cannot use the signal at all.

### 2.4 Relay Failover

If a selected relay drops (crashes, goes offline, or its `bandwidth_cap` becomes exceeded), participants renegotiate onto a different willing relay node from the capability ledger using the mechanism defined in §1.4 (trigger → propose → converge → make-before-break) — the same process handles both the mesh↔relay threshold transition and relay-to-relay failover, since both are the same underlying "active transport topology needs to change mid-call" event. This is a resilience property worth stating explicitly given the project's overall takedown-resistance goals: a call should never structurally depend on one specific relay node remaining online for its duration.

---

## 3. Live Streaming

### 3.1 Why This Isn't Just "A Call With More People"

A call (§1) is symmetric (every participant both sends and receives, few-to-few) and latency-critical (delay breaks conversation). Streaming is asymmetric (one broadcaster, potentially many viewers) and latency-*tolerant* by a few seconds — a viewer being a couple seconds behind the broadcaster is completely normal and expected (as with any mainstream streaming platform today). This difference is what makes a different mechanism not just viable but preferable, and it's also why this isn't simply static swarm-serving (Storage Spec §4) either: static content is finished and sitting still, whereas a stream's most recent chunk doesn't exist yet a few seconds ago, so viewers need chunks propagated to them promptly rather than fetched whenever convenient.

### 3.2 Live-Propagating Swarm

The broadcaster's node continuously produces a sequence of small, short-lived, sequentially numbered chunks (encoding detail — segment duration, codec, etc. — is an implementation decision, not an architectural one). Distribution then works as a propagating swarm rather than a static one:

- A viewer who has already received chunk N becomes an immediate re-distribution source for chunk N to other viewers, while it's still fresh — the same "any node that has fetched content becomes an eligible server for it" principle from Storage Spec §4.2, but applied to a live-advancing window of chunks instead of a fixed, finished set.
- This is conceptually a fire-brigade chain: the broadcaster hands each chunk to a first tier of viewers/relay-willing nodes, who immediately begin forwarding it onward to further viewers, rather than every viewer independently pulling from the broadcaster.
- The result is that the broadcaster's own upload burden stays roughly constant regardless of audience size — the thing that actually solves the cost problem you raised, since bandwidth cost scales with the *swarm's* total capacity, not the broadcaster's connection alone.

### 3.3 First-Tier Assignment — Resolved

**Decided: reuse Rendezvous Hashing (HRW), the same deterministic placement algorithm already established for storage replica placement (Storage Spec §3.3), rather than requiring any explicit "promote to redistributor" signal from the broadcaster or the network.**

For a given live stream, the first-propagation tier is the top-K `relay_media_willing` nodes ranked by the same HRW computation already defined in the Storage Spec (§3.3 of that document), weighted by the capacity field that actually matters for this role:

```
score = hash(stream_id, node_id) × bandwidth_cap
```

Any node can independently compute the same tier assignment just from the stream's identifier and the current **gossiped** capability ledger, with no coordination, signaling protocol, or broadcaster decision-making required.

**The weight field differs from storage placement, deliberately; the algorithm does not.** Storage Spec §3.3 weights by `storage_offered` because durability placement is about who will *hold* bytes; first-tier stream redistribution is about who can *forward* sustained throughput, which is what `bandwidth_cap` declares (Core Protocol Spec §4.2) — weighting a media-relay tier by donated disk would rank nodes on a resource the role never consumes. Both fields are gossiped, so substituting one for the other changes nothing about the property this section depends on: every node still computes an identical tier from network-visible state alone. Implementations should share one HRW routine parameterized by the weight field, not fork two copies of the ranking logic.

**`reliability_signal` is not an input here either, for the same reason it was removed from Storage Spec §3.3.** It is local-only and never gossiped (Core Protocol Spec §4.6, a deliberate anti-slander property that is not to be reversed), so including it would mean every node computing a *different* first tier — destroying the coordination-free, independently-recomputable property that is this section's entire justification for reusing HRW instead of having the broadcaster explicitly nominate redistributors. Reliability still shapes real-time behavior, but only where the decision is local and per-node: **relay selection for calls** (§2.3). Tier members that fail to actually redistribute are handled by the existing recomputation trigger below (a dropped or over-capacity tier member causes reassignment), not by weighting the ranking. The broadcaster pushes fresh chunks directly to this computed tier, which then redistributes to everyone else via the ordinary live-propagating-swarm mechanics in §3.2.

**Tier assignment is computed once per stream, not per chunk.** The ranking is keyed off the stream's mutable pointer (§3.5) for the duration of the broadcast, not recomputed for every individual chunk — recomputing constantly would mean the broadcaster tearing down and rebuilding connections on a sub-second basis for no real benefit. A stable tier lets the broadcaster maintain persistent connections to a small, fixed set of first-tier nodes for the session's duration, only triggering recomputation if a tier member drops out or exceeds its `bandwidth_cap` — the same repair-trigger pattern already used for storage replica maintenance (Storage Spec §3.4), applied here to a live rather than durability-driven context.

### 3.4 Roles Reuse Existing Capability Ledger Fields

No new capability-ledger fields are needed for any of this: `relay_media_willing` nodes (§2) are the natural candidates for first-tier assignment per §3.3 (deliberately taking on redistribution load, similar to their call-relay role), while ordinary viewers participate more passively in later tiers simply by virtue of having received recent chunks, same as any swarm member. A node's `bandwidth_cap` self-limits how much redistribution load it takes on at any tier, exactly as in static swarm-serving (Storage Spec §4.5) — same backpressure principle, applied here to a live rather than static distribution graph.

### 3.5 Stream Encryption — Asymmetry With Call Relays, Stated Explicitly

Stream content is encrypted under the network's current epoch key (via each object's DEK, wrapped under the epoch key — Storage Spec §1.2, §5), consistent with all content in this system (Core Protocol Spec §3). **This is a materially different confidentiality posture from call relays, and this document previously left that asymmetry implicit in a way that risked being misread.** Call relays (§2.2) are genuinely blind — the encryption keys involved are scoped only to the specific call's participants, and a relay node has no way to obtain them regardless of what else it's a member of. First-tier stream redistribution nodes are not in the same position: as ordinary network members, they legitimately hold the network's current epoch key, and therefore *could* decrypt the stream content they're forwarding, even though nothing about their forwarding role requires them to. "They don't need to decrypt to forward" was true as far as it went, but shouldn't be read as "they cannot decrypt" — those are different claims, and only the first one is actually true here.

This is an acceptable posture for what this section specifies — ordinary, network-wide broadcasts, where every redistributor is by definition someone already entitled to see the content anyway. **It is explicitly flagged as forward guidance, not a gap to fix now:** a future "stream to a subset of the network" feature (a restricted-audience broadcast) cannot reuse epoch-key encryption for confidentiality, since the epoch key is shared network-wide by definition — such a feature would need its own scoped key, closer in spirit to how call encryption already works (§1.3), not an extension of this section's mechanism. Whoever eventually specs that feature should start from that constraint rather than rediscover it.

### 3.6 Broadcast Discovery

A live broadcast needs to be discoverable while in progress — this reuses the same naming/registry pattern from the App Hosting spec (§4.3–4.4): a broadcaster's stream can be represented as a mutable pointer (Storage Spec §2) whose `current_cid` always resolves to "wherever the live chunk sequence currently is," updated continuously rather than per-edit, letting the existing pointer-resolution and name-registry mechanisms serve broadcasts without inventing a parallel discovery system.

---

## 4. VOD (Video-on-Demand) Conversion

### 4.1 Default Behavior: On

Per your decision, once a broadcast ends, its full chunk sequence is by default retained and converted into ordinary **immutable, content-addressed content** (Storage Spec §1) — at that point it requires no special handling at all: it's just content, replicated per network policy (Storage Spec §3) and delivered via ordinary static swarm-serving (Storage Spec §4) to anyone who wants to watch it later. This is close to free given the architecture already in place — the live chunks already exist and are already content-addressed pieces; VOD conversion is essentially "stop treating this as a live-propagating window and start treating it as a finished, referenceable set," plus publishing a manifest (analogous to the App Hosting manifest, §2.1 of that document) tying the chunk sequence together into a single watchable object with a stable mutable-pointer address.

### 4.2 Opt-Out — Honest Framing: Prevents Discoverability, Not Retention

A broadcaster can disable VOD retention **per stream, at broadcast time** (not a global account-level setting) — when disabled, the live chunk sequence is not converted into a persistent, named manifest/pointer after the broadcast ends, so it doesn't become something the platform itself surfaces or makes casually discoverable after the fact.

**This document previously implied a stronger guarantee than is actually achievable, and that's corrected here rather than left standing.** Opt-out prevents the *platform* from publishing a discoverable, retrievable record of the broadcast — it does not, and cannot, prevent a viewer who received the live chunks from independently retaining and republishing them on their own. This isn't a gap specific to this design; it's inherent to how any streaming or broadcast system works — anything decrypted and shown to a legitimate viewer can, in principle, be captured and kept by that viewer, regardless of what the originating platform does or doesn't do with it afterward (the same "analog hole" that applies to any content, digital or otherwise, once it's been legitimately displayed to someone). Stating this plainly here is consistent with how this project handles similar limits elsewhere (e.g. Core Protocol Spec §3.1's corrected revocation guarantee) — the honest scope of a guarantee, not an overstated one.

### 4.3 Encryption Continuity

Since the live stream and its VOD form share the same underlying epoch-key/DEK encryption model (§3.5, Storage Spec §1.2/§5), converting to VOD requires no re-encryption step at all — the exact same ciphertext chunks that were propagated live simply become the VOD's immutable content, and its DEK is wrapped under the epoch key exactly as any other object's would be. This also means VOD content is subject to the same revocation/rotation behavior as any other content (Storage Spec §5) — if the broadcaster's identity is later revoked from the network, VOD content follows the same live-pointer re-wrap-or-go-dark rules as any other mutable-pointer-referenced content, per Storage Spec §5's corrected, honest revocation guarantee.

---

## 5. Summary: What Other Specs Should Assume From This Document

- Calls use direct mesh below a policy-configurable participant threshold (default ~4–5) and switch to blind-relay-mediated above it, transparently mid-call if needed. Both this transition and relay failover use one shared renegotiation mechanism — trigger, propose, lightweight tie-break, make-before-break handover (§1.4) — reusing existing call signaling infrastructure rather than new machinery.
- Media relay (`relay_media_willing`) is a distinct capability-ledger role from bootstrap/connection relay, selected using the same general signal set as swarm-serving but weighted toward latency/jitter.
- A relay carries **one envelope per frame from each sender and replicates it to the rest of the call** (§2.2.1). A sender addressing each recipient separately is the mesh form; on a relay it costs the sender exactly what mesh costs and is therefore the wrong form to switch to. The fan-out set is the participant list the relay was told, never one the sender supplies, and each forwarded copy is readdressed to the participant that receives it.
- **Call media is delivered unreliably and unordered** (§1.5) — QUIC datagrams or equivalent — because a frame past its playout deadline is worthless and retransmitting it head-of-line blocks everything behind it. This is architectural, not tuning. Call *signalling* (§1.4) and live-stream *chunks* (§3.2) are both correctly reliable, and the three must not be collapsed into one channel with one delivery model.
- Live streaming is neither a call nor static swarm-serving — it's a live-propagating swarm, where viewers who already have a chunk immediately help redistribute it, keeping broadcaster upload cost roughly constant regardless of audience size. First-tier redistributor assignment reuses the Storage Spec's HRW placement algorithm directly (§3.3) — deterministic and coordination-free, weighted **only by gossiped capacity**, specifically `bandwidth_cap` rather than storage placement's `storage_offered`, since this role forwards throughput rather than holding bytes (local-only `reliability_signal` is explicitly not an input in either case, since every node must compute the same tier; Core Protocol Spec §4.6). Computed once per stream rather than per chunk, with no explicit "promote to redistributor" signaling needed. Call relay selection (§2.3), by contrast, is a local per-node decision and *may* use `reliability_signal` — these two are not the same kind of choice and must not be implemented with the same weighting. **Unlike call relays, stream redistributors are not blind** — they hold the network's epoch key as ordinary members and could decrypt what they forward, even though nothing requires them to (§3.5); a future restricted-audience stream feature cannot reuse epoch-key encryption and would need its own scoped keying, closer to how calls work.
- Finished broadcasts convert to ordinary immutable, swarm-servable VOD content by default (broadcaster can opt out per-stream), requiring no new storage mechanism — it's the same primitives from the Storage spec applied to now-finished content. **VOD opt-out prevents the platform from surfacing a discoverable record — it cannot prevent a viewer who already received the stream from independently retaining and republishing it** (§4.2); this is an inherent limit of any streaming system, not a gap specific to this design, and consuming specs should not imply a stronger guarantee than this to users.
- Any future application-layer spec should treat calls, live streams, and VOD playback as three distinct but capability-ledger-consistent transport primitives it can build a UI on top of, not three unrelated systems.

---

## 6. Explicitly Open Questions

1. Exact chunk/segment duration and codec choices for both calls and streams — implementation-level tuning, not architectural. Frame-loss concealment is part of this: §1.5 requires that late and lost frames be dropped, and *how* the resulting gaps are concealed is a codec decision.

**Previously listed as the last remaining item, which was wrong.** Call media *delivery semantics* — reliable versus unreliable — were never specified and were mistakenly treated as covered by "transports: TCP and QUIC" in Core Protocol Spec §5.1. They are architectural rather than tuning, because the choice determines what a conversation does under packet loss, and they are now stated in §1.5. Every other question originally flagged (mesh↔relay renegotiation, relay failover, live-propagation tier assignment) remains resolved in the sections above.
