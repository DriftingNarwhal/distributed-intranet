# Storage & Replication Specification

**Document status:** Draft v1 — architecture/design only, not implementation
**Depends on:** Core Protocol Spec (identity, capability ledger, epoch-based encryption)
**Consumed by:** App Hosting Spec (published apps are stored content), and any future application-layer specs

---

## 0. Purpose and Scope

This document specifies how content is stored, addressed, replicated, encrypted, and updated across a network. It covers:

1. **Immutable content addressing** — the IPFS-like layer, for data that never changes once published.
2. **Mutable pointers** — a generic primitive for content that has an owner and gets updated over time (e.g. a published app's current version), without which nothing above this layer can represent "this got edited."
3. **Replication** — how many copies of something exist, where, and how that's decided and maintained (durability-driven).
4. **Swarm-based serving** — how content is actually *delivered* to requesters on demand (demand-driven), so no single node — including the original publisher — becomes a bottleneck for popular content.
5. **Encryption integration** — how stored content ties into the epoch-key rotation defined in the Core Protocol Spec, via envelope encryption (per-object DEKs wrapped under the epoch key) rather than direct content re-encryption.

Out of scope: what any specific application does with this layer (that's the App Hosting spec and any future application-layer specs) — this document only defines the storage primitives they build on.

---

## 1. Immutable Content Addressing

### 1.1 Model

Content is identified by a hash of its (encrypted) bytes — a **content ID (CID)**, following the same principle as IPFS: the address *is* a function of the content, so identical content always produces the same ID, and any change produces a different ID. This gives free integrity verification (any node can confirm retrieved content matches its claimed CID). Deduplication is **scoped to an object's own version history, not global across unrelated publishes** — see §1.2 for why, and why that's a deliberate tradeoff rather than an oversight.

### 1.2 What Gets Hashed, Encryption Order, and Determinism — Corrected

**Chunking happens on plaintext, before encryption — this ordering is required, not incidental.** Content-defined chunking (§1.3) determines chunk boundaries from the content's own bytes via a rolling hash; encryption effectively randomizes output, so encrypting first and chunking second would destroy the content-similarity signal CDC depends on, and a one-line edit would once again look like an entirely different file to the storage layer — defeating the delta-fetch benefit this whole approach exists to provide.

**Chunk encryption must be deterministic per (chunk plaintext, key) — this was previously required implicitly by the delta-fetch and deduplication claims below, without ever being stated as an explicit requirement, which was a real correctness gap.** Semantically secure encryption with random nonces (e.g. ordinary AES-GCM) produces different ciphertext for the same plaintext on every encryption — which means re-publishing an edited object would give *every unchanged chunk* a brand-new CID too, silently destroying the entire delta-fetch property this design depends on. To actually deliver what §1.3 promises, chunk encryption must use a **synthetic/deterministic nonce derived from the chunk's own plaintext** (e.g. a nonce computed as `HMAC(key, hash(chunk_plaintext))`, in the spirit of AES-SIV or convergent-encryption-style keying) — the same chunk plaintext, encrypted under the same key, always produces the same ciphertext, and therefore the same CID. This introduces a known, accepted tradeoff: an **equality leak** — two identical chunks under the same key are visibly identical as ciphertext to anyone who can see that ciphertext, even without the key. This is precisely what deduplication requires structurally, and it's a defensible choice given who can actually observe that equality (holders of ciphertext are already network members with legitimate access to the swarm, per Storage Spec §5's encryption scope) — but it is a real cryptographic design decision with a real tradeoff, not a free property, and this document did not previously say so.

**Envelope encryption: each object gets its own randomly-generated Data Encryption Key (DEK), used for the determinism above — not the network's epoch key directly.** At creation, an object (a mutable pointer's initial content) is assigned a fresh, random DEK. That DEK — not the epoch key — is what chunk encryption is deterministic *with respect to* (point above): same chunk plaintext, same DEK, same ciphertext, same CID. The DEK is generated once and **stays fixed for the object's lifetime**, across every subsequent edit/version, which is exactly what preserves delta-fetch across an object's version history: two versions of the same object, encrypted under the same fixed DEK, produce identical CIDs for any chunk whose plaintext didn't change between versions. The DEK itself is never transmitted in the clear — it's **wrapped (encrypted) under the network's current epoch key** and stored as a small field alongside the object's mutable pointer (§2.2); unwrapping it requires holding the current epoch key, tying object access back to network membership without requiring the epoch key to ever touch the (potentially large) content itself.

**Why deduplication is scoped per-object, not global, as a deliberate consequence:** because each object has its own independently-generated DEK, identical plaintext published as two unrelated objects will *not* produce identical ciphertext or CIDs by default (different DEKs mean different deterministic outputs even for the same input) — so the earlier "free deduplication" claim in §1.1 was overstated for the general case. What's actually preserved, and what's the property that genuinely matters for this platform's stated goals, is deduplication **within an object's own edit history** — which is exactly the "don't re-download a page you already have most of" case this whole design exists to serve. Cross-object dedup for coincidentally-identical content from unrelated publishes is given up in exchange for cheap rotation (below) and for closing a real security gap that a network-wide shared encryption scope would otherwise create — a trade worth making explicitly, not silently.

**Why this makes rotation cheap — the direct payoff of this rework.** Because content chunks are encrypted under a *per-object* DEK rather than the network-wide epoch key directly, an epoch rotation (triggered by revocation, Core Protocol Spec §3) never needs to touch content ciphertext or CIDs at all — it only needs to **re-wrap each live object's small DEK record** under the new epoch key. This is the mechanism that resolves the cost and availability problems the original full-content-re-encryption design had at scale; see §5 for the complete mechanics, including who performs the re-wrap and what happens to already-cached access.

### 1.3 Chunking

**Decided: content-defined chunking (CDC)**, not fixed-size chunking — e.g. FastCDC or an equivalent rolling-hash-based scheme, for which mature implementations exist, including in Rust. This choice is driven directly by a requirement from elsewhere in this project: a node re-visiting content it already holds (e.g. re-checking a wiki page for updates) should only need to fetch what actually changed, not re-download the whole object. Fixed-size chunking doesn't support this well — a single byte inserted near the start of a file shifts every subsequent chunk boundary, making a small edit look like a near-total rewrite to the storage layer. Content-defined chunking determines boundaries from the content itself, so a local edit only disturbs the chunk(s) immediately around it; everything else re-chunks identically and is recognized as already-held, unchanged data by both requester and swarm.

**Target chunk size is a network-wide policy setting**, not a fixed protocol constant — consistent with how this project handles other tunables (replication factor, Storage Spec §3.1; mesh/relay threshold, Real-Time Spec §1.2), configured via the same governance mechanism as other network policy (Core Protocol Spec §2.6), defaulting to a target somewhere in the **16–64KB** range. This must be a single consistent setting across a given network, not chosen per-publisher: content-defined chunking's deduplication benefit depends on identical content producing identical chunk boundaries, and two publishers using different target sizes within the same network would silently lose deduplication between otherwise-identical content. Changing a network's target chunk size going forward doesn't retroactively re-chunk already-published content, since chunking occurs once at publish time.

**Small-file exemption:** content below the target chunk size is stored as a single chunk, skipping rolling-hash computation entirely, since there's nothing to gain from chunking something already smaller than one chunk.

Each object's chunk sequence is referenced by a manifest listing the chunk CIDs in order — this is what §2 (Mutable Pointers) and later documents (e.g. App Hosting's bundle manifest) build on.

---

## 2. Mutable Pointers

### 2.1 The Problem

Content addressing is inherently immutable — "this piece of content as it exists right now, and however it gets updated later" needs a *stable* identifier that other things (links, bookmarks, an app's reference to its own latest version) can point to permanently, while the content it resolves to changes over time.

### 2.2 The Primitive

A **mutable pointer** is a small, signed, versioned record, itself stored and replicated like any other content, with a structure along these lines:

```
MutablePointer {
  pointer_id:      stable identifier, chosen at creation, never changes
  owner_identity:  the per-network identity (Core Protocol Spec §1.2) authorized to update this pointer
  content_type:    declared type tag (e.g. "text", "image", "app-bundle") — checked against the
                    network's content-type allowlist (Core Protocol Spec §2.8) at publish time
  current_cid:     content ID this pointer currently resolves to
  dek_commitment:  hash(DEK) — a commitment to this object's Data Encryption Key (§1.2), letting
                    any node verify a wrapping is authentic without the owner having to re-sign
                    every time that wrapping changes (§5.3 explains why this split matters)
  version:         monotonically increasing counter (or Lamport-clock-style logical clock)
  signature:       owner's signature over (pointer_id, content_type, current_cid, dek_commitment, version)
}
```

**The DEK's current wrapping is deliberately *not* part of the signed pointer record — it's a separate, freely-republishable attachment**, corrected from an earlier version of this document that put `wrapped_dek`/`dek_epoch` directly inside the owner-signed fields:

```
DekWrapping {
  pointer_id:    which object this wrapping is for
  wrapped_dek:   the DEK, wrapped under a specific governance-log-anchored rotation (§5.3)
  rotation_ref:  the hash of the governance log entry that produced the epoch this DEK is wrapped
                 under — not a bare epoch counter (§5.3 explains why the distinction matters)
  wrapper_identity, signature:  whoever produced this wrapping and their signature — recorded for
                 accountability/anti-spam purposes only, and is *not* what makes a wrapping valid
}
```

A `DekWrapping` is valid if and only if unwrapping `wrapped_dek` (using the epoch key for `rotation_ref`) produces a value whose hash matches the pointer's `dek_commitment` — validity is verified against the owner's original commitment, not against who happened to publish the wrapping. This is exactly what makes it safe for *any* current member to produce and publish a re-wrap (§5.3): they're never asked to forge the owner's authority over the pointer, only to demonstrate they correctly wrapped the DEK the owner already committed to.

- Resolving a pointer means: fetch the latest signed `MutablePointer` record for `pointer_id`, verify the signature is from `owner_identity`, verify `version` is higher than any previously-seen version (to reject replay of a stale pointer state); separately, fetch the current valid `DekWrapping` for that `pointer_id`, verify it against `dek_commitment`, unwrap it using the current epoch key, then fetch and decrypt `current_cid`'s chunks using that DEK (§1.2).
- Updating content means: publish new immutable content (get a new CID), then publish a new `MutablePointer` record with that CID and an incremented version, signed by the owner. `dek_commitment` is carried forward unchanged on an ordinary content update — the DEK itself never changes across an object's life (§1.2), only its wrapping does, and that lives outside the signed record entirely. **A `DekWrapping` update never increments the pointer's `version` counter** — since re-wrapping is no longer part of the owner-signed record, there's nothing for concurrent re-wraps to collide on, which is exactly the point of the split. **Every publish, including updates, must pass two independent checks (Core Protocol Spec §2.8): the declared `content_type` must be on the network's current allowlist, and the publishing identity must belong to a group holding `publish:<content_type>` for that specific type.** Either check failing means the publish is rejected outright by receiving/replicating nodes, fail-closed and protocol-enforced, not merely conventional. Note the two checks answer different questions: the allowlist governs whether the type may exist on this network at all; `publish:<content_type>` governs whether *this* identity is one of the ones permitted to create it — a network can allow a type broadly while still restricting who may actually publish it (e.g. `app-bundle` allowed on the network, but `publish:app-bundle` held only by a small maintainers group).
- **Version *collisions* between concurrent publishers are resolved by the same deterministic tie-break the governance log already uses.** Rejecting *lower* versions (above) does not cover the case where two valid `MutablePointer` records for the same `pointer_id` claim the **identical** `version` number — two publishers each building on the same prior version concurrently, neither having seen the other. When that happens, **the record with the lower record-hash wins**, exactly as for sibling governance log entries (Core Protocol Spec §2.7.1, point 1): no new rule, no negotiation, no timestamps to backdate, and any node holding both records independently computes the same answer. The losing record is **rejected, not merged or queued** — its publisher must retry by publishing again with an incremented `version` against the now-canonical record, the same retry-against-current pattern any optimistic-concurrency scheme uses. **This resolves only which record is provisionally canonical when versions collide; it deliberately does not define what two concurrent edits *mean* together.** Content-merge semantics (reconciling the substance of competing edits, and any UX around that) remain deferred to whichever application-layer spec first needs them (§7) — nothing here should be read as supplying them, and an implementation should not invent merge behavior to fill that gap.
- Any node holding a copy of an old `MutablePointer` version can detect it's stale (a newer signed version exists) and update its local reference — this is a natural fit for the same gossip mechanism used for capability ledger propagation (Core Protocol Spec §4.5).

### 2.3 Ownership and Authorization

`owner_identity` is a single identity by default (matching a "single owner, others read" model). Nothing in this primitive prevents `owner_identity` from later being redefined as a group holding an appropriate capability (Core Protocol Spec §2) rather than a fixed identity — that kind of decision is deferred entirely to whatever application-layer spec first needs it. The primitive itself is intentionally agnostic to that decision.

**`owner_identity` and `publish:<content_type>` govern two different moments, not the same permission.** `publish:<content_type>` is checked once, at the moment a *new* `pointer_id` is created — it answers "may this identity publish a new thing of this type at all?" `owner_identity` then governs every *subsequent update* to that specific, already-created pointer — it answers "may this identity change what this particular thing currently points to?" A group broadly holding `publish:text` might contain many members who can each create their own new text pages, while each individual page's `owner_identity` narrows back down to whoever specifically created (or was later assigned as owner of) that one page.

### 2.4 Why This Belongs Here, Not in an App Spec

Any future consumer needing "a stable address for something that gets updated" — app publishing (next document) being the first concrete case — should use this same mechanism rather than inventing its own versioning scheme.

### 2.5 Distributed Append-Sets — A Second Primitive for Multi-Writer Collections

**A mutable pointer is inherently single-writer** — one `owner_identity`, one linear version history. Several real needs in this platform's design don't fit that shape at all: a network's browsable app directory (App Hosting Spec §4.4) needs many different publishers to register names independently; a search index (Search Spec §3.1) needs many different publishers to contribute postings under shared search terms. Both were originally specified as "just write to a shared key," which doesn't actually work — a single DHT key with no coordination between independent writers is a known hard multi-writer problem (concurrent-write conflicts, unbounded growth, no real way to enumerate what's there), and it was a real gap for this document to leave unaddressed. This section defines one generic primitive both consumers build on, rather than each inventing its own ad hoc fix.

**The primitive: reuse the DHT's existing provider-record mechanism, applied to a logical collection instead of a single CID.** Content routing already has a native answer to "many independent nodes can each announce something under one shared key without conflicting with each other" — Kademlia provider records, which is exactly how "who currently holds CID X" announcements already work for ordinary swarm-serving (Storage Spec §4). A **distributed append-set** is simply this same mechanism applied one level up:

```
AppendSetEntry {
  collection_id:       hash(network_id + collection-specific-name) — e.g. hash(network_id + "app-registry")
  entry_id:             content hash of this entry's own payload — the entry is itself ordinary,
                         independently content-addressed immutable content (§1)
  payload:               the entry's actual data (e.g. a name-registration record, or a search posting)
  publisher_identity:    per-network identity of whoever created this entry
  signature:             publisher's signature over the entry
}
```

- **Publishing an entry** means: publish the entry's payload as ordinary content (§1), then announce "I am a provider of `entry_id` under `collection_id`" via the same Kademlia provider-record mechanism already used for content routing — no new DHT operation, no custom conflict resolution, because nothing is actually being overwritten. Each entry is independently addressed; different publishers' entries simply coexist as separate provider-record announcements under the same collection key.
- **Enumerating a collection** means: query the DHT for all current providers under `hash(collection_id)`, which returns the current set of `entry_id`s announced, then resolve each to its content as normal. This is what makes a collection genuinely browsable — a real improvement over a single hash-keyed pointer, which had no such property at all. **Enumeration is best-effort, not a completeness guarantee** — real Kademlia implementations cap the number of providers returned and stored per key, so a very large or unusually popular collection may not be fully enumerable in one pass. This is an accepted, stated limitation for uses where best-effort discovery is the actual requirement (e.g. search, §3.1) — consumers that need a genuinely authoritative, complete answer (e.g. "who owns this name," App Hosting Spec §4.3) should not rely on enumeration completeness alone, and should anchor their authoritative answer elsewhere (see App Hosting Spec §4.3 for how the name registry specifically handles this).
- **Freshness follows the same TTL-and-refresh pattern already used elsewhere** (capability ledger propagation, Core Protocol Spec §4.5) — a publisher periodically re-announces its entries, and un-refreshed entries fall out of the collection naturally, with no separate deletion protocol needed. **This freshness model is appropriate for discovery-oriented collections (like search postings) but not for anything where losing an entry due to the publisher's node being offline would itself be a security problem** — see App Hosting Spec §4.3 for a case (name ownership) where TTL-based liveness is actively the wrong model, and how that's handled instead.
- **Each entry carries a `dek_commitment`, with its actual key wrapping as a separate, freely-republishable attachment — the same split used for mutable pointers (§2.2), for the same reason.** An append-set entry is otherwise ordinary content, chunked and DEK-encrypted like anything else (§1.2), and inherits the same cheap-rotation property (§5) — but since an entry has no single `owner_identity` in the mutable-pointer sense to sign a re-wrap, the commitment/wrapping split isn't optional here the way it might first appear for pointers — it's the only way re-wrapping an entry's key material can work at all without reintroducing a publisher-liveness dependency on rotation. Any current member can produce and publish a fresh wrapping for any entry it's tracking, verified against that entry's `dek_commitment`, exactly as described in Storage Spec §5.3.
- **Validation is mandatory, not optional, for any node storing or relying on provider-record data for a collection.** A storage/routing node must verify: (a) an entry's signature is valid, (b) the signing identity is a **current member** of the network (checked against replayed governance state, Core Protocol Spec §2.7), and (c) **if the entry's payload references other pointer-addressed content (e.g. a search posting referencing the pointer it indexes), that referenced pointer is not currently delisted** — determined by replaying the governance log for the most recent `ModerationEntry` targeting that `pointer_id` (Core Protocol Spec §2.7), which is the concrete record behind this check; it is the same replayed-governance-state lookup already performed for check (b), not a second mechanism, and a pointer with no `ModerationEntry` is simply not delisted — without all three checks, a malicious or revoked identity could keep announcing entries indefinitely regardless of moderation action taken elsewhere (checks a–b), or a still-current member could keep an index entry alive for content that's already been moderated away (check c), both of which would make moderation elsewhere in this design toothless in practice rather than actually effective.
- **This reuses baseline DHT participation, not the opt-in storage-replication mechanism (§3), and that distinction matters.** Maintaining routing-table entries and provider-record announcements is ordinary, lightweight overhead every DHT-participating node already performs as part of being on the network at all — it is not the same thing as opting in to hold a full content replica, which remains explicitly gated by a node's declared `storage_offered` (Core Protocol Spec §4.2, Storage Spec §3). A popular collection with many entries doesn't conscript nodes into heavier storage duty than ordinary DHT routing already requires, and doesn't contradict this project's opt-in-contribution principle — because the two kinds of storage this section and §3 are talking about are genuinely different in scale and in what a node signed up for.

App Hosting's name registry and Search's posting index are both, from this point forward, concrete instances of this one primitive — see App Hosting Spec §4.3–4.4 and Search Spec §3.1 for how each configures `collection_id` and `payload` for its own purpose, and for how the name registry specifically layers governance-log anchoring on top of this primitive to get the durability and trustworthy ordering that discovery-oriented use cases like search don't need but authoritative naming does.

---

## 3. Replication

### 3.1 Replication Factor: Network-Wide Policy

Per your decision, replication factor is a **network-wide setting**, not chosen per-publisher. It's configured as part of a network's policy (Core Protocol Spec §2.6 — the same place governance policy lives), e.g. "replicate every piece of content to N nodes," set at genesis and changeable later by whoever holds the relevant capability.

This keeps the publishing experience simple (a publisher never has to think about durability trade-offs) and centralizes the decision where it belongs: with whoever is responsible for the network's overall health.

### 3.2 Degraded Availability in Small Networks

If a network has fewer than N willing/eligible nodes (per the capability ledger's `storage_offered` field), the system replicates to **as many nodes as are available** and accepts reduced durability, rather than failing to publish or blocking on unmet targets. This is a deliberate design choice: a 3-person friend network should still function, just with weaker durability guarantees than a network with thousands of nodes — the protocol should never punish small networks by refusing to operate.

Practical implication: replication status should be observable (a node/publisher can see "this content is at 2 of target 3 replicas") so degraded durability is visible rather than silent, even though it isn't blocking.

### 3.3 Replica Placement — Rendezvous Hashing (HRW)

**Decided: replica placement uses Rendezvous Hashing (Highest Random Weight, HRW)**, a deterministic, coordination-free placement algorithm purpose-built for this exact problem in distributed systems, rather than plain weighted-random selection.

**Mechanism:** for a given CID, every eligible node's placement score is computed as

```
score = hash(CID, node_id) × storage_offered
```

where `storage_offered` is read from that node's **gossiped** capability ledger entry (Core Protocol Spec §4.2). The top N nodes by this score form the replica set for that CID.

**`reliability_signal` is deliberately *not* an input to this score — a correction, not an omission.** An earlier version of this section derived the weight from `storage_offered` *and* `reliability_signal`, which silently destroyed the determinism this entire section depends on: `reliability_signal` is local-only observation state that is never gossiped (Core Protocol Spec §4.6 — a deliberate anti-slander decision, not an incidental one, and one that must not be reversed to make this formula easier). Every node therefore holds a *different* value for the same peer, so a placement function taking it as an input yields a *different* replica set on every node — precisely the outcome HRW was chosen to prevent, and one that would have made the harness's exact-match placement assertion (Reference Test Harness Spec §4) unsatisfiable by any correct implementation. Placement weights only network-visible, gossiped capacity. **Unreliable nodes are still corrected for, just at a different point in the design:** the replica-repair loop (§3.4) re-places content away from nodes that fail to actually hold or serve what they were assigned — remediation based on observed outcomes, rather than biasing initial placement on evidence no two nodes agree on.

**Why this solves anti-correlation without extra metadata:** the `hash(CID, node_id)` term effectively reshuffles the ranking independently per CID — a node that scores highest for one piece of content is very unlikely to score highest for most others, even holding its declared capacity constant. High-capacity nodes still get proportionally *more* replica assignments than low-capacity ones (the weighting isn't discarded), just not the *same* fixed set every time — which is exactly what prevents the network's storage burden (and its practical takedown surface) from concentrating on a small, easily identified set of nodes.

**Why HRW specifically, over plain weighted-random:** it's **deterministic** — any node can independently recompute the identical replica set for a given CID just from the CID and the capability ledger, without needing to gossip or store "who was assigned this" as a separate fact. Placement becomes a pure function rather than a decision that has to be made once and remembered.

**What that determinism does and does not claim — a clarification, not a retraction.** The sentence above is a statement about the *function*: given the same ledger contents, every node computes a byte-identical replica set. It is not a claim that every node holds the same ledger at every instant, and an earlier version of this section read as though it were. There is no single "the current capability ledger": each node holds its own cache, populated by gossip and filtered by its own staleness judgment (Core Protocol Spec §4.5). Two nodes therefore agree on placement **once their ledgers agree, not before**, and a node that has just learned of a new high-capacity peer will briefly rank differently from one that has not.

This is a materially weaker property than the one §4.6's `reliability_signal` restriction protects, and the difference is the whole point of keeping them separate. `reliability_signal` is per-observer private state that *never* converges — no amount of waiting makes two nodes agree, so a placement function taking it as an input is permanently non-deterministic. Ledger contents are network-visible and *do* converge, so disagreement is a bounded propagation window rather than a permanent property. That window is exactly what the replica-repair loop (§3.4) exists to close: content that landed on the wrong nodes during it is re-placed once the ledger settles, by the same deterministic ranking. Refresh cadence should be kept well inside the staleness TTL so the window stays small.

Conformance tests must therefore fix the ledger snapshot before asserting exact-match placement, which is how Reference Test Harness Spec §4 already states it ("given a fixed CID and a fixed capability ledger snapshot"). A test that asserted identical placement across nodes whose ledgers were still converging would be asserting a timing coincidence, not a protocol property.

This deliberately does **not** attempt geo/ASN-based failure-domain diversity (e.g. avoiding co-locating replicas behind the same ISP or region) — that would require nodes to expose additional location metadata this design doesn't otherwise need, and P2P networks frequently lack reliable geo/ASN signal for arbitrary peers anyway. Correlated-failure resistance instead comes from a different, already-established mechanism: see §3.3.1.

### 3.3.1 Volunteer Over-Replication Beyond N

The replication target N (§3.1) is a **minimum durability guarantee**, not a cap. Any node may declare `storage_offered` well beyond what's needed to be a proportionate contributor to that minimum — and when it does, no separate "volunteer backup" workflow or flag is needed: the same HRW-ranked list for a given CID simply gets extended past the cutoff at N, and a high-capacity node organically ends up holding content beyond its statistical "fair share" of baseline replicas, purely as a function of its declared capacity and the same deterministic ranking.

This is the mechanism that actually provides resilience against correlated failure, in place of geo/ASN heuristics: rather than trying to guess which failures are likely to be correlated and engineering placement around that guess, the network simply accumulates more independent copies, held by more independent people on more independent connections, whenever generous members have the capacity to offer it. Small networks still get their guaranteed minimum N cheaply (§3.2); networks fortunate enough to have high-capacity members organically get meaningfully stronger real-world durability on top, through the same single mechanism rather than a second system bolted on for it.

This is also a direct continuation of a resource-declaration principle established at the very start of this project's design: users decide, per network, how much of their machine they're willing to contribute — this section is simply that declaration doing double duty as opportunistic extra redundancy, with no additional protocol surface required.

### 3.4 Replica Maintenance

- Nodes periodically announce (via the same gossip/DHT mechanism as peer discovery) which CIDs they're currently holding.
- If a replica holder goes offline permanently (or its `storage_offered` capacity is withdrawn), the network's remaining nodes should detect the resulting under-replication and select a new node to bring the count back to target — this is conceptually identical to how IPFS-pinning-service clusters or Storj-style repair mechanisms handle replica repair, and doesn't need a novel mechanism, just a defined trigger (periodic scan for under-replicated CIDs) and the same HRW placement logic from §3.3.
- **Repair — not placement weighting — is where unreliable nodes are corrected for**, per §3.3's removal of `reliability_signal` from the placement score. A node that is assigned replicas but repeatedly fails to hold or correctly serve them surfaces to the rest of the network as ordinary under-replication for those CIDs, and the trigger above re-places that content onto the next nodes in the same deterministic HRW ranking. No reputation input to placement is needed to get this effect, and none is used: repair reacts to the observable fact that copies are missing, which every node can see identically, rather than to per-observer private judgments about a peer, which they cannot. Repair placement therefore stays as deterministic and independently recomputable as initial placement.
- This repair process is itself something a node opts into performing based on its capability ledger entry — not every node needs to run repair-scanning logic, but at least some willing nodes per network should.

---

## 4. Swarm-Based Serving

### 4.1 Purpose and Relationship to Replication

Replication (§3) answers "how many durable copies exist, independent of demand." This section answers a different question: **when a node requests a CID, who actually serves it, and how does the network make sure a suddenly-popular piece of content doesn't overload any single node — including the original publisher?**

This is the mechanism that fulfills the original goal behind app hosting (publish once, let the network absorb demand) and is modeled directly on swarm/BitTorrent-style distribution rather than a fixed-replica-set model.

### 4.2 Swarm Membership Is Automatic

Any node that has fetched a CID for any reason — because it's one of the N durability replicas from §3, or simply because a user viewed/used that content — becomes an eligible server for that CID to other requesters, for as long as it keeps the data cached locally. There is no separate opt-in per item; participation is governed by the node's existing general-purpose resource limits already declared in the capability ledger (`bandwidth_cap`, `storage_offered`), not a new per-content setting.

Concretely, in your original example: Person A publishes, Person B fetches it to view it, and from that point Person B is automatically a candidate server for Person C's request — without Person B doing anything explicit to "start serving."

### 4.3 Server Selection

When a node needs to fetch a CID, it identifies known swarm members currently holding it (via the DHT/gossip layer, alongside the same peer-discovery machinery used elsewhere) and selects among them using:

- **Network distance** — hop count / observed latency, from routing information already available via the DHT.
- **Available throughput** — read from the candidate's capability ledger entry.
- **Current load** — how many concurrent requests a candidate is already serving, so load naturally spreads rather than piling onto whichever node happens to have the best raw stats.
- **Local reliability observations** — `reliability_signal` (Core Protocol Spec §4.6): a candidate this node has personally observed failing hash/signature verification is deprioritized as a source. **This is one of only two selection paths where that signal may legitimately be used** (the other being media relay selection, Real-Time Spec §2.3). Both are purely local, per-requester decisions with no cross-node consistency requirement — it does not matter, or even make sense, for two nodes to pick the same source — which is exactly what distinguishes them from replica placement (§3.3), a deterministic computation every node must reproduce identically and which therefore cannot take this signal as an input.

### 4.4 Multi-Source Parallel Chunk Fetch — Resolved

For content spanning multiple chunks (§1.3), fetching proceeds as follows, directly reusing mechanisms already established elsewhere in this document rather than introducing new machinery:

1. The requester holds the object's manifest (ordered chunk CID list, §1.3) and queries the DHT for each chunk CID it doesn't already hold locally, getting back the set of current swarm members holding that chunk — as a side effect, this query also yields a **holder count per chunk**.
2. **Decided: rarest-first prioritization.** Chunks are fetched in order of scarcity — chunks with the fewest current holders are requested first, following the same principle BitTorrent uses. This keeps the swarm healthier as a whole: scarce chunks (held by only one or two peers) get additional copies in circulation sooner, reducing the window in which they could become temporarily unavailable if their few holders go offline. This requires only the holder count already obtained in step 1, not new bookkeeping.
3. For each chunk, a source is selected using the same criteria already specified in §4.3 (distance/latency, `bandwidth_cap`, current load) — applied per-chunk rather than per-object; no new selection logic.
4. Chunks are fetched **simultaneously from multiple different sources** — a large object's total fetch time is bounded by the swarm's aggregate available throughput across sources, not any single source's throughput.
5. Each chunk is independently hash-verified against its CID on arrival, per the mandatory content-addressing guarantee already established in §1.1 — no special-case handling needed for corrupt or malicious chunks: a failed verification simply means that source's copy is discarded and the chunk is re-requested from a different holder, and it also feeds that source's `reliability_signal` (Core Protocol Spec §4.6) as an ordinary verification-failure event, same as anywhere else in the system.

**Concurrency degree is a local, per-node setting, not a network policy.** How many chunks a requester fetches simultaneously is purely about how aggressively that one node wants to use its own downstream bandwidth — unlike chunk size (§1.3), it has no cross-node consistency requirement, so there's no reason to make it a network-wide, governance-configured value.

### 4.5 Backpressure and Publisher Protection

Each node enforces its own `bandwidth_cap` locally. When a node is saturated, it simply stops being offered as a candidate for new requests until capacity frees up — no central throttling authority needed, since the cap is self-enforced and self-reported the same way every other capability-ledger field works.

This directly solves the "don't let my machine become unusable because I published something popular" concern from the original design goals: as more people view a piece of content, more nodes join its swarm and share the serving load, and the original publisher's node is never structurally required to remain the primary (or even a) source once at least one other viewer holds a copy. A publisher can go fully offline after initial distribution and popular content remains servable — which also reinforces takedown-resistance specifically for the content that would otherwise be the most attractive target.

### 4.6 Relationship to Replication Targets

Swarm-serving copies and durability replicas (§3) are not force-distinguished in storage — a node doesn't need to know "am I a designated replica or just an opportunistic cache holder" for serving purposes, both simply hold the bytes and both are eligible to serve. The distinction only matters for the *repair* process in §3.4, which specifically cares about maintaining the durability-guaranteed count N regardless of transient demand-driven copies coming and going as viewer interest rises and falls.

---

## 5. Encryption Integration

### 5.1 Content Encryption

Every chunk of content is encrypted deterministically under its object's own Data Encryption Key (DEK) — not the network's epoch key directly — immediately after chunking and before hashing (§1.2: chunk plaintext first, then encrypt each chunk deterministically under the object's DEK, then hash to get its CID). The DEK's *commitment* is carried inside the owner-signed pointer (§2.2); its current *wrapping* is a separate, freely-republishable attachment (§2.2, §5.3). This means any node without network membership (and therefore without any epoch key, and therefore unable to unwrap any object's DEK) that somehow obtains raw replicated bytes gets nothing but ciphertext, CIDs, and an opaque wrapped key blob it cannot open — replication can safely happen across the general peer-to-peer transport without leaking content to non-members who happen to relay traffic.

### 5.2 Rotation Is Cheap: Only the Wrapping Changes, Not the Content

**This is the direct payoff of the envelope-encryption model in §1.2, and it resolves what was previously the single biggest scalability problem in this document.** Because content chunks are encrypted under a per-object DEK that never changes, and only that small DEK is wrapped under the epoch key, an epoch rotation (triggered by revocation, Core Protocol Spec §3) never requires touching content ciphertext, recomputing CIDs, or re-replicating anything. It requires exactly one thing: **producing a fresh `DekWrapping` (§2.2) for each live object under the new epoch**, published as an independent attachment — never a pointer version update (§2.2).

Contrast with the original design this replaces: previously, a revocation event required re-encrypting every live-referenced object's *entire content* — new ciphertext, new CIDs for every chunk, full re-replication, all swarm/replica placement state invalidated. In a large, high-churn network (this project's stated target of hundreds of thousands of members), that meant the network was perpetually re-encrypting and redistributing its own corpus just to keep up with routine membership changes — a real availability and cost problem, not a hypothetical one. Under the corrected model, rotation cost is proportional to the number of live objects' small key records, not the total size of the network's content — a difference of orders of magnitude at scale.

**Content with no live pointer referencing it** (orphaned/historical immutable data, e.g. an old, superseded version of a page, if the network chose to keep history) is simply never re-wrapped — its most recent `DekWrapping` stays fixed under whatever rotation it was last touched in, and nobody without that specific old epoch key can unwrap it once that epoch key is no longer distributed to new members — the intended, unconditional effect for content nobody's actively maintaining access to (see §5.4 and Core Protocol Spec §3.4 for what actually remains policy-configurable versus what's now unconditional).

### 5.3 Who Performs the Re-Wrap — Fixed: The Owner-Signature Contradiction

**An earlier version of this document said "any current member can re-wrap and publish the updated pointer fields" while simultaneously specifying that the pointer's signed fields include the wrapped DEK, verified against `owner_identity`. Those two statements directly contradict each other — a non-owner cannot produce a valid signature over a field attributed to the owner, so as originally written, honest nodes would have had to reject every non-owner re-wrap, silently reintroducing the exact owner-offline blackout this whole rework exists to eliminate.** This is fixed by the commitment/wrapping split introduced in §2.2, not by weakening who's allowed to re-wrap:

- **The owner signs a one-time commitment** (`dek_commitment = hash(DEK)`) inside the pointer record, at creation, and never needs to re-sign anything related to the DEK again for the rest of the object's life.
- **The wrapping itself (`DekWrapping`, §2.2) lives outside the owner-signed record entirely**, and is valid whenever unwrapping it (using the epoch key for its stated `rotation_ref`) produces a value matching the pointer's `dek_commitment` — a check anyone can perform, regardless of who published the wrapping. This is what actually makes "any current member can re-wrap" true rather than contradictory: a re-wrap never needs the owner's signature, because its legitimacy comes from matching the owner's original commitment, not from a fresh signature over each new wrapping.
- **The wrap operation itself must be deterministic**, for the same reason chunk encryption must be (§1.2): wrapping the same DEK under the same epoch key must always produce the same ciphertext bytes (e.g. via the same synthetic-nonce approach used for chunks), so that multiple members independently re-wrapping the same object under the same rotation produce byte-identical `DekWrapping` records with no conflict to resolve — this was an unstated requirement in the original design and is made explicit here.
- **`rotation_ref` references the governance log entry hash that produced the epoch, not a bare epoch counter.** This matters specifically under the fork-choice model (Core Protocol Spec §2.7.1): two competing branches can each legitimately produce "the next epoch" with the same ordinal number, and a bare counter can't disambiguate which rotation a given wrapping actually corresponds to. Referencing the entry hash directly resolves this, and is also what makes cleanup after a voided branch well-defined (§5.3.1 below) — a node can always tell, by comparing a wrapping's `rotation_ref` against current canonical governance state, whether that wrapping is for a rotation that's still canonical or one that got voided.
- **No proxy re-encryption scheme is needed**, because there's no plaintext-exposure problem to solve with one — a DEK re-wrap never involves content plaintext, so the mechanism this document previously specified (opt-in PRE proxies, generated at publish time) remains unnecessary and stays removed.
- **In practice:** any node that observes an epoch rotation and is tracking a given object (as a replica holder, an active swarm participant, or simply the owner if they happen to be online) can and should produce and publish a `DekWrapping` for it, asynchronously and independently — multiple nodes redundantly doing this for the same object produces no conflict, by construction (determinism, above), consistent with this project's general eventually-consistent, no-single-point-of-responsibility design philosophy.

### 5.3.1 Cleanup After a Voided Governance-Log Branch

If a governance log fork resolves (Core Protocol Spec §2.7.1) such that a rotation some nodes had already re-wrapped against turns out not to be canonical, the fix is a natural extension of ordinary re-wrapping, not a new mechanism: any node encountering a `DekWrapping` whose `rotation_ref` doesn't match a currently-canonical governance log entry simply treats it as stale and produces a fresh wrapping against whatever rotation actually is canonical post-reconciliation — the same opportunistic process described above, triggered by an additional condition (stale `rotation_ref`) alongside "no wrapping exists yet." Members who held the now-voided rotation's epoch key retain what they need to perform this cleanup, since reconciliation voids the *governance log entries*, not any key material a node had already derived from them.

### 5.4 Membership-Gated Serving, Keyed on `read-content`

**A DEK fixed for an object's lifetime (§1.2) creates a real, specific gap that re-wrapping alone doesn't close: a revoked member who had already obtained an object's DEK before their removal could, in principle, keep decrypting *new* edits to that same object made after their removal — provided they could still obtain the new ciphertext bytes at all.** This matters because, absent an explicit fix, ordinary swarm-serving (§4) has no reason to refuse a request for content bytes based on the requester's status — it's built entirely around efficient distribution once someone already has appropriate keys, not around checking who's asking.

**The fix, corrected from an earlier version of this section: any node serving content bytes for a network must first verify the requester belongs to a group holding `read-content`** (Core Protocol Spec §2.2, an ordinary — not governance-tier — capability, typically granted broadly to `everyone` but network-configurable like any other) — not merely "holds a valid, non-revoked identity," which was too permissive as originally worded. Identity validity alone doesn't distinguish a genuine member from a waiting-room identity under explicit intake (Core Protocol Spec §2.4): a waiting-room node is a valid, non-revoked identity that simply hasn't been admitted into any group yet, and gating serving on identity validity alone would have honest nodes handing it ciphertext, metadata, and bandwidth — falling short of the "essentially nothing" posture explicit intake is supposed to guarantee. Gating on `read-content` specifically closes this: a waiting-room node holds no group membership at all, hence no `read-content`, hence is correctly refused service, consistent with §2.4's intent.

**This is enforced against each node's own current view of governance state, and convergence — not instantaneity — is the honest guarantee.** A node whose governance-log replay hasn't yet caught up to a recent revocation will, for a brief propagation window, still serve a since-revoked identity, simply because that node doesn't yet know about the revocation. "No honest node will ever serve a revoked member" is not achievable in a gossip-propagated system without unrealistic synchrony assumptions; "every honest node converges to refusing service once it processes the revocation" is what's actually delivered, and is the correct, honest framing — consistent with how this project has already corrected similar overstatements elsewhere (Core Protocol Spec §3.1).

This requirement applies to the same swarm-serving nodes already described in §4 — it's an addition to server behavior, not a new subsystem — and should be understood as a necessary companion to §4's server-selection logic, not an optional hardening step.

### 5.5 Corrected Guarantee Summary

Restating the honest, achievable guarantee this section delivers, consistent with Core Protocol Spec §3.1: a revoked member cannot obtain any object's DEK wrapped for the first time after their removal (§5.1–5.3), and — once honest nodes' governance-log replay converges on the revocation — cannot obtain new ciphertext bytes for content published or edited after their removal (§5.4). They retain, unavoidably, the ability to decrypt whatever they had already fetched and could already decrypt before removal. No symmetric-key scheme can retroactively erase already-known access, and this document does not claim otherwise.

---

## 6. Summary: What Other Specs Should Assume From This Document

- Anything published that needs a stable, updatable address uses a **mutable pointer** (§2), not a raw CID directly. Every publish, including updates, declares a `content_type` and must pass two independent gates (Core Protocol Spec §2.8): the type must be on the network's allowlist, and the publisher must hold `publish:<content_type>` — consuming specs must not assume a network accepts arbitrary content types or that allowlisted types are publishable by everyone. Stale (lower-version) pointer records are rejected, and **two records colliding on the *same* version are resolved by lower-record-hash-wins** — the identical deterministic tie-break used for sibling governance log entries (Core Protocol Spec §2.7.1) — with the loser rejected and retryable at an incremented version (§2.2). That rule settles *which record is canonical* only; **it supplies no content-merge semantics**, which stay deferred to the application layer (§7).
- Content is chunked using content-defined chunking (network-configurable target size, default 16–64KB) **before** encryption, then each chunk is encrypted **deterministically under the object's own DEK** and hashed independently (§1.2–1.3) — this ordering, plus the determinism requirement, is what makes delta-fetching of edited content actually work; consuming specs should chunk-then-encrypt (never the reverse) and must not use randomized-nonce encryption for chunk content.
- **Deduplication is scoped per-object (across an object's own version history), not global across unrelated publishes** — a deliberate tradeoff for making rotation cheap and closing a real security gap, not an oversight (§1.1–1.2).
- Every object's DEK is committed to (`dek_commitment`) inside its owner-signed mutable pointer, but its actual current **wrapping is a separate, freely-republishable attachment** (`DekWrapping`, §2.2) — this split is what makes it safe for *any* current member, not just the owner, to re-wrap on rotation, and is the mechanism the whole revocation guarantee (Core Protocol Spec §3.1) depends on.
- Replication factor is a single network-wide policy value, degrading gracefully (not failing) when the network is too small to meet it (§3.1–3.2). Placement uses Rendezvous Hashing (HRW) — deterministic, coordination-free, and weighted **solely by gossiped `storage_offered`** (§3.3): local-only `reliability_signal` is explicitly *not* an input, because placement must recompute identically on every node and that signal is private per observer by deliberate design (Core Protocol Spec §4.6). Unreliable nodes are corrected for by the repair loop (§3.4) instead. Durability beyond the minimum N comes from volunteer over-replication by high-capacity nodes, not geo/ASN-based diversity heuristics (§3.3.1).
- Actual content delivery to requesters uses **swarm-based serving** (§4): any node that has fetched a CID for any reason becomes an eligible server for it, selected by distance/throughput/load, self-limited by each node's own `bandwidth_cap` — this is what prevents a popular publish from bottlenecking or overloading its original publisher. Multi-chunk objects are fetched with rarest-first prioritization from multiple simultaneous sources (§4.4), following the established BitTorrent/Bitswap pattern; fetch concurrency is a local per-node setting, not network policy. **Serving nodes must verify a requester holds `read-content` before serving content bytes (§5.4)** — not merely a valid identity, since a pre-admission waiting-room identity is valid without holding any capability; this closes a gap that would otherwise let a revoked member keep decrypting new edits to an object whose DEK they'd previously cached, once honest nodes' governance-log replay converges.
- **Multi-writer collections use the Distributed Append-Set primitive (§2.5)**, built on the DHT's existing provider-record mechanism, not ad hoc "append to a shared key" — Search's posting index is a direct, unmodified instance of this primitive. App Hosting's name registry, by contrast, needed the append-set layered *on top of* governance-log anchoring for authoritative ordering and durability (App Hosting Spec §4.3) — a distinction this document's second review pass surfaced: not every multi-writer collection has the same durability/ordering needs, and consuming specs should evaluate which properties they actually need rather than assuming the base primitive alone always suffices. Entries must be validated (signature, current membership, and — where applicable — the referenced pointer's non-delisted status, resolved by replaying the governance log for the most recent `ModerationEntry` targeting it, Core Protocol Spec §2.7) by any node relying on them, or moderation of malicious entries has no teeth.
- **Epoch rotation is cheap**: only each live object's small DEK wrapping is re-wrapped on rotation, never content itself (§5.2) — any current member can perform this, not just an object's owner, eliminating the owner-offline blackout window and the proxy re-encryption mechanism this document previously specified (§5.3, now removed as unnecessary). The resulting guarantee is stated honestly (§5.5): future access is blocked, already-known access is not retroactively erased — consistent with Core Protocol Spec §3.1's corrected framing.
- The App Hosting spec should treat a published app's "current version" as a mutable pointer to an immutable, chunked, content-addressed bundle, delivered via swarm-based serving — this document's primitives should be sufficient without extension for that use case.

---

## 7. Explicitly Open Questions

None remaining at the architectural level — every item originally flagged in this document (chunking scheme, replica placement anti-correlation, multi-source fetch protocol) has been resolved in the sections above, and subsequent review passes identified and resolved further gaps: deterministic chunk encryption, honest revocation framing via envelope encryption, the Distributed Append-Set primitive for multi-writer collections, the DEK commitment/wrapping split (resolving a real signature contradiction the first rework introduced), governance-log-referenced (not bare-counter) rotation tracking, the `read-content`-gated serving requirement, the removal of local-only `reliability_signal` from HRW placement (§3.3 — it made a deliberately deterministic function depend on state no two nodes share), the concrete `ModerationEntry` record behind append-set check (c) (§2.5, Core Protocol Spec §2.7), and the same-version pointer collision tie-break (§2.2). This document's interfaces should be treated as stable for the remaining specs and for implementation planning.

Remaining application-specific questions about mutable content (ownership transfer, edit history/versioning UX beyond the raw version counter, and **the merge semantics of concurrent edits** — i.e. what two competing edits mean *together*, as distinct from which record wins, which §2.2 now settles deterministically) remain deliberately deferred to whichever future application-layer spec first needs them — the mutable pointer primitive above is designed to support those decisions later without requiring changes to this document.
