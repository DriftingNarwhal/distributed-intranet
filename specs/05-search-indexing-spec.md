# Search & Indexing Specification

**Project:** Distributed Intranet
**Document status:** v1.0 — stable. A reference implementation exists (see the repository root); where the two differ, this document is normative and the divergence is recorded in the implementation.
**Depends on:** Core Protocol Spec (identity, capability ledger, governance policy, content-type policy), Storage & Replication Spec (mutable pointers, content addressing, Distributed Append-Sets)
**Consumed by:** any future application-layer specs built on this platform

---

## 0. Purpose and Scope

This document specifies how content published to a network becomes discoverable through search, without relying on crawlers. It covers:

1. **Why no crawlers** — the founding requirement this whole document exists to satisfy.
2. **What gets indexed** — default metadata for all content, plus an opt-in mechanism for richer, structured content.
3. **Index structure and distribution** — a DHT-based distributed inverted index, reusing infrastructure already established in the Core Protocol Spec.
4. **Indexing as a publishing side effect** — indexing happens automatically as part of publishing, never as a separate crawl step.
5. **Query resolution** — how a search actually gets answered across a distributed index.
6. **Integrity** — preventing index spam/poisoning, using mechanisms already established elsewhere in this design.

Out of scope: any specific search UI, and cross-network search — this document is intentionally, permanently scoped to search within a single network.

---

## 1. Why No Crawlers

This platform's founding motivation for a dedicated search layer, stated plainly: if this platform succeeds at what it's meant to do, it produces a large number of independent, small "internets" (Core Protocol Spec §0 — a network per app-purpose, per community, per group). Without a native way to discover content within a network, the predictable failure mode is that someone builds a crawler to compensate — reintroducing exactly the bot traffic problem this project exists partly to avoid. The design principle that follows: **discoverability must be a built-in property of publishing, not something bolted on afterward by an external agent polling the network.**

**Cross-network search is never possible, by design, not by current limitation.** Every network is independently keyed, independently membered, and (per Core Protocol Spec §1.2) deliberately unlinkable from any other network a node participates in. A search layer that reached across networks would require either a common index spanning multiple independent trust boundaries (undermining network isolation) or a node correlating its own memberships across networks (undermining identity unlinkability). Search is therefore scoped to one network, permanently, as a direct consequence of decisions already locked into the Core Protocol Spec — not a limitation to revisit later.

---

## 2. What Gets Indexed

### 2.1 Default Metadata Indexing — All Content Types

Every publish, regardless of `content_type` (Core Protocol Spec §2.8), carries minimal descriptive metadata that is indexed automatically: at minimum, a `title` and `description`-equivalent field. This applies uniformly — an app-bundle's manifest `name`/`description` (App Hosting Spec §2.1), a piece of `text` content, an `image`, whatever a network's content-type allowlist permits — all carry some minimal describable identity, and all get indexed by default with no publisher action beyond the ordinary act of publishing.

### 2.2 Opt-In Rich Content Indexing — Structured Fields

Beyond default metadata, a publisher can expose richer, structured content for indexing by including an **index document** alongside their publish:

```
IndexDocument {
  pointer_id:  the mutable pointer (Storage Spec §2) this index document describes
  title:       searchable title (may restate or extend the default metadata title)
  tags:        list of searchable keyword tags
  body_text:   searchable plaintext body — the publisher explicitly extracts and provides this;
               it is not automatically derived from arbitrary bundle contents
  signature:   publisher's signature over the above
}
```

**Structured, not free-form**, per your direction — a publisher explicitly maps whatever content they want searchable into `title`/`tags`/`body_text`, rather than handing over an arbitrary blob for the platform to interpret. This has a real, deliberate benefit beyond consistency: it gives publishers precise control over what becomes searchable, so a wiki-style app can expose a page's rendered text for search while withholding page metadata it doesn't want indexed (e.g. an editor's private notes stored alongside a page but never mapped into `body_text`) — indexing is opt-in and explicit at the field level, not an automatic scrape of everything the content contains.

**This mechanism is content-type-agnostic, not app-specific.** Any published content — a wiki page (`content_type: text`), an app-bundle's own listing, anything else a network's allowlist permits — uses the identical `IndexDocument` structure to expose rich search fields. This directly resolves the earlier "app-bundle" terminology question: the app-bundle (the wiki *program*) and the individual pages it manages (separate `text`-typed content the app publishes) are indexed independently, each via its own `IndexDocument` if they opt in, exactly the way they're stored and versioned independently per the Storage Spec's mutable pointer model.

### 2.3 Content-Type Policy Still Applies

Indexing never bypasses a network's publishing rules — only content that was actually permitted to publish in the first place (both the content-type allowlist and the `publish:<content_type>` capability check, Core Protocol Spec §2.8) can be indexed. A network that excludes `app-bundle` from its allowlist has no app-bundles to index, by the same enforcement already specified there; this document adds no new bypass path.

---

## 3. Index Structure and Distribution

### 3.1 Distributed Inverted Index — Built on the Distributed Append-Set Primitive

Rather than any centralized or per-node-only index, search postings are stored using the **Distributed Append-Set primitive (Storage Spec §2.5)**, itself built on the same Kademlia DHT already established for peer/content routing (Core Protocol Spec §5.1) — reusing infrastructure rather than standing up a parallel distributed data store.

**This corrects an earlier version of this section, which described postings as being "appended to whatever exists under a term's DHT key" — not a native Kademlia operation, and a real underspecification.** Multi-writer append to a single DHT value is a known hard problem (concurrent-write conflicts, unbounded value growth, no clean way to reconcile independent writers) — exactly the gap the Distributed Append-Set primitive exists to close, and search postings are one of its two motivating use cases (the other being App Hosting's name registry, App Hosting Spec §4.3 — though note that registry now anchors authoritative ordering in the governance log, since search postings and name ownership turned out to need genuinely different durability/ordering properties; postings are a correct, unmodified fit for the append-set as originally specified). Concretely: for each searchable term extracted from a publish's default metadata (§2.1) or opt-in `IndexDocument` (§2.2) — tokenized and normalized (lowercased, basic stemming; exact tokenization rules are implementation detail, not architecture) — a posting is published as an `AppendSetEntry` (Storage Spec §2.5) with `collection_id = hash(network_id + term)` and `payload = {pointer_id, term_frequency, field_matched, timestamp}`. A query for a term becomes enumerating that collection's current providers — any node can independently locate the same postings for the same term, with no central index server, and without the multi-writer conflicts the earlier "append to one value" framing would have created.

**Implementation efficiency note, not an architectural requirement:** a naive implementation might create one fully DEK-wrapped, TTL-refreshed posting object per (publish, term) pair — expensive for content matching many terms, since each term's posting would carry its own full object overhead. A better approach, worth stating explicitly so an implementer doesn't build the expensive version by default: **one posting object per publish, announced under every one of its matched terms' `collection_id`s** — the object itself (and its DEK/wrapping) is created once, and only the lightweight provider-record announcement is repeated per term. This is an implementation detail, not something this document needs to mandate, but it's cheap to state now and expensive to discover later.

**Encryption and rotation cost:** posting objects carry a `dek_commitment` and are subject to the same commitment/wrapping split as any other object in this system (Storage Spec §2.2, §2.5, §5.3) — not a special case requiring its own encryption handling, and specifically not dependent on the original publisher's continued liveness to survive a rotation, since any current member can produce a fresh wrapping the same way they would for any other content. This means postings automatically inherit the same cheap-rotation property as everything else (Storage Spec §5.2): a revocation event never requires re-encrypting or rebuilding the search index, only re-wrapping the small number of DEKs involved.

**Validation is mandatory for any node relying on posting data, not optional.** Per Storage Spec §2.5's general requirement for append-set entries: a node must verify a posting's signature is valid, that the signing identity is a *current* network member (checked against replayed governance state, Core Protocol Spec §2.7), **and that the pointer the posting references hasn't itself been delisted** — all three, not just the first two. The third check has a concrete record behind it, previously referenced here as an undefined state: a pointer is currently delisted if the most recent `ModerationEntry` targeting its `pointer_id` in the canonical governance log has `action: "delist"` (Core Protocol Spec §2.7); a pointer with no such entry, or whose most recent one is a `relist`, is not delisted. This is the *same* replayed-governance-state query already performed for the membership check — one replay answers both, not two separate lookups against two separate stores. Without the full set, a malicious or already-revoked member could keep announcing postings indefinitely regardless of moderation action (closed by the first two checks), or a still-*current* member could keep an index entry alive pointing at content that's already been moderated away (closed only by the third) — this closes both gaps, and is what makes §6.2's moderation-based remedy actually, fully effective rather than partially cosmetic.

**Hotspot/storage-conscription concern, addressed at the primitive level, not specific to search.** Popular search terms naturally accumulate many postings, which might seem to conscript whichever nodes are closest to that term's DHT key into unbounded storage duty — but per Storage Spec §2.5, this is ordinary DHT provider-record participation (lightweight, baseline overhead every routing-participating node already handles), not the opt-in, `storage_offered`-gated full-replica storage that §3's replication mechanism uses. This distinction is what keeps popular-term storage from contradicting the project's opt-in-contribution principle. Note also, per Storage Spec §2.5's honest caveat: enumeration of a very popular term's postings is best-effort, not guaranteed-complete — acceptable for search specifically (a slightly incomplete result set is a normal, tolerable property of search, unlike the name-registry case where incompleteness would mean a wrong answer, not just a partial one).

### 3.2 Posting Freshness and Expiry

Postings are subject to periodic re-announcement rather than being permanent, gossiped forever — the same TTL-and-refresh pattern already used elsewhere in this design for capability ledger entries (Core Protocol Spec §4.5), peer address propagation, and Distributed Append-Set entries generally (Storage Spec §2.5). A publisher's node re-announces its content's postings periodically while the content remains live; postings that aren't refreshed within a defined window are treated as stale and dropped, so removed or delisted content (§6.2) naturally falls out of the index without requiring an explicit deletion protocol for every case.

### 3.3 Re-Indexing on Update

Since any content update advances its mutable pointer's version counter (Storage Spec §2.2), a re-publish is the natural, existing trigger for re-indexing: a publisher whose content changes re-derives and re-announces its postings (§3.1) as part of the same publish action — no separate "please re-index me" step. This is consistent with the broader principle from §4 below: indexing is a side effect of publishing, never a separate action a publisher has to remember to perform.

---

## 4. Indexing as a Publishing Side Effect

**Decided, and foundational to this whole document:** indexing is not an action a publisher performs separately from publishing — it is bundled into the publish operation itself (Storage Spec §2's mutable pointer publish flow), automatically, every time. A publish that includes default metadata (§2.1, always present) or an `IndexDocument` (§2.2, if the publisher chose to include one) automatically produces and announces the corresponding DHT postings (§3.1) as part of that same publish action. There is no separate indexing pipeline, no delay between "content is live" and "content is searchable," and critically, **no external agent ever needs to visit content after the fact to make it discoverable** — which is the direct structural answer to the no-crawlers requirement from §1.

---

## 5. Query Resolution

A search query is tokenized the same way publishing-side terms are (§3.1), and each term is looked up via its DHT key. A querying node:

1. Looks up postings for each query term via the DHT.
2. Merges and ranks results across matched terms — a reasonable starting approach is a standard TF-IDF-style relevance score, computed locally by the querying node from the postings' `term_frequency` data; exact ranking algorithm is implementation-level tuning, not an architectural decision this document needs to pin down.
3. Resolves ranked `pointer_id`s to their current content the same way any other content resolution works (Storage Spec §2.2) — search results are just an ordered list of pointer references, nothing new needed at this step.

No query ever crosses a network boundary (§1), and no query requires contacting a central search service — the DHT lookups are peer-to-peer, consistent with every other lookup this platform performs.

---

## 6. Integrity

### 6.1 Self-Attested Postings, Now With Mandatory Verification

Index postings are signed by the publishing identity, the same as any other publish in this system (Storage Spec §2.2), and — per the correction in §3.1 — any node relying on posting data must verify **three things**, not two: the signature, that the signer is a *current* network member, and that the pointer being indexed hasn't itself been delisted. This is what actually gives search its permissioned-network trust model teeth: postings only count if they come from identities that are demonstrably current members pointing at content that's still legitimately live — a revoked member's old postings fail the second check automatically the moment their membership ends, and a moderated pointer's postings fail the third check regardless of whether its publisher is still a current member, closing both gaps rather than only one.

**This does not eliminate spam/keyword-stuffing as a possibility** — a current, legitimate member could still self-attest misleading tags or padded body text to inflate their own content's search ranking, the same "SEO spam" problem that exists on the ordinary web. That risk is accepted here for the same reason it's accepted elsewhere: this is a permissioned network of known, identity-gated members, not an open, anonymous web — and the moderation mechanism below provides a real, existing remedy for it, backed now by a fully closed enforcement point rather than an assumption that publishers would simply stop re-announcing on their own.

### 6.2 Moderation of Bad-Faith Index Entries

No new capability and no new record type is needed for this: `moderate-content` (Core Protocol Spec §2.2) already covers removing published content within network policy, and an `IndexDocument` is itself published content — a moderator delists a bad-faith or spammy index document by appending a `ModerationEntry` (Core Protocol Spec §2.7) targeting its `pointer_id`, exactly as they would for any other malicious publish (App Hosting Spec §3.4). Because that entry lives in the governance log rather than in the append-set, a delisting is durable and cannot be outlasted: it doesn't depend on anyone continuing to re-announce it, and the spammer cannot restore their posting's standing by simply continuing to refresh it, since honest nodes re-derive delisting state from replay on every validation. **Combined with §6.1's mandatory three-part validation (signature, current membership, and referenced-pointer moderation state), this now fully closes a gap two successive review passes identified in stages:** the first pass found that nothing required a storage/routing node to check a posting's legitimacy at all (fixed by adding signature + membership checks); a second pass found that even with those two checks, a still-*current* member could keep an index entry alive for content that had already been delisted, since moderation state of the *referenced* content was never part of the check (fixed by adding the third check above). With all three enforced, delisting (for content whose publisher remains a current member) and membership revocation (for a departed publisher) both now have real, fully enforced effect, regardless of the malicious party's cooperation.

---

## 7. Summary: What Other Specs Should Assume From This Document

- Every publish, of any content type, gets default metadata indexing automatically (§2.1) — no publisher action required beyond the publish itself.
- Any publisher can optionally attach a structured `IndexDocument` (title/tags/body_text) to expose richer search content (§2.2) — this mechanism is content-type-agnostic and works identically for an app-bundle's own listing and for content that app manages (e.g. a wiki page).
- Search is a distributed inverted index built on the Distributed Append-Set primitive (Storage Spec §2.5), itself living on the same per-network DHT already established in the Core Protocol Spec — no new distributed data store, no crawler, no central index service, and no multi-writer-append problem, since the primitive is designed specifically to avoid that.
- Indexing is bundled into the publish action itself (§4) — this is the direct structural answer to the platform's no-crawlers requirement.
- Search is permanently scoped to a single network (§1) — a direct, unavoidable consequence of this platform's per-network identity unlinkability and membership isolation, not a current limitation.
- **Posting validation is mandatory**, not optional (§3.1, §6.1): any node relying on postings must verify **all three** of signature, current membership, and the referenced pointer's non-delisted status before trusting an entry. The third is resolved concretely by the most recent `ModerationEntry` for that `pointer_id` in the governance log (Core Protocol Spec §2.7) — the same replay that answers the membership check, not a separate lookup. This is what makes moderation (§6.2) actually effective rather than depending on a malicious publisher's cooperation.

---

## 8. Explicitly Open Questions

1. Exact tokenization/normalization rules (stemming, stop-words, language handling) — implementation-level tuning, not architectural.
2. ~~Exact posting-freshness TTL and re-announcement cadence (§3.2).~~ **Resolved for v1.0: a 24-hour TTL, with re-announcement well inside it.** The value stays tuning rather than architecture, but it needed a concrete default and now has one. The constraint behind it is worth stating, because it is the same one the capability ledger has (Core Protocol Spec §4.5): re-announcement cadence must sit comfortably inside the TTL, or entries expire between refreshes and content silently drops out of the index while its publisher is still online and serving it. A long TTL costs only the staleness of a discovery index, which §3.2 already accepts; a cadence too close to the TTL costs availability, which it does not.
3. Precise relevance-ranking algorithm (§5) — TF-IDF-style scoring is a reasonable default assumption, but the exact formula is an implementation task.
