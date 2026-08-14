# App Hosting Specification

**Project:** Distributed Intranet
**Document status:** v1.0 — stable. A reference implementation exists (see the repository root); where the two differ, this document is normative and the divergence is recorded in the implementation.
**Depends on:** Core Protocol Spec (identity, capability ledger, governance policy, governance log), Storage & Replication Spec (mutable pointers, swarm-based serving, Distributed Append-Sets)
**Consumed by:** any future application-layer specs built on this platform

---

## 0. Purpose and Scope

**This document is optional, opt-in infrastructure — not a layer every network or every client needs.** As established in the Core Protocol Spec's "How Applications Are Expected to Be Built On This Platform," most applications built on this platform are expected to be conventionally-distributed native clients (installed from GitHub, an app store, etc.) that use the Core Protocol and Storage Spec directly as a networking/data backend, without ever touching what's specified here. This document applies specifically to networks that want to support **in-network published, dynamically-updatable, sandboxed applications** — rendered by a generic, protocol-aware client rather than a purpose-built native one — a deliberate choice a network opts into by including `app-bundle` on its content-type allowlist (Core Protocol Spec §2.8), not a requirement imposed on every network.

This document specifies how a user publishes a browser-style application to a network, how other members discover and run it, and how it's kept safe to run despite coming from another, possibly untrusted, network member. It covers:

1. **Execution model** — what an "app" is and how it runs, entirely on the visitor's own machine.
2. **Publishing format** — the manifest and bundle structure, including a forward-looking capability-declaration system.
3. **Security model** — sandboxing and hardening against XSS and related browser-class attacks, since bad actors on a network are an expected condition, not an edge case.
4. **Discovery & resolution** — how a human-shared "check this out" turns into running code, on top of the Storage spec's mutable pointers and swarm-serving.

Out of scope: the actual content or purpose of any specific app — this document defines the platform apps run on, not any application built with it.

---

## 1. Execution Model

### 1.1 Confirmed Model: Runs on the Visitor's Machine

An app published to a network is **not executed by the publisher's node on behalf of visitors**, and the network does **not** schedule it onto arbitrary donated compute. When a visitor accesses a published app, the app's code and assets are fetched (via swarm-based serving, Storage Spec §4) to the *visitor's own node* and executed there, in a sandbox, using the visitor's own resources. This is the core design decision that keeps this tractable: it's a distribution problem (already solved by the Storage spec), not a scheduling/trust-in-strangers'-code problem.

### 1.2 v1 Sandbox: Browser-Style Webview

For v1, apps are HTML/CSS/JS bundles executed in an embedded webview — the same trust model as a browser tab. This directly matches the general "dynamic web page / hosted app" model this platform is meant to support, and it means the security properties of this system can build on decades of hardened browser sandboxing practice rather than inventing a new execution safety model from scratch.

### 1.3 Forward-Looking, Not Yet Built: Richer Runtimes

The manifest format (§2) is designed so that a future version could support additional execution targets (e.g. a general WASM/WASI runtime for apps needing more than a webview provides) without changing how apps are addressed, discovered, or fetched. This is purely a capability-declaration and platform-extension concern — nothing in v1 requires building this, but nothing in v1 should preclude it either.

---

## 2. Publishing Format

### 2.1 Bundle Structure

An app is a **manifest + asset bundle**, stored and versioned exactly like any other content in the Storage spec:

```
AppManifest {
  app_id:            stable identifier — this IS the pointer_id of a mutable pointer (Storage Spec §2)
  name, description: human-readable metadata
  version:           matches the mutable pointer's version counter
  entry_point:        path to the root HTML file within the bundle
  requested_capabilities: [ ... ]   (see 2.2)
  publisher_identity: per-network identity (Core Protocol Spec §1.2) of the publisher
  signature:          publisher's signature over the manifest
}
```

The manifest itself, plus all referenced assets, are chunked/content-addressed per Storage Spec §1, and the manifest is always fetched via the app's mutable pointer (Storage Spec §2) so that publishing a new version is exactly "publish new content, update the pointer" — no new versioning mechanism needed. The underlying mutable pointer's `content_type` (Storage Spec §2.2) is set to `app-bundle` — one content type among the others a network may allow (Core Protocol Spec §2.8), not a privileged or automatically-permitted one, and publishing one is gated by the same two-check mechanism as any other content type (Storage Spec §2.2, Core Protocol Spec §2.8): **the network's allowlist must include `app-bundle`, and the publishing identity must separately hold `publish:app-bundle`.** These are independent gates — a network can permit `app-bundle` on its allowlist while restricting who may actually publish one to a small maintainers group, which is expected to be the common case: most networks built around a single app (a wiki, a shared library, a chat client) will grant `publish:app-bundle` only to that app's developers, not to `everyone`, so ordinary members participate in the app without ever holding — or needing to know about — the ability to publish new versions of it. A network deliberately built as an open sandbox for app publishing, by contrast, could grant `publish:app-bundle` broadly. **A network whose allowlist doesn't include `app-bundle` at all cannot host apps under any configuration** — this is the mechanism that lets a network operator scope their network away from app hosting entirely (e.g. a chat-style use case restricted to text/image/video), without needing any App-Hosting-specific configuration beyond the general content-type policy already defined in the Core Protocol Spec.

### 2.2 Capability Declarations

Per your direction to build in richer capability from the start even though v1 only *grants* a subset, the manifest declares what the app is asking permission to do. This is a permission-request system, conceptually similar to mobile app permissions or browser permission prompts — declared now, enforced incrementally:

| Capability | v1 status | Description |
|---|---|---|
| `network-storage-read` / `network-storage-write` | **Supported in v1** | Per-user persistent storage for this app, scoped and isolated per (app_id, visiting user) — backed by the Storage spec's primitives, not raw browser storage. |
| `network-call` | **Declared, not yet enforced in v1** | Ability to reach other published apps/services within the same network. Placeholder for later inter-app communication. |
| `realtime-media` | **Declared, not yet enforced in v1** | Hook into the voice/video/streaming transport (Real-Time Transport spec) — the extension point a future communications-style app would consume. |

Any capability not explicitly granted is denied by default (fail-closed, consistent with project-wide principle). A visitor's node presents requested capabilities to the user before first run, similar to a browser permission prompt or an app store install screen, and the grant decision is stored locally per (app_id, user) so it isn't re-asked every visit.

### 2.3 Ownership and Updates

`publisher_identity` plays the role of `owner_identity` from the Storage spec's mutable pointer (§2.3 of that document) — by default a single identity, with the same door left open for that to later become capability-based (e.g. a team publishing an app together) without changing this document.

---

## 3. Security Model

### 3.1 Why This Matters Now, Not Later

Agreed with your framing: a network's membership policy (Core Protocol Spec §2) controls *who* can join, not whether every member is well-intentioned forever — a bad actor gaining membership (compromised account, or simply someone who turns out to be malicious) is an expected eventual condition for any sufficiently long-lived or large network, not a hypothetical. Since app execution is the one place in this whole system where another member's *code* runs on your machine, it's the highest-leverage place to get containment right, and containment is much cheaper to design in now than retrofit later.

### 3.2 Sandbox Isolation

The v1 webview sandbox must provide, at minimum, the same isolation guarantees a modern browser tab provides against a malicious website:

- **Origin isolation per app:** each `app_id` runs in an isolated context (no shared DOM, no shared JS globals, no shared cookies/storage) equivalent to distinct origins in a browser — one app cannot read or manipulate another app's execution context.
- **No ambient access to the host system:** no filesystem access, no arbitrary process spawning, no access to other running apps' data, by default — access to anything outside the sandbox is only ever granted through an explicit capability from §2.2, never ambient.
- **Content Security Policy enforced by the platform, not the app:** the visitor's node — not the app bundle — sets and enforces CSP headers/equivalent for every app it runs, preventing inline script injection and restricting script/asset sources to the app's own declared bundle. An app cannot weaken its own sandboxing by declaring a permissive policy for itself.
- **Standard web hardening applied uniformly:** input sanitization boundaries, output encoding at render time, and the general set of XSS/injection defenses that a modern browser engine already provides for arbitrary web content — this system should inherit that protection by virtue of building on an actual embedded browser engine rather than a custom-built HTML renderer, which is itself a strong reason to keep v1 scoped to "webview," not a bespoke rendering pipeline.

### 3.3 Network-Layer Containment

Beyond the in-sandbox protections above, the app's *ability to affect the network itself* is separately constrained:

- The `network-storage-write` and `network-call` capabilities (§2.2), when eventually enforced, are the **only** channels an app has to affect anything outside its own local sandbox — and both are subject to the same governance/capability system as everything else in this project (Core Protocol Spec §2), meaning a network's moderators can revoke an app's ability to write or call out, independent of removing the publisher from the network entirely.
- A malicious app cannot use its execution context to forge messages as the visiting user, impersonate other identities, or bypass the epoch-key encryption model — because the sandbox has no access to the visiting user's master identity or per-network keys (Core Protocol Spec §1) at all; any signed action on the user's behalf must go through a platform-level permission prompt, never be directly executable by app code.

### 3.4 Moderation and Takedown of Malicious Apps

Since `moderate-content` is already a defined capability (Core Protocol Spec §2.2), it directly covers apps: a network's moderators can delist a malicious app's mutable pointer, which stops it from being surfaced through discovery (§4) — this doesn't retroactively un-run code that already executed on someone's machine (nothing can), but it does stop further spread through the network's normal discovery paths, and combined with §3.2's containment, limits blast radius of what already ran.

**The concrete mechanism is a `ModerationEntry` in the network's governance log (Core Protocol Spec §2.7)** — `{action: "delist" | "relist", target_pointer_id, moderator_identity, signature}`, valid only if the moderator belonged to a group holding `moderate-content` at that point in the chain. This document previously referred to delisting as though it were a defined state without any record type behind it; it is now the same replay-for-current-state question as every other governance fact: an app is currently delisted if the most recent `ModerationEntry` targeting its `pointer_id` says so, and is not delisted if no such entry exists. Two consequences worth naming, both of which fall out of using the governance log rather than a separate store:

- **Delisting is durable and can't be waited out.** Unlike an append-set entry, it doesn't lapse when nobody re-announces it — the same property that made governance-log anchoring necessary for name ownership (§4.3) applies equally to takedown.
- **Delisting propagates to the discovery index automatically**, without a separate takedown step there: a node relying on an app-registry `AppendSetEntry` must already verify that the pointer it references isn't delisted (Storage Spec §2.5, check (c)), so a delisted app's directory entry stops being honored as soon as each node's governance replay reaches the entry — converging, not instantaneous, consistent with how every other governance-derived check in this design behaves.

Delisting affects whether the *app* is servable and surfaced; it does not alter who is recorded as the owner of any name pointing at it (§4.3) — those stay separate concerns, and a `relist` restores the app without any re-registration.

### 3.5 Publishing Policy: Open vs. Reviewed — Resolved

Whether an app must be reviewed before it's servable is a **network-wide policy setting**, mirroring the same pattern already used for invite admission mode (Core Protocol Spec §2.4) — not a per-app or per-publisher choice.

- **`open` (default):** an app publish is immediately live and discoverable through the name registry (§4.3–4.4) as soon as it's stored. Safety relies entirely on the reactive mechanisms already specified: sandbox containment (§3.2–3.3) limits what any single run of malicious code can do, and moderation (§3.4) can delist it afterward.
- **`reviewed`:** a publish is stored exactly as normal (nothing about chunking, replication, or the underlying storage mechanics changes), but the app enters a pending state — visible to reviewers along with its manifest and publisher identity, similar in spirit to the invite waiting-room (Core Protocol Spec §2.4) — and is **not resolvable through the name registry, and not fetchable/executable by an ordinary visitor's node**, until a holder of the new `approve-app-publish` capability (Core Protocol Spec §2.2) admits it. This is deliberately a distinct capability from `moderate-content`: one governs admitting new content, the other governs taking down content already live — consistent with keeping "let something in" and "kick something out" as separate, independently grantable actions throughout this design.

**Review applies per-version, not only to an app's first publish.** Gating only the initial publish would leave a known gap: a publisher could get an innocuous first version approved, then push a malicious update that bypasses review entirely. Under `reviewed` policy, every new manifest version (tied to the underlying mutable pointer's version counter, Storage Spec §2.2) requires its own approval before it becomes servable. This adds real friction for publishers pushing frequent legitimate updates, but it closes an otherwise-obvious bypass, and is the right tradeoff given this project's general fail-closed bias.

---

## 4. Discovery & Resolution

### 4.1 The Flow You Described

Restating your example to confirm the design matches it: Person A publishes an app. Person B hears about it and fetches/runs it — at that point Person B's node holds a full local copy and is automatically part of that content's swarm (Storage Spec §4.2). Person C now discovers it, and the network — not any fixed publisher — decides who serves Person C's copy, based on hop count, latency, throughput, and load (Storage Spec §4.3). This is exactly the swarm-serving mechanism already specified; App Hosting doesn't need its own delivery mechanism, only its own **naming/discovery** layer on top of it.

### 4.2 What "Discovery" Actually Needs to Solve

Two distinct sub-problems, worth naming separately:

- **Addressing:** turning a human-shareable reference into the app's `app_id` (mutable pointer ID) — this is what lets "check out this app" be a stable, shareable thing even as the app updates over time.
- **Browsability:** letting members find apps they *don't* already have a link to — a directory/catalog experience within a network (closer to "here's what's published on this network" than "here's a link someone sent me").

### 4.3 Addressing: Human-Friendly Names — Corrected Again: Governance-Log Anchored, Append-Set for Discovery Only

A raw `pointer_id` (likely a hash-derived identifier) is not human-shareable. This needs a **name registry**, scoped per network, mapping a chosen human-readable name (e.g. `game-night-tracker`) to a `pointer_id`.

**A second review pass identified that the Distributed Append-Set alone (the previous fix) isn't sufficient for names specifically, even though it's exactly right for search postings (Search Spec §3.1).** Two of the append-set's own properties, both correct and desirable for a discovery index, are actively wrong for something that needs to answer "who authoritatively owns this name":

- **Append-sets have no trustworthy internal ordering.** "First-valid-entry wins by timestamp" (the earlier fix) relies on a timestamp field that's self-attested by whoever submits an entry — nothing stops a squatter from simply backdating their entry to claim priority over a genuinely earlier registration. An append-set is an unordered, additive set by design; it was never going to be able to supply a trustworthy total order on its own.
- **Append-sets use TTL-based liveness, which is the wrong durability model for ownership.** An entry that isn't periodically re-announced expires and falls out of the collection — desirable for search postings (stale results should disappear), actively dangerous for a name registration (a legitimate registrant whose node is simply offline for a while would have their registration silently lapse, at which point a squatter who kept a standing competing entry announced would become the resolved owner by default).

**The fix: the authoritative name → `app_id` mapping lives in the network's governance log (Core Protocol Spec §2.7), not in the append-set.** Since name registration was already a capability-gated action, this is a natural extension rather than a new mechanism: a registration is recorded as a governance log entry, giving it the same properties every other governance action already has — a trustworthy, tamper-evident total order (so "first" is well-defined and can't be backdated), and permanent durability via log replay (so a legitimate registrant's temporary absence can never cause their registration to lapse). **The Distributed Append-Set is still used, but now purely as a best-effort discovery/browsability index** (§4.4) — something that helps a node efficiently find out a name exists without walking the entire governance log, but which is never the authoritative source of truth for who owns it. If the append-set entry for a name happens to be stale or missing, resolution can always fall back to replaying governance log state directly; nothing about ownership depends on the append-set being complete or fresh.

**Two distinct, separately-tier-tagged capabilities, not one — closing a second gap the earlier version left open:**

| Capability | Effect | Tier |
|---|---|---|
| `register-app-name` | Can claim a **currently unclaimed** name in this network's registry | Ordinary |
| `reclaim-app-name` | Can **reassign an already-claimed** name to a new `app_id`, overriding the existing registrant | Governance-tier |

An earlier version of this section let a single `register-app-name` capability also perform reassignment via an unrestricted "supersession" — which, in a network where `register-app-name` is broadly granted (e.g. an open sandbox network, §1.3), would have made name hijacking trivial for anyone holding that broad grant. Splitting reclaim into its own, separately-gated, governance-tier capability (consistent with Core Protocol Spec §2.2's requirement that consuming specs tier-tag anything they define) closes this: claiming a new name stays low-friction and broadly grantable, while reassigning an existing one requires real, deliberately-scoped authority.

- **Resolving a name** means: replay (or query a cached, verified replay of) governance log entries for `register-app-name`/`reclaim-app-name` actions targeting that name, and take the current state that replay produces — the append-set (§4.4) can be used as a fast-path hint for *which names exist*, but the governance log is what's actually trusted for *who currently owns one*.
- **Moderation can still delist a name's current target app** via `moderate-content` (§3.4), recorded as a `ModerationEntry` in the same governance log (Core Protocol Spec §2.7) and independent of registry ownership — delisting affects whether the *app* is servable and surfaced, not who's recorded as the name's owner; those remain separate concerns, resolved by replaying different entry types from the same log.

### 4.4 Browsability: Network App Directory

A network-scoped, browsable list of published apps uses the Distributed Append-Set (Storage Spec §2.5) as a **best-effort discovery index**, not an authoritative source — the distinction that §4.3's correction turns on. Each registration, alongside being recorded in the governance log (the authoritative record, §4.3), also publishes a corresponding `AppendSetEntry` to `collection_id = hash(network_id + "app-registry")`, whose payload carries the name, `app_id`, and manifest metadata like name/description (§2.1). A node reconstructs "everything published on this network" by enumerating this collection — a fast, DHT-native way to browse without walking the full governance log — while understanding that enumeration is best-effort (Storage Spec §2.5: provider-record queries aren't guaranteed complete for very large or popular collections) and that authoritative ownership, if ever in question, is always resolvable by falling back to governance log replay (§4.3), which enumeration completeness has no bearing on.

### 4.5 First-Run Resolution Sequence

Putting it together, a visitor accessing an app for the first time:

1. Resolve human name → `app_id` via the name registry (§4.3), if entering by name; skip if already holding a direct `app_id`/pointer reference.
2. Resolve `app_id`'s mutable pointer → current manifest CID (Storage Spec §2.2).
3. Fetch the manifest via swarm-based serving (Storage Spec §4).
4. Present requested capabilities (§2.2) to the user for consent, if not already granted for this app.
5. Fetch the remaining bundle assets via swarm-based serving.
6. Execute in the sandbox (§3), with only the granted capabilities active.
7. The visitor's node is now itself a swarm member for this app's content, per Storage Spec §4.2, ready to serve the next visitor.

---

## 5. Summary: What Other Specs Should Assume From This Document

- Apps execute entirely on the **visitor's** machine, in a webview-based sandbox equivalent to browser-tab isolation — never scheduled by the network onto donated compute.
- App identity, versioning, and updates reuse the Storage spec's mutable pointer primitive directly — no separate versioning system. An app's underlying `content_type` is `app-bundle`, gated by two independent checks (Core Protocol Spec §2.8): the network's allowlist must include it, and the publisher must separately hold `publish:app-bundle` — expected to typically be restricted to a small maintainers group rather than granted to `everyone`, so most members of an app's network never publish app-bundles themselves. A network whose allowlist excludes `app-bundle` entirely cannot host apps under any configuration, which is the mechanism for scoping a network away from app hosting altogether (e.g. a chat-only network).
- App delivery reuses swarm-based serving directly — no separate distribution system.
- Capabilities requested by an app are fail-closed by default and gated through the same capability/governance system as everything else in this project — there is no app-specific permission model, just this project's general one, applied to apps.
- Human-shareable app names are **governance-log anchored for authoritative ownership** (Core Protocol Spec §2.7), with a Distributed Append-Set (Storage Spec §2.5) layered on top purely as a best-effort discovery index — not the other way around. Claiming an unclaimed name (`register-app-name`, ordinary) and reassigning an already-claimed one (`reclaim-app-name`, governance-tier) are separately-gated capabilities, closing a hijack path an earlier version of this section left open by treating them as one.
- Publishing policy is network-wide: `open` (default, immediately live, purely reactive moderation) or `reviewed` (pending until `approve-app-publish`, re-checked on every new version, not just first publish) — §3.5.
- Malicious apps are contained primarily by sandbox isolation (limits damage from code that already ran) and secondarily by moderation-driven delisting from discovery (limits further spread) — both mechanisms already exist elsewhere in this design and are applied here, not reinvented. Delisting is a **`ModerationEntry` appended to the governance log** (Core Protocol Spec §2.7), gated on `moderate-content` and answered by replay like every other governance fact — durable (it cannot lapse through non-refresh) and automatically honored by discovery-index consumers via the append-set validation requirement (Storage Spec §2.5, check (c)), with no separate takedown path for the index.

---

### 3.2.1 Where the Sandbox Is Implemented — a Conformance Boundary, Not a Gap

**Stated explicitly at v1.0 because the division is easy to mistake for an omission.** §3.2 specifies the isolation a published app must run under. It does not, and cannot usefully, specify *how* — because the answer is a property of a particular browser engine on a particular platform, and the whole point of §1.2's choice of a webview is to inherit decades of hardened browser sandboxing rather than reinvent it.

The boundary is therefore: **the protocol layer decides which bytes are the app and whether it is servable; a client decides whether to execute them and under what isolation.** A protocol implementation that ships no sandbox is complete as a protocol implementation — it has no business executing anything. A *client* that renders published apps is conformant only if it provides §3.2's isolation, and that obligation does not weaken because the protocol layer cannot enforce it.

Two consequences worth being blunt about. Nothing in a protocol implementation will ever tell a caller that an app is safe to run, so a client that fetches an `app-bundle` and executes it without its own sandbox has not been let down by the protocol — it has skipped the step the protocol was never in a position to take. And a network operator choosing whether to allow `app-bundle` on its content-type allowlist (§1.1) is making a decision about what its members' *clients* will be asked to execute, which is why that allowlist entry is opt-in rather than default.

---

## 6. Explicitly Open Questions

1. Exact enforcement mechanics and platform API surface for `network-storage-write` and `network-call` once they move from "declared" to "enforced" (§2.2) — deferred until those capabilities are actually needed by a real app.
2. Whether/how a future richer runtime (§1.3) would need its own, stricter capability model given a WASM sandbox has different ambient-access risks than a webview — flagged for whenever that extension is actually pursued, not needed for v1.
