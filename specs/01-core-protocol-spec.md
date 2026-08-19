# Core Protocol Specification

**Project:** Distributed Intranet
**Document status:** v1.0 — stable. A reference implementation exists (see the repository root); where the two differ, this document is normative and the divergence is recorded in the implementation.
**Depends on:** nothing (this is the foundation layer)
**Consumed by:** Storage & Replication Spec, App Hosting Spec, Real-Time Transport Spec

---

## 0. Purpose and Scope

This document specifies the foundation layer that every other part of the system is built on:

1. **Identity** — how a person is represented cryptographically, across many independent networks, without those networks being able to correlate them.
2. **Membership & Governance** — how networks decide who joins, what a new joiner is granted by default, who has authority, and how that authority is exercised.
3. **Group Encryption & Revocation** — how data in a network is encrypted such that removed members retroactively lose access.
4. **Capability Ledger** — how nodes advertise what resources they're willing to contribute, per network, and how other subsystems consume that information.
5. **Discovery & Transport** — how nodes find and connect to each other, including NAT traversal and bootstrap.

Explicitly **out of scope** for this document: content storage/replication mechanics, app publishing/execution, real-time media relay mechanics, and any user-facing application built on top of this platform. Those are separate specs that treat this document's outputs as their inputs. This document (and the specs built on it) intentionally describe a general-purpose platform, not any specific application — application design is deferred entirely, to keep the platform's architecture from being shaped around one particular use case.

### Design principles carried through this whole project

- **Many independent networks, one protocol.** The protocol must work identically for a two-person friend group and a 200,000-node fandom network. No component should assume a specific scale.
- **No required central authority.** Bootstrap infrastructure exists only to solve the cold-start connectivity problem. Nothing about identity, membership, encryption, or ongoing operation should depend on any single always-on service.
- **Resource contribution is opt-in and revocable, per network.** A user decides, per network they belong to, how much of their machine they're willing to give.
- **Fail closed.** Anywhere the system is unsure whether an operation is authorized or a key is available, it must refuse the operation rather than silently fall back to something less secure.

### How Applications Are Expected to Be Built On This Platform

This document, together with the Storage & Replication Spec, forms the **mandatory foundation** every client built on this platform depends on — identity, membership, encryption, content publishing, and replication. The App Hosting Spec, by contrast, is **optional additional infrastructure**: a network only needs it if that network wants to support in-network, dynamically-published, sandboxed applications. It is not a layer every client or every network passes through. Two coexisting, equally valid usage patterns are expected in practice, and neither is privileged over the other by the protocol:

- **Native client applications (expected to be the common case):** conventionally-distributed software (installed from GitHub, an app store, a website — entirely outside this protocol's concern) that links against this platform's protocol implementation as a networking and data backend. A friend group's chat client, for example, is downloaded and installed once, and from then on creates or joins specific networks (one per friend group) using the identity/membership/encryption mechanics in this document, and publishes/reads ordinary typed content (e.g. `text` messages, Core Protocol Spec §2.8) via the Storage Spec directly. Such a client never needs the App Hosting Spec at all for its core functionality — updates to the client software itself are ordinary software updates, unrelated to anything published inside any network it connects to, the same way a browser's own software updates are unrelated to the websites it renders.
- **In-network published applications (a specific, opt-in capability, not the default):** the App Hosting Spec's model, where a **generic, protocol-aware client** (closer to a browser than to any specific application) creates/joins networks and renders `app-bundle`-typed content published *inside* them, sandboxed. This is the right fit for networks that specifically want dynamically-updatable, in-network-hosted apps — a sandbox/experimentation network, a community wiki whose software itself is meant to live inside the network it serves — but it is a deliberate choice a network's operator opts into (by including `app-bundle` on that network's content-type allowlist, Core Protocol Spec §2.8), not a requirement imposed on every network or every application built on this platform.

**These two patterns are packaging/distribution choices for a given application, not mutually exclusive categories of application.** A single application's UI and logic can, in principle, be shipped both ways at once: as a standalone native client (installed and run independently, like a desktop Spotify or Discord install) *and* as an `app-bundle` runnable inside a generic Model A client — the same way many companies today ship both a native app and a website with equivalent functionality. Nothing in this protocol requires picking one path exclusively; a developer can offer either, both, or migrate between them over time. A generic Model A client (this document's design refers to it informally as the "Sandbox" going forward) simply provides one more way for people to reach a given network's application without installing anything dedicated to it first.

---

## 1. Identity Model

### 1.1 Master Identity

Each **person** (not each device, not each network) has one **master identity**, represented by a single high-entropy seed generated once and stored locally (analogous to a BIP-39-style mnemonic/seed for key derivation — the exact scheme is an implementation detail for Claude Code to select, but it must support deterministic child key derivation, e.g. an HD-derivation scheme similar to BIP-32).

The master seed itself is:
- Never transmitted over the network, ever, under any circumstance.
- The single source of truth from which all other keys are derived.
- Recoverable by the user (e.g. via a backup phrase), independent of any device.

### 1.2 Per-Network Identity Derivation

For every network a user joins, a **distinct keypair is deterministically derived** from the master seed plus the network's unique identifier:

```
network_identity_keypair = derive(master_seed, network_id, "identity")
```

Properties this must guarantee:
- **Unlinkability:** Given two per-network public keys from two different networks, an observer (including a malicious network operator) cannot determine they belong to the same person, without the person's cooperation.
- **Determinism:** The same master seed + network_id always regenerates the same keypair, so identity survives device loss as long as the master seed is recovered.
- **Provable common ownership, at the user's discretion:** The user must be able to *choose* to prove that two per-network identities are the same person (e.g. to their own alt accounts, or to a trusted party), without this being derivable by anyone else. (Mechanism: a signed statement linking two per-network public keys, only created and shared voluntarily.)

**Unlinkability must extend to the transport layer, or it's void in practice.** Key-level unlinkability alone is insufficient: if a node reuses one libp2p PeerId (or one persistent listening address) across multiple networks, its memberships become trivially correlatable by any observer regardless of how carefully the per-network identity keys themselves are derived — the key layer being unlinkable doesn't help if the transport layer hands out the same correlating fingerprint everywhere. This document therefore requires: **a node's libp2p PeerId must be derived from that network's per-network identity keypair, distinctly per network** (libp2p already derives a PeerId from a public key, so using the per-network identity keypair as that network's transport identity yields a distinct PeerId per network for free, consistent with the derivation pattern used throughout this document — no separate mechanism needed). Stated honestly, not silently assumed: **IP-level and network-timing correlation remain explicitly out of scope for this protocol.** An observer who can see that the same IP address participates in multiple networks at overlapping times can correlate that fact regardless of any key or PeerId-level unlinkability — mitigating that (e.g. via different network paths per identity) is a user operational choice, not a guarantee this protocol provides. This is stated explicitly here so an implementer doesn't quietly overclaim a stronger anonymity property than what's actually achieved.

### 1.3 Multi-Device Identity Linking — Resolved

A person may want to act as the same identity from multiple physical devices (a laptop and a phone, say), without any device other than a deliberately-chosen few ever holding the master seed itself — copying the master seed to every device it's used from would mean losing/compromising *any one* of them forces rotating the entire identity across every network, which is exactly the outsized blast radius this design is meant to avoid.

**Devices are independent, then linked — never derived from the master seed.**

1. **Each device generates its own local device seed** at setup, independently, never leaving that device and never shared with the master identity or any other device. A device is not a derivative of the master seed; it starts as its own thing and is subsequently *authorized* to act on the master identity's behalf.
2. **Per-network device keys, same derivation pattern as §1.2.** A device derives a distinct device keypair per network from its own local device seed + network_id — for the identical unlinkability reason identities are derived this way: a device's participation in one network should not be correlatable, by its key material alone, to its participation in another. This reuses the same HD-derivation approach as the master identity rather than inventing a second pattern.
3. **Linking (enrollment) requires the master seed, once, per network.** To authorize a device for a given network, whichever device currently holds the master seed derives that network's per-network identity private key (transiently, in memory, as it already does for any per-network operation) and signs a **device certificate**: `(network_id, per_network_identity_pubkey, device_pubkey_for_that_network, device_label, issued_at)`. This certificate is gossiped and recorded in that network's governance log (§2.7) — reusing the same tamper-evident, independently-replayable structure rather than inventing a parallel record type, even though device linking isn't a group/capability action.
4. **Verifying a device's actions.** Any signed action from a linked device is checked against its currently-valid device certificate: is there a non-revoked certificate binding this device's per-network pubkey to a recognized identity in this network? If so, the action carries whatever authority that identity holds (via its group memberships, §2) — the device itself has no independent standing beyond what its certificate grants.
5. **No protocol-level "primary device" role.** Any device holding the master seed can mint or revoke device certificates for any network the identity belongs to — the protocol has no concept of one designated primary device, only "devices that currently hold the master seed" versus "devices that hold only a certified device key." How many devices a person chooses to trust with the master seed itself (ideally as few as possible) is an operational choice, not a protocol distinction.
6. **Revocation is two distinct, separable actions**, addressing two different risks a lost/stolen device creates:
   - **Device-certificate revocation** cuts off future signing authority: a revocation record is issued by a master-seed-holding device and appended to the governance log, same as issuance. From that point, signatures from that device's key are no longer valid for that identity in that network — no master seed or per-network identity key rotation required, exactly the property this section set out to provide.
   - **Voluntary self-initiated epoch rekey request** addresses the separate risk that a compromised device may have already cached the network's current epoch key, retaining decryption ability for previously-accessible content even after its signing authority is cut off. An identity can request the network trigger an epoch rotation (§3.3) for this reason alone, without needing any special capability — this is a self-service, security-positive action analogous to how MLS already allows any member to propose a key update, and gating it behind approval would actively discourage reporting a compromise, which is the wrong incentive to create.
7. **Enrollment is per-network.** Authorizing a device for one network doesn't authorize it for another — each network's certificate is independently issued, gossiped, and revocable, keeping networks properly isolated from each other, consistent with every other per-network mechanism in this document. A user adding a new device to several networks at once is a UX convenience (one workflow issuing several independent certificates), not a change to this underlying model.
8. **Recovering from losing every master-seed-holding device is a separate concern**, already covered by the seed-backup/recovery guarantee in §1.1 — not something this section needs to re-solve. Once the master seed is recovered onto any device, that device can immediately mint or revoke certificates as normal, since certificate authority was never tied to a specific device, only to master seed possession.

### 1.4 What "Node" Means Going Forward

To avoid ambiguity in later documents: a **node** is a running instance of the software on a physical machine — in multi-device terms, either a master-seed-holding device or a device operating under a certificate per §1.3. A **user/identity** is the master identity above, and may correspond to more than one node simultaneously. One user's node(s) can collectively participate in many networks, presenting a different per-network identity in each, subject to per-network resource limits (see §4).

---

## 2. Membership & Governance

### 2.1 Group-Based Authorization Model

Authorization in this system follows a deliberately restrictive, established pattern from enterprise identity/access-control systems (in the spirit of Active Directory-style RBAC), chosen specifically to avoid both the ad-hoc sprawl those systems are notorious for accumulating and the unbounded-graph-traversal problems a free-form delegation model would introduce. Two hard rules define the whole model:

1. **Capabilities can only be granted to groups, never to individual identities.** An identity's effective permissions are the union of the capabilities held by every group it belongs to. There is no mechanism anywhere in the protocol for granting a capability directly to a single identity.
2. **Groups are flat — no nested groups.** A group contains identities directly; it cannot contain other groups. Nested-group hierarchies are the single most common source of incomprehensible, unmanageable permission sprawl in real-world RBAC deployments (Active Directory being the canonical example), and nothing in this project's requirements needs that complexity. If a real future need for nesting emerges, it should be a deliberate, visible extension to this document — not something that creeps in through convenience.

This split cleanly separates two concerns that a pure delegation-chain model conflates: **what a role can do** (a group's capability set — should change rarely, tightly governed) versus **who currently holds that role** (a group's membership — changes often, can be delegated more liberally). See §2.5 for why that separation matters directly for revocation.

### 2.2 Capabilities

The protocol defines a set of discrete, grantable **capabilities**, granted only to groups (§2.1). An action is authorized if the acting identity belongs to at least one group holding the relevant capability. Every capability is tagged, at the point it's defined, as either **governance-tier** or **ordinary** — this tag is what the `everyone` denylist in §2.4 actually keys off, rather than a hardcoded list of names, so capabilities introduced later (by this document or by consuming specs, which this section explicitly permits) can't silently escape the invariant by simply not appearing on some fixed list written down at one point in time.

Example capabilities (non-exhaustive — the app-layer specs may define more, and must tag anything they define per the same governance-tier/ordinary distinction):

| Capability | Effect | Tier |
|---|---|---|
| `approve-node` | Can admit a new member to the network | Governance-tier |
| `revoke-node` | Can remove a member (triggers key rotation, §3) | Governance-tier |
| `define-group` | Can create a new group or change an existing group's capability set | Governance-tier |
| `manage-membership:<group>` | Can add/remove identities from a specific, named group | Governance-tier *if the target `<group>` itself currently holds any governance-tier capability; ordinary otherwise* — see §2.4 |
| `moderate-content` | Can flag/remove published content within network policy — exercised by appending a `ModerationEntry` to the governance log (§2.7) | Governance-tier |
| `define-policy` | Can change the network's governance policy itself (see 2.4) | Governance-tier |
| `audit-reputation` | Can request a node's raw local reliability observations for oversight purposes (see §4.6) | Governance-tier |
| `define-content-policy` | Can change the network's content-type allowlist (see §2.8) | Governance-tier |
| `publish:<content_type>` | Can create new published content of a specific type — an independent gate from the content-type allowlist itself (see §2.8) | Ordinary |
| `approve-app-publish` | Under reviewed-publishing policy, can admit a pending app version before it becomes servable (see App Hosting Spec §3.5) | Governance-tier |
| `read-content` | Can request/receive content bytes for this network from other nodes — the capability that gates swarm-serving (Storage Spec §5.4), not merely holding a valid identity | Ordinary |

**`read-content` is what actually gates content access, and was previously referenced without being formally defined here — a real gap now closed.** Earlier sections of this document (§2.4's waiting-room description) referred to a joining node having "no `read-content` or any other capability" as if this were already an established capability, without it ever appearing in this table. It's added here explicitly: an ordinary capability, typically granted broadly to `everyone` in most networks (so that ordinary admission implies the ability to actually read content, matching the intuitive default), but genuinely network-configurable like any other ordinary capability — a network wanting an even more locked-down posture could restrict it further. Storage Spec §5.4 is the primary consumer of this capability, using it as the actual gate for whether a node's request for content bytes is honored.

Note the deliberate asymmetry between `define-group` and `manage-membership:<group>`: **defining what a group can do is a high-bar action**, gated the same way policy changes are (§2.6) — this is the structural guard against sprawl, since creating new permission surface is never a casual, low-friction action. **Managing who is currently in an already-defined group is comparatively low-bar and delegable** for ordinary groups, since it doesn't create new capability surface, only changes who currently holds capabilities that have already been reviewed and approved — but see §2.4 for why this delegability has a hard limit once the target group itself carries real governance power.

### 2.3 Founder as Implicit Root Group

Every network begins with a single **Founders** group, implicitly created at genesis, holding every capability, with the network creator as its sole initial member. This is not a special-cased individual identity with hardcoded permissions — it is an ordinary group under the same rules as every other group (§2.1), which keeps the authorization model fully uniform with no bootstrap-time exceptions to reason about. The Founders group is not required to be un-growable — its own membership can be managed like any other group's, per whatever `manage-membership:Founders` is granted to, though most networks will likely keep this tightly held.

### 2.4 The `everyone` Group and Invite-Driven Admission

Every network also has a second implicit group, **`everyone`**, created automatically at genesis alongside `Founders` (§2.3). `everyone` is where a newly admitted node's baseline membership lives — the group whose capabilities define "what any ordinary member can do by default."

**Hardcoded ceiling, configurable floor.** A network's `Founders` (via `define-group`) may grant `everyone` whatever non-governance capabilities suit that network's posture — e.g. a small trusted network might grant `everyone` the ability to publish content by default, while a large open network might keep `everyone` read-only. This is genuinely configurable per network. However, the protocol **hardcodes a structural invariant: `everyone` may never hold any capability tagged governance-tier (§2.2), under any configuration.** This is defined as a class, not an enumerated list — any capability tagged governance-tier at the point it's defined is automatically covered, including capabilities introduced later by this document or by consuming specs, without requiring this section to be patched every time a new one is added.

**`manage-membership:<group>` requires a recursive check, since it's parametrized.** A `manage-membership:<group>` grant to `everyone` is permitted only if `<group>` itself currently holds no governance-tier capability — since granting `everyone` the ability to add/remove members of a group that *does* hold real governance power would let it indirectly seize that power regardless of what `everyone`'s own capabilities are. This is checked dynamically (governance state is always fully recomputable by replaying the governance log, §2.7, so this check has no additional cost beyond what the protocol already does) — if a governance action later grants `<group>` a governance-tier capability while `everyone` already holds `manage-membership:<group>`, that grant must itself be rejected, since it would retroactively violate the invariant. A network can still safely grant `everyone` membership-management over purely ordinary groups (e.g. a group with no real power, used only for something like `publish:text`), which is exactly the low-bar delegable case §2.2 describes.

An attempt to grant any governance-tier capability to `everyone` (whether at genesis or via a later `define-group` action) must be rejected by the protocol itself, not merely discouraged by convention. This guarantees that simply being admitted to a network — however low-friction that admission is — can never itself confer governance power, regardless of how permissively a given network configures its default group. This is a structural invariant, consistent with the project's fail-closed principle, not a per-network policy choice.

**Admission mode is a network-wide policy setting** (configured alongside other governance policy, §2.6), with two options:

- **Auto-admit:** successfully using a valid invite immediately grants `everyone` membership — no separate review step. This is the low-friction, scalable default, appropriate for large or open networks where manually reviewing every joiner isn't viable.
- **Explicit intake:** successfully using a valid invite establishes connectivity and a per-network identity, but grants **no group membership at all**, including `everyone`. The node enters an explicit **waiting-room state**: it is discoverable by anyone holding `manage-membership:everyone` (surfaced with basic context — at minimum, which invite was used and who issued it), but has no `read-content` or any other capability until an admin explicitly admits it into `everyone` (or any other group). This is the "zero permissions until explicitly granted" mode, well suited to small, high-trust networks where manual review is a feature, not friction to eliminate.

This is deliberately a single network-wide setting rather than something an individual invite encodes — mixing admission postures within one network would create inconsistent onboarding and blur accountability for who's responsible for the network's admission stance. If a network wants some invites to bypass scrutiny and others not to, that's a property of *who gets an invite in the first place* (already controlled by whoever holds `approve-node`), not something the invite payload itself needs to express.

### 2.5 Membership Revocation Cascade

When an identity is removed from a group (whether that identity is a `manage-membership:<group>` holder who had been adding others, or an ordinary member), a question arises: if that identity had itself added other members to the group, what happens to those downstream memberships?

Default and opt-in behavior, in order:

- **Default — non-cascading (B):** removing an identity from a group only removes that identity. Anyone else it added remains, since their membership was validly granted at the time. This avoids collateral damage from routine membership cleanup (e.g. someone stepping down from a moderator group shouldn't silently strip everyone they ever onboarded).
- **Opt-in — cascading (C):** the identity performing the removal can explicitly specify a cascade, removing everyone the revoked identity added to that group (recursively, if those people had also added others), optionally scoped to a time window (e.g. "cascade everything added in the last 48 hours" for a compromised-account scenario). This is specified explicitly at the moment of revocation, not as a standing group setting — a deliberate, visible choice each time it's used, not a background policy someone forgets is active.

This mirrors the fail-closed-by-default-with-explicit-opt-in pattern used elsewhere in this project (e.g. §3.4's current-epoch-forward-by-default, full-history-opt-in access policy), applied here to group membership rather than encryption keys.

### 2.6 Pluggable Governance Policy

"Who can approve a new node," "who can define groups," and similar high-level governance questions are configurable per network, expressed as a **policy module** selected at genesis (or changed later via `define-policy`):

- **Sole authority:** only the Founders group (or another specific group holding `approve-node`) can admit members.
- **Delegated moderation:** Founders grants `approve-node` to an additional group (e.g. "Moderators"), and manages who's in that group via `manage-membership:Moderators`.
- **Member vote:** admission requires a quorum of existing members (or a delegated smaller body — see §2.6.1) within a time window, rather than any group's capability holders acting unilaterally.

The policy module's job, abstractly, is to answer one question: **"is this action currently authorized, given the network's current group memberships and rules?"** Storage/app-hosting/real-time specs should call into this same policy interface for their own authorization needs (e.g. "is this identity authorized to publish an app") rather than reimplementing authorization logic.

**Member-vote is not compatible with auto-admit, and the combination must be rejected rather than resolved.** This document defines admission mode (§2.4) and governance policy (this section) independently, and never addressed what it means to set both — a gap, since one pairing asks for opposite things. Auto-admit says successfully using a valid invite *immediately* grants `everyone` membership with no separate review step; member-vote says admission requires a quorum of the electorate within a time window. A network configured for both is asking for admission to be simultaneously automatic and deliberated, and there is no correct behaviour to fall back on: honouring either setting silently discards the other. **Such a configuration must therefore be refused at the point policy is set — at genesis, and on any later `define-policy` change — not at the point a joiner is turned away**, since discovering it then means an operator learns their network cannot admit anyone from a confused joiner rather than from the action that broke it. Member-vote pairs with **explicit intake**, which is the coherent reading of both: the invite establishes connectivity and an identity, and the electorate — rather than an admin — is what decides whether the joiner is admitted.

**A network also cannot *open* under member-vote, which follows from the mechanism rather than being a separate rule.** Admission requires a quorum of a frozen electorate (§2.6.1), and at genesis that electorate is empty or holds only the creator, so the first admission could never reach quorum. A network reaches member-vote by starting under capability-holder policy, admitting a founding electorate, and then switching via `define-policy` — which is an ordinary governance action, recorded and replayable like any other. This is worth stating because the alternative reading, that member-vote is a genesis-time choice, produces a network that is permanently unable to admit anybody and gives no indication why.

### 2.6.1 Member-Vote Quorum Mechanism — Resolved

The mechanism below resolves the previously open question of how vote-based admission reaches a decision without any central tallying authority, at any network scale:

1. **Frozen electorate.** The eligible-voter pool ("M") is a **snapshot** of a specific group's membership, taken at a fixed version the moment a vote is proposed — the same versioning mechanism already used for mutable pointers (Storage Spec §2.2), applied here to group membership instead of content. No one can be added to or removed from the electorate mid-vote to influence the outcome, since the vote is defined against a fixed roster from the start. The electorate group defaults to `everyone`, but a network can instead designate a smaller group (e.g. an elected/appointed "Voters" group) as the electorate — this is how representative rather than direct-democracy voting is supported, with no separate mechanism: it's the same quorum process run against a smaller M.
2. **Gossiped, signed ballots.** A vote is a signed record (`vote_id`, voter identity, yes/no) propagated via the same GossipSub-based dissemination already used throughout this protocol (§5.1) — no new transport. Sybil resistance requires no separate mechanism either, since membership is already identity-gated (§1.2): one per-network identity, one ballot.
3. **Fixed close window, not real-time synchrony.** Every vote proposal carries an explicit close time (e.g. 72 hours). A ballot is valid for inclusion in a certificate only if its own signed timestamp is at or before the close time — this is what actually defines "was this ballot cast in time," not when any node happens to observe it or assemble a certificate from it.
4. **Outcome is defined as certificate existence, not local computation or assembly timing — this is the actual deterministic source of truth.** A vote **passes if and only if a valid quorum certificate exists** — a Merkle-rooted, independently-verifiable bundle of qualifying signed ballots (each with a timestamp at or before close, per point 3) checked against the fixed electorate snapshot (point 1). This is a deliberate correction to an earlier, looser framing ("each node computes the outcome from whatever ballots it collected"): different nodes can observe different ballot sets near the close boundary due to ordinary clock skew and gossip propagation delay, so *local* computation from *locally collected* ballots can genuinely diverge between honest nodes — it is not itself a reliable source of truth. The certificate is what's actually deterministic, since any node checking a given certificate against the same fixed snapshot and the same ballot timestamps will always agree — **including a certificate assembled well after close, from ballots that were validly cast before it.** Certificate *assembly* time is irrelevant to a certificate's validity; only the referenced ballots' own timestamps matter, which closes an ambiguity an earlier version of this document left open (whether "by the close time" referred to when a certificate had to exist, which would have wrongly penalized a legitimately-passing vote whose certificate simply took time to assemble and propagate). Local ballot collection is only ever a tool for *constructing* a candidate certificate, never the outcome itself. **If no certificate meeting these criteria is ever produced, the vote fails — fail-closed, consistent with this project's core principle, with no ambiguous "maybe it passed for some nodes" state, and no deadline pressure on certificate assembly itself.**

This deliberately avoids heavier distributed-consensus machinery (e.g. threshold-signature/DKG-based schemes), which bring real operational cost — key ceremonies, re-keying on every membership change — for a problem that gossiped, independently verifiable ballots already solve cleanly at any scale, since what matters here is verification cost, not tallying speed or real-time synchrony.

**Explicitly out of scope:** delegated/liquid voting, where an individual member assigns a personal delegate to vote on their behalf (as opposed to a network simply designating a smaller electorate group per point 1 above). That's a materially heavier feature — per-voter delegation chains, revocability, transitivity — and isn't something this project has asked for; if ever wanted, it should be proposed as its own deliberate extension later, not designed around speculatively now.

### 2.6.2 Application-Layer Policy Values — Added for Consuming Specs

**Added at the request of the Chat Application Spec (§7, E9), and generalised rather than
special-cased.** A consuming spec may need settings that must be identical on every node.
The motivating case is a flood ceiling: if it is a *validity* rule — records past it are
refused rather than merely discouraged — then two members computing it differently would
render different history from the same records, which is the cross-node divergence this
document is otherwise careful to design out.

Network policy is the only place with the properties that requires: replayed, ordered,
tamper-evident, and gated on `define-policy`. So a network's policy carries an additional
map of **application-layer values**:

- **Keys are namespaced**, `<namespace>:<name>`, both parts non-empty. This is enforced,
  not conventional — an unnamespaced key is refused when decoded, so two applications
  sharing a network cannot collide.
- **The protocol stores, orders and encodes these values but does not interpret them.**
  What a value means is the consuming spec's business entirely.
- **An unrecognised key round-trips unchanged**, which is what lets a network run a newer
  client alongside an older one without a policy migration.
- **They are part of the entry hash**, like every other policy field. A policy change that
  did not alter the hash would be a change no node could detect.

**Why not named fields.** §0 states that this document describes a general-purpose
platform and that application design is deferred entirely, "to keep the platform's
architecture from being shaped around one particular use case". A
`chat_message_rate_per_minute` field here would be exactly that shaping. The division used
instead — the governance layer carrying a registry on a consuming spec's behalf without
understanding it — is the one `extension_capabilities` (§2.2) already established, applied
a second time rather than invented.

**Absent means default, not refused** — deliberately unlike the extension-capability
registry, where an unregistered name *is* refused. The asymmetry is not an inconsistency:
a missing capability tier would let a governance-tier grant pass as ordinary, which is a
security failure, while a missing setting simply means nobody changed it from whatever
default the consuming spec ships.

### 2.7 Governance Log

Every network maintains a single **hash-chained, append-only governance log**: every membership change, capability grant, group definition, policy change, moderation action (see **Moderation entries** below), and epoch rotation (§3.3) is recorded as a signed entry referencing the hash of the immediately prior entry, gossiped like all other network state (§5.1). This borrows the core structural idea behind blockchain-style ledgers — tamper-evident, independently verifiable history with no central authority — while deliberately discarding the parts of that model built for anonymous, permissionless participants (mining, proof-of-work/stake). Nothing here is needed, because every actor in this system already has a verified identity and explicit group membership (§1–2) before taking any action; the log's job is only to make the *sequence and content* of authorized actions tamper-evident and independently replayable, not to establish trust among strangers.

**What this gives the protocol, concretely:**

- **A single source of truth for current authorization state.** Any node can independently verify a network's entire current governance state — who's in which group, what capabilities each group holds, what the current policy configuration is — by replaying the log from genesis (or from a recent, independently verifiable checkpoint) and checking each entry's signature against the authorization rules that were in effect at that point in the chain. No node has to trust another node's claim about "the current state"; it can always recompute it.
- **A decentralized realization of a "policy engine."** In zero-trust-architecture terms (see the discussion that led here), this log plus the capability system together *are* the network's policy enforcement point — just replicated and self-verifying instead of centralized. Any node checking "is this action authorized" is really asking "does replaying the governance log up to this point produce a state where the acting identity holds the relevant capability" — a computation, not a query to a trusted server.

**Moderation entries — the concrete record behind "delisted," previously referenced by three consuming specs without ever being defined.** Delisting (and re-listing) published content is recorded in the governance log, exactly like every other authoritative yes/no fact in this design — **not** as a Distributed Append-Set entry (Storage Spec §2.5), and not through any separate, unauthenticated side channel:

```
ModerationEntry {
  action:             "delist" | "relist"
  target_pointer_id:  the mutable pointer (Storage Spec §2.2) being moderated
  moderator_identity: per-network identity of whoever performed the action
  signature:          moderator's signature over the above
}
```

- **Authorization is the ordinary capability check, not a special case.** A `ModerationEntry` is valid only if `moderator_identity` belonged to a group holding `moderate-content` (§2.2) at that point in the chain — the same rule every other governance action is validated under, applied by the same replay logic.
- **"Is this pointer currently delisted?" is answered by replay**, not by a lookup against any separate store: take the most recent `ModerationEntry` targeting that `pointer_id` in the canonical branch, and its `action` is the current state. A pointer with no `ModerationEntry` at all is not delisted. This is the identical replay-for-current-state pattern already used for group membership, capability grants, and policy configuration — deliberately not a new mechanism, and it inherits every property that pattern already has: tamper-evidence, independent verifiability, and no trusted party to ask.
- **`relist` exists so moderation is reversible on the same terms it was applied** — a mistaken or later-overturned delisting is corrected by appending, never by rewriting or removing history, consistent with the log being append-only.
- **Moderation entries are capability-gated, so they count toward branch length** under the fork-choice rule (§2.7.1, point 2) — unlike capability-free entry types such as device certificates (§1.3), which are excluded from that count.

This is the concrete mechanism several consuming specs already depend on and which each previously referred to only as an undefined "delisted"/"moderated" state: append-set entry validation (Storage Spec §2.5), search posting validation (Search Spec §3.1, §6.1), and app takedown (App Hosting Spec §3.4). All three now resolve that state the same way, through this one record type.

### 2.7.2 Application-Layer Entries — Added for Consuming Specs

**Added at the request of the Chat Application Spec (§7, E2), and generalised rather than
special-cased**, for the same reason §2.6.2 was.

An application layer sometimes needs durable, ordered, tamper-evident records for its own
structure — a chat application's channel definitions, say. A Distributed Append-Set cannot
hold those: its entries lapse when unrefreshed (Storage Spec §2.5), so a channel would
silently vanish while its creator was offline. The governance log is the only mechanism
with the required properties.

The log therefore carries an **application entry**: a namespace, a kind, the capability the
consuming spec says the record requires, and an opaque payload.

- **The protocol orders, hash-covers and authorizes these entries. It does not decode
  them.** Replay refuses an entry whose author did not hold the declared capability at that
  point in the chain, and does nothing else with it; a consuming spec replays the log
  itself, filtering for its own namespace.
- **What the protocol cannot check is whether the *right* capability was declared.** A
  reader that understands the namespace must verify that too — that a channel definition
  demands channel-management authority and not something weaker. The protocol enforces the
  capability that was named; the consuming spec decides which one should have been.
- **Payloads are bounded.** The log is replayed in full by every joiner and never shrinks,
  so an unbounded payload would let one application make a network permanently expensive to
  join. Application *content* belongs in storage behind a CID an entry can reference; this
  carries structure.
- **Application entries do not count toward branch length** (§2.7.1, point 2). Whether one
  is cheap to mint depends on whether its declared capability is scarce, and answering that
  means resolving a tier against replayed state — which the branch-length metric
  deliberately cannot do. Excluding them fails closed against grinding. The cost is that an
  application's actions carry no weight in fork choice and a partition may void them, which
  is acceptable: everything that must survive a partition — membership, revocation, policy,
  epoch rotation — is a core entry that still counts, and a voided application entry is
  resubmittable through the voided-actions report like any other.

**Why this is generic.** §0 says this document describes a general-purpose platform and
defers application design entirely. Naming each consuming spec's records here would shape
the log around whichever applications arrived first — and that has already happened once:
`AppNameRegistration` is App Hosting's record sitting in this document's entry vocabulary.
Adding four chat-shaped variants beside it would have made a pattern of an exception. One
door, used by every application layer, is the correction.

### 2.7.1 Fork-Choice and Reconciliation Rule — Resolved, With a Bounded-Finality Correction

**"Whichever entry attaches first is canonical" is not itself a well-defined rule in a distributed system** — with two concurrent entries both referencing the same parent hash, gossiped into different parts of the network, each side can honestly observe its own entry as having "attached first" from its own local vantage point. There is no global "first" without an explicit, deterministic rule, so this document specifies one directly rather than leaving it implicit:

1. **Deterministic sibling tie-break.** When two entries reference the same parent (a single-entry fork), every node applies a fixed, objective rule to choose the canonical one: **the entry with the lower entry-hash wins.** This requires no additional signaling or negotiation — any node holding both competing entries computes the same answer.
2. **Longest-branch reconciliation for deeper partitions — measured only by capability-gated actions.** If a genuine partition allows both sides of a fork to be extended multiple entries deep before the network reconnects, the reconciliation rule is: **the branch with more capability-gated governance actions is canonical; on equal count, apply the sibling tie-break (point 1) to the two branches' tip entries.** **This is a correction to an earlier version of this rule, which measured raw entry count** — a real exploitable gap, since device certificate issuance (Core Protocol Spec §1.3) requires no capability at all, only possession of the master seed, meaning any member could mint arbitrarily many device-certificate entries during a partition to grind their own branch to victory regardless of what governance actions it actually contained (including, notably, voiding an unfavorable revocation of themselves). Device-certificate entries (and any other future entry type that similarly requires no capability to produce) still exist in and are recorded by the log — they are simply excluded from the count this rule compares, so they carry no weight in deciding which branch wins.
3. **Bounded finality — a correction that resolves multiple downstream problems at once.** A branch **can no longer be displaced by a competing branch, full stop**, once **both** of the following hold:
   - it is buried under **k = 10 subsequent capability-gated governance actions**, *and*
   - its tip is at least **T = 30 minutes** old.

   **Both conditions are required — this is deliberately not either/or.** Depth alone is insufficient: a fast burst of legitimate-looking capability-gated actions could finalize a branch before enough real-world time has passed for a genuine competing branch to propagate and surface, which would weaken exactly the anti-grinding protection point 2 exists to provide. Time alone is insufficient: a quiet branch would finalize on the clock without ever accumulating meaningful confirmation. Requiring both closes each gap the other leaves open. Note that depth is counted in **capability-gated** actions specifically, consistent with point 2's metric — capability-free entries (device certificates, §1.3) can no more grind a branch to *finality* than they can grind it to *victory*.

   **These are starting defaults, explicitly tunable, not permanent constants.** They are stated here concretely — rather than left abstract, as an earlier version of this document did — because downstream mechanisms cannot be implemented or tested against an unspecified threshold: MLS secret retention (§3.3) needs a defined point at which it is safe to discard superseded epoch secrets, and the harness's partition-with-competing-rotations test (Reference Test Harness Spec §3) needs real numbers to wait on and assert against. Both values should be revisited once the harness produces realistic gossip-propagation and partition-duration measurements, the same way replication factor (Storage Spec §3.1) and chunk size (Storage Spec §1.3) are expected to be tuned per network.

   This bounded-finality rule is a genuine addition, not present in an earlier version of this rule, and it exists because "longest branch wins, forever, with no finality point" turned out to have real consequences: without it, any entry is perpetually provisionally voidable by a sufficiently long later competing branch, meaning "replay the log for current authorization state" never actually terminates in a settled answer — which in turn is what made the MLS-state problem below unsolvable without this fix. With a bounded finality point, "settled" becomes a concrete, checkable condition (an entry has reached both depth k and age T), not an open-ended possibility.
4. **Effects of a losing branch are voided, not partially applied — for governance log entries.** Once reconciliation selects a canonical branch (constrained by finality, point 3, once reached), every entry that exists *only* on the losing branch is treated as if it never happened — any membership grant, capability change, or epoch rotation recorded only there has no effect on the reconciled state. Entries shared by both branches (everything before the fork point) remain valid, since hash-chaining guarantees that shared prefix is identical either way.
5. **Mandatory voided-actions report.** Reconciliation must produce an explicit, computable list of every entry voided by the process — this is what turns "an action from the losing branch can be resubmitted" from a passive possibility into an actual, defined step someone can act on, rather than something depending on a party noticing on their own. Client software is expected to watch for its own previously-submitted actions appearing in this report and prompt for (or automatically perform) resubmission — this is particularly important for a **voided revocation**: without an explicit report and a resubmission step, a person who was legitimately revoked on the now-losing branch is, for a real window between heal and resubmission, a fully current member again on the winning branch, entitled to its epoch key, simply because nobody was specifically assigned the job of noticing. The report makes noticing a defined, automatable client behavior rather than an unassigned hope.
6. **Interaction with non-cascading revocation (§2.5) is clean, not a new edge case.** If a losing branch contained both a membership grant and a later revocation of that same membership, and the winning branch never saw either action, the reconciled outcome is simply "that membership never existed" from the winning branch's perspective — not "granted, then evaluated for cascade." Voiding a losing branch's entries wholesale doesn't interact awkwardly with the cascade rules, since there's no partial state left over to reason about.

This is deliberately not a general Byzantine-fault-tolerant consensus solution — it's a simple, adequate rule sized to this project's actual expected fork frequency (rare, short partitions), consistent with the lightweight-over-heavyweight preference already established for vote quorum. The bounded-finality correction (point 3) and the capability-gated-only length metric (point 2) are what keep it adequate under adversarial conditions, not just benign ones — an earlier version of this rule handled ordinary partitions correctly but was exploitable by a motivated bad actor, which is now closed.

The governance log is network-scoped (one log per network, consistent with everything else in this design being per-network) and is itself just gossiped, signed, hash-chained data — no new storage or transport primitive beyond what's already specified in §5.1 and the Storage Spec's content-addressing model.

### 2.8 Content-Type Policy

Every network maintains a **content-type allowlist**: a governance-configured set of tags describing what kinds of content may be published within it (e.g. `text`, `image`, `video`, `audio`, `app-bundle`). This is what lets a network stay meaningfully scoped to a specific purpose — a friend group's chat-style network can permit `text`, `image`, `video`, and animated-image content while excluding `app-bundle` entirely, so that network structurally cannot be used to host an arbitrary web app, the same way an actual chat platform wouldn't let someone deploy a website into a channel. A separate network for, say, a shared wiki would carry its own independent allowlist suited to that purpose.

**Enforcement is fail-closed and protocol-level, not conventional.** Publishing anything (via the Storage Spec's mutable pointer mechanism, Storage Spec §2) requires declaring a `content_type` tag as part of the publish action. Any publish whose declared type isn't currently on the network's allowlist is rejected outright by the protocol — not merely discouraged by policy or filtered after the fact.

**Two independent gates, not one.** The allowlist governs *what content types may exist on this network at all*. A separate, parametrized capability, `publish:<content_type>` (§2.2), governs *which specific groups are allowed to publish that type* — a type being on the allowlist does not by itself grant anyone permission to publish it; that permission must be explicitly held. This distinction matters in practice: a single-purpose network (say, a wiki) can allow both `text` and `app-bundle` on its allowlist while granting `publish:text` broadly to `everyone` (so members can freely edit pages) and keeping `publish:app-bundle` restricted to a small "Developers" group (so only the wiki's actual maintainers can push new versions of the wiki program itself) — the overwhelming majority of members never need, and are never granted, the ability to publish new app-bundles at all. A network built specifically as an open sandbox for experimenting with app publishing, by contrast, could grant `publish:app-bundle` broadly to `everyone` — both are simply different configurations of the same two-gate mechanism, not different protocol paths.

**Starter vocabulary, extensible per network.** A small set of generic content types (`text`, `image`, `video`, `audio`, `app-bundle`) is defined as a shared baseline convention, similar in spirit to how MIME types provide a common core with room for extension — a network isn't limited to only these, and can register additional custom tags suited to its own purpose via the same policy mechanism below.

**Changing the allowlist requires `define-content-policy`** (§2.2), a group-held capability like everything else in this model, and every change is recorded as an entry in the network's governance log (§2.7) — tamper-evident and independently verifiable, consistent with how every other policy change in this document is handled. Granting or revoking `publish:<content_type>` follows the ordinary group-capability mechanics from §2.1–§2.2 (typically via `manage-membership` on whichever group holds that capability), also recorded in the governance log.

**Deliberately flexible, not permanently fixed at genesis.** A network's allowlist, and its `publish:<content_type>` grants, can both be changed later by whoever holds the relevant capability, the same as any other governance policy — the protocol doesn't hard-lock a network to one purpose or one publishing posture forever. In practice, this is expected to strongly encourage a "one network, one purpose, narrow publish rights" pattern (the natural, sensible default for a network built around a specific use case), without the protocol rigidly forcing it — an operator who genuinely wants a combined-purpose or wide-open-publishing network can configure that instead.

**Consequence worth naming explicitly:** because each network maintains fully independent membership (by design — see §1.2's unlinkability guarantee), a group of people using this platform for both a chat-style network and a separate wiki network are, functionally, joining two independent networks and will typically be invited to both. This is a deliberate tradeoff, not an oversight — the alternative (some form of shared membership across networks) would undercut the very isolation properties the identity and membership model was built to provide.

---

## 3. Group Encryption & Revocation

### 3.1 Requirement Recap — Honest Guarantee, Corrected

Revocation must prevent a removed member from continuing to access content going forward: they must be unable to obtain anything not already in their possession at the moment of removal.

**This document previously overstated what's achievable here, and that claim is corrected now rather than left standing.** Earlier framing described a revoked member's previously-cached ciphertext as becoming "permanently undecryptable" once rotation completes. That is not achievable under any symmetric-key scheme, including this one: if a member already holds a decryption key, no protocol action can make them un-know it, and any content they already fetched and decrypted (or held the key to decrypt) before removal remains something they can decrypt offline, forever. This isn't a weakness specific to this design — it's true of any system built on symmetric encryption, and claiming otherwise would be dishonest about a real, unavoidable limit.

**What this design actually, honestly delivers:**
- A revoked member cannot obtain the current epoch key, so cannot decrypt anything wrapped for the first time after their removal (§3.3).
- Combined with a membership-gated content-serving requirement (Storage Spec §4, new addition prompted directly by this correction), a revoked member cannot obtain *new* ciphertext for content published or edited after their removal from any honest node — closing a specific, otherwise-real gap where a member who'd previously cached an object's key material could keep decrypting that object's future edits simply by fetching new bytes through ordinary swarm traffic, which by itself has no membership check.
- What a revoked member retains, unavoidably: the ability to decrypt whatever they had already fetched and could already decrypt before removal. This is the honest floor of any symmetric-key system, not a bug in this one.

See Storage Spec §5 for the concrete mechanism this guarantee is built on (envelope encryption — small per-object keys wrapped under the epoch key, rather than content encrypted directly under it).

### 3.2 Why a Single Shared Key Doesn't Work

A single symmetric key shared by all members (the naive approach) cannot support even the corrected guarantee above — anyone who ever held the key can decrypt anything encrypted under it, forever, unless the network operator manually rotates and redistributes a new key to every remaining member for every revocation event. This does not scale and is easy to get wrong. This scheme is explicitly rejected for this project.

### 3.3 Epoch-Based Group Rekeying

The network's **epoch key** is versioned into **epochs**. Membership changes advance the epoch:

```
epoch_key[n] = derive(epoch_key[n-1] or fresh_random, membership_delta)
```

**The epoch key's role is narrower than earlier framing implied: it wraps small per-object key material, it does not directly encrypt content.** Content itself is protected by envelope encryption (Storage Spec §5) — each object gets its own randomly-generated data key, and the epoch key's job is only to wrap/unwrap that small key record, not to encrypt the (potentially large) content itself. This distinction is what makes rotation cheap (§3.3 below references the mechanism; full mechanics are Storage Spec §5's) rather than requiring re-encryption of a network's entire corpus on every membership change.

- On **join**, the new member receives the current epoch key (via a secure 1:1 channel using their per-network identity key — see §3.5), and can unwrap object key material from the current epoch forward, but not prior epochs unless explicitly granted (e.g. a network with "new members can read history" policy vs. one without).
- On **revoke**, the network advances to a new epoch with a freshly derived/rotated key. The new epoch key is distributed to all *remaining* members only, via the same MLS/TreeKEM mechanism described below.
- The revoked identity, holding only old epoch keys, cannot derive or otherwise obtain the new epoch key, and per §3.1, this is understood to mean they cannot access anything wrapped for the first time going forward — not that their prior access is retroactively erased.

This is conceptually the same family of approach used by modern group-messaging protocols (Signal-style group ratcheting / MLS-style tree-based group rekeying). **Decided: this protocol uses MLS (RFC 9420) or an equivalent tree-based group-key scheme (e.g. OpenMLS, which has a Rust implementation, relevant given this project's stack), not pairwise/per-member rekeying.** Pairwise rekeying costs O(n) per membership change — at this project's stated target of hundreds of thousands of members, a single revocation would require individually re-keying every remaining member, which is not viable. MLS/TreeKEM organizes members into a binary tree such that a rekey only touches the path from the changed member to the root, giving O(log n) cost per membership change — a few hundred thousand members means a rekey touches on the order of 20 tree nodes, not 200,000 individual operations. Because the epoch key now only ever wraps small key records rather than directly re-encrypting content (per the correction above), this O(log n) rekey cost is the *entire* cost of a rotation at the cryptographic layer — content itself does not need to move.

**Commit ordering without a central Delivery Service.** Standard MLS deployments typically rely on a Delivery Service to enforce a strict order of commits (the operations that advance the tree/epoch), which is normally a centralized or semi-centralized component — in tension with this project's no-required-central-authority principle. This is resolved by treating each epoch rotation as simply another entry in the network's **governance log** (§2.7): a rotation is triggered by a single authorized action (whoever holds `revoke-node`), producing one commit that gets appended to the log like any other governance action. The rare case of two genuinely concurrent rotations is resolved by the governance log's explicit fork-choice and reconciliation rule (§2.7.1) — a deterministic sibling tie-break for single-entry forks, longest-branch reconciliation (by capability-gated action count) for deeper partitions, bounded by finality — rather than an undefined "whichever attaches first."

**MLS state retention and re-welcome — required because MLS doesn't let members simply "rewind."** Treating rotations as governance log entries resolves *ordering*, but a member who has already processed a commit has, per MLS's own forward-secrecy contract, deleted the prior epoch's secrets — and if that commit later turns out to have been on a branch voided by reconciliation (§2.7.1), the member has no way back to a state that can process whatever commit actually turns out to be canonical. This is a real gap an earlier version of this document didn't address, and it's precisely what the bounded-finality rule (§2.7.1, point 3) exists to make solvable:

- **A member must treat a rotation's governance log entry as *tentative* until it reaches finality** (buried under k = 10 capability-gated actions **and** at least T = 30 minutes old — both required, per §2.7.1) — they may update their working epoch state to reflect a tentative rotation immediately (so ordinary operation isn't blocked waiting for finality on every rotation), but **must retain the prior epoch's MLS secrets rather than letting MLS discard them, until the rotation's log entry is finalized.**
- **If a tentatively-applied rotation is later voided** (only possible before finality, by construction — finality is exactly the point past which this can no longer happen), the member uses the prior-epoch state they deliberately retained to process whichever commit reconciliation determines is actually canonical — a **re-welcome**, in effect, back onto the correct branch. This is only possible because retention wasn't optional during the tentative window.
- **Once finality is reached, ordinary MLS forward-secrecy behavior resumes as normal** — the member discards the superseded epoch's secrets, since at that point no future reconciliation can void the rotation that superseded them.

This is a deliberate, bounded departure from MLS's default "delete immediately" behavior, scoped precisely to the tentative window bounded finality defines — not a general weakening of MLS's forward-secrecy guarantees, which still apply in full once a rotation is settled.

#### 3.3.1 Group State Must Survive a Restart — Previously Unspecified

Everything §3.3 asks of a member — advancing the epoch on a membership change, welcoming a joiner under §3.5, applying somebody else's commit — needs the member's *live* MLS group state, not merely its current epoch key. A key is what the group produced; the group is what can produce the next one.

**No section said that state has to outlive the process holding it**, and an implementation reading §3 alone will reasonably keep it in memory, which every MLS library makes the easy default. That is survivable in a test and not survivable in a deployment: a member that restarts is left holding epoch keys it can still read with and no ability to rotate, welcome, or revoke. A network's founder in that state can never key anybody in again, and the revocation guarantee §3.1 describes quietly stops being available to anyone — not because a rule was broken, but because the state that enforces it is gone.

**An implementation MUST therefore be able to persist and restore a member's group state**, with three properties:

1. **A restored member derives the same epoch key.** Anything else silently loses access to content the network already holds, which presents as data loss rather than as a keying failure.
2. **A restored member can still advance the epoch** — add, remove, and rotate. This is the property the persistence exists for; a restore that only recovered the ability to *read* would leave the revocation guarantee unavailable while looking healthy.
3. **A partial restore fails rather than half-loads.** A session recovered without its group looks alive and fails at the first rotation, which is both the worst moment to discover it and the point at which the caller has the least reason to suspect the restore.

**The serialised state is secret and the caller owes it protection.** It contains the group's secret tree and the member's signature private key — jointly enough to impersonate that member and read the network's content. This is the same narrow exception §3.5 makes for delivering a superseded epoch key point-to-point: key material leaves its type only for a purpose that cannot be served otherwise, and storing it unsealed defeats the guarantee the rest of §3 provides. An implementation that writes this to disk in the clear has given away the network, and no other part of this specification will notice.

**What this does not require.** Nothing here mandates *where* the state is kept, or that it be portable between implementations — it is one member's private state, read by nobody else, and never appears on a wire. Two implementations need not agree on its format, which is why this section states properties rather than an encoding.

### 3.4 New-Member Historical Access Policy — Corrected From an Earlier, Contradictory Framing

**This section previously described a "retroactive vs. non-retroactive" toggle controlling whether a revoked member retains access to pre-revocation content — that framing directly contradicted Storage Spec §5.4's membership-gated serving requirement, which blocks a revoked member's access to new content and new key material unconditionally, not as a configurable policy.** Under the envelope-encryption model, there is no remaining design choice about *revoked-member* access to make here — §5.4's gate applies regardless of network configuration, which is a stronger and cleaner guarantee than a toggle would have been, not a weaker one. This section is renamed and refocused on the genuine, still-real configurable choice the earlier framing was conflating with revocation: **how much history a brand-new member gets access to.**

As already stated in §3.3: a new member receives the current epoch key on join and can unwrap object key material from the current epoch forward by default — but not necessarily prior epochs' material, which is where a real, still-relevant policy choice lives:

- **Current-epoch-forward only (default):** new members can access content whose key material is wrapped under the current or any subsequent epoch, but not content that was only ever wrapped under epochs that predate their join — appropriate for networks that treat membership as roughly synonymous with "was present for this," and the more conservative default.
- **Full-history opt-in:** a network may instead grant new members access to historical epoch keys as well (e.g. delivered alongside the current epoch key at join, subject to whatever capability governs this), letting them read everything the network has ever published, not just what's been published since they joined — appropriate for networks that want new members to have full context (an archive-style community, for instance).

This should be a policy flag decided at network genesis (changeable later only with the appropriate capability), independent of anything to do with revocation — which, again, is now unconditional and not a per-network configuration choice.

### 3.5 Bootstrapping Trust for Key Distribution

New-member key delivery and epoch-key redistribution both require secure point-to-point channels between the distributing identity (whoever holds the relevant capability) and each recipient, authenticated using the per-network identity keys from §1.2. This is a standard authenticated-key-exchange problem (e.g. X25519 ECDH + signature, similar in spirit to what the earlier prototype attempted) — no new invention needed here, just applying it per-epoch instead of once.

---

## 4. Capability Ledger

### 4.1 Purpose

A single, consistent mechanism by which every node advertises what it is willing to contribute, **per network it belongs to**, that every other subsystem (storage placement, media relay selection, and app-routing/discovery) reads from rather than each building its own resource-negotiation logic.

### 4.2 What Gets Advertised

Per (node, network) pair:

| Field | Description |
|---|---|
| `storage_offered` | Bytes the node will allocate to replicated content for this network |
| `bandwidth_cap` | Throughput limits (up/down), possibly time-of-day scoped |
| `relay_bootstrap_willing` | Will this node help NAT-traverse new peers (circuit relay / DCUtR role) |
| `relay_media_willing` | Will this node act as a blind relay for real-time audio/video (distinct capability — see §4.4) |
| `compute_class` | Coarse hint for app-hosting-adjacent decisions (browser-style app execution happens on the *visitor's* node, per the App Hosting spec, so this is more about relay/storage duty cycling than app scheduling) |

**`reliability_signal` is deliberately absent from this table, and that absence is load-bearing.** An earlier version of this document listed it here as an advertised per-(node, network) field while §4.6 simultaneously specified it as private and never gossiped — a direct contradiction, and one with a real downstream consequence: Storage Spec §3.3's replica placement was deriving its weight partly from it, which would have made a deliberately deterministic, independently-recomputable placement function depend on state no two nodes ever agree on. `reliability_signal` is **local-only observation state, never advertised and never gossiped** (§4.6), so it is not part of the capability ledger's advertised schema at all, and no deterministic, cross-node-recomputed algorithm may take it as an input.

This table is deliberately not fixed forever — the App Hosting and Real-Time specs may extend it — but it should live in one schema, owned by this document, so it doesn't fork into three incompatible resource-description formats.

### 4.3 Why Per-Network, Not Global

A node's willingness to contribute is explicitly scoped per network (confirmed requirement): full participation in a small trusted friend network, relay-only in a massive fandom network, etc. The ledger entry is keyed `(node_id_for_this_network, network_id) → capabilities`, consistent with the unlinkability goal in §1 — a node's contribution profile in one network should not be automatically derivable from its profile in another.

### 4.4 Explicit Distinction: Bootstrap Relay vs. Media Relay

These are two different capabilities with two different jobs, and must not be conflated in implementation:

- **Bootstrap/connection relay** (`relay_bootstrap_willing`): helps two NAT'd peers establish a connection (circuit relay + hole-punch upgrade), then gets out of the way. Short-lived, low continuous bandwidth.
- **Media relay** (`relay_media_willing`): continuously forwards **encrypted** real-time audio/video/stream traffic for the duration of a call or broadcast — a **blind relay**, forwarding ciphertext it cannot decrypt. Sustained bandwidth/latency demands, very different resource profile.

A node may offer one, both, or neither, per network. The Real-Time Transport spec owns the selection algorithm for picking media relays from among willing nodes; this document only owns the fact that willingness is declared here.

### 4.5 Ledger Propagation

The ledger doesn't need a central store — capability advertisements are gossiped among network members (piggybacking on the same peer-discovery/DHT mechanisms in §5) and cached locally by peers who need to make placement/selection decisions (e.g. "which nodes should replicate this content," "which relay should this call use"). Staleness tolerance and refresh cadence are implementation-level tuning, not an architectural decision.

**What "cached locally" implies for the algorithms that read it, stated explicitly because it was previously left to inference.** There is no single authoritative ledger; there are as many ledgers as there are nodes, each converging on the same contents. The deterministic, cross-node-recomputed algorithms that consume it — replica placement (Storage Spec §3.3) and live-stream first-tier assignment (Real-Time Spec §3.3) — are therefore deterministic **given a ledger**, and agree between two nodes only once those two nodes' ledgers agree. This is eventual, not instantaneous, and implementations should not be written or tested as though it were instantaneous.

This does **not** reopen the `reliability_signal` question (§4.6), and the distinction is worth being precise about because the two look superficially similar. `reliability_signal` is per-observer private state that never converges, so a function taking it as an input is permanently non-deterministic across nodes and no amount of propagation fixes it. Advertised capacity is network-visible and converges, so disagreement is a bounded propagation window. A bounded window is tolerable because a remediation path already exists for it (Storage Spec §3.4's repair loop); permanent divergence is not tolerable and has no such path, which is why one is gossiped and the other must never be.

Two practical consequences follow. Refresh cadence should be kept well inside the staleness threshold, so the window in which two nodes hold different views stays short. And an advertisement is only meaningful from a current member, so a node's ledger cannot be validated ahead of its governance log (§2.7) — a node still catching up should expect to reject advertisements it will later accept, and should re-request rather than treating the rejection as final.

### 4.6 Reliability Signal and Auditability

**Passive, opportunistic, essentially free.** Every node already has to verify signatures and content hashes as a mandatory correctness step on data it receives — swarm-served chunks (Storage Spec §1.2), gossiped ballots (§2.6.1), governance log entries (§2.7), relay traffic. `reliability_signal` widens this into a lightweight reputation mechanism at no meaningful additional cost: when verification of something received from a given peer fails, that node increments a local counter for that peer instead of just discarding the bad data and moving on. No new probing, no active health-checking, no new network traffic — purely bookkeeping on top of checks already mandatory for correctness.

**Local, never gossiped.** Each node's `reliability_signal` observations about its peers are private to that node and are never broadcast, advertised in the capability ledger (§4.2), or aggregated network-wide. This is a deliberate choice: a shared, network-wide reputation score would be vulnerable to coordinated slander (a group of colluding nodes tanking a target's score) in a way a private, per-observer signal is not. **This property is not a default to be relaxed for convenience — it must not be reversed**, including to make some downstream algorithm easier to make deterministic (see the constraint below, and Storage Spec §3.3).

**Where it may be used, and where it may not.** `reliability_signal` feeds selection algorithms that are **local, per-node, and have no cross-node consistency requirement** — specifically **swarm-serving source selection** (Storage Spec §4.3) and **media relay selection** (Real-Time Spec §2.3) — deprioritizing a peer this node has personally observed failing verification. It is explicitly a **soft signal for selection only**, never a gate on group membership or capabilities, and never an automated trigger for revocation. Revocation remains a deliberate action by a capability holder (§2.2), never something the protocol does on its own based on a reputation score.

**It must never feed a deterministic, cross-node-recomputed decision** — a correction to an earlier version of this document, which named replica placement (Storage Spec §3.3) among its consumers. Because every node holds different observations, any function taking it as an input produces a different answer on every node; replica placement is required to be identical everywhere (that determinism is the entire reason HRW was chosen over weighted-random), so it now weights only gossiped `storage_offered`. Unreliable nodes are still corrected for in placement, just at a different point: through the replica-repair loop (Storage Spec §3.4), which re-places content away from nodes that fail to hold or serve it, rather than through evidence no two nodes agree on. The same restriction applies to live-stream first-tier assignment (Real-Time Spec §3.3), which reuses the same HRW computation weighted by gossiped `bandwidth_cap` rather than `storage_offered` — a different capacity field for a different role, but the same requirement that every input be network-visible.

**Auditable on demand, by authorized parties, for large-network oversight.** A purely private-by-default signal is of limited use for catching a pattern of bad behavior across a large network, where no single node's view is enough to see the whole picture. A new capability, `audit-reputation` (granted to a group, per the standard model — typically Founders or a Moderators group), allows its holder to send a signed request to a specific node asking it to disclose its local `reliability_signal` observations. The responding node returns its **raw local counters as-is, signed** — no interpretation, no network-wide aggregation computed or stored anywhere — so the requester can independently cross-reference responses from multiple nodes that have interacted with a suspected peer. A consistent pattern of verification failures reported independently by many unrelated observers is meaningfully stronger evidence than any single node's opinion, and is the kind of evidence an admin should have in hand before exercising `revoke-node`.

Responding to a valid, capability-signed audit request is **mandatory but rate-limited**: mandatory, because allowing refusal would let a compromised or malicious node simply decline audits of itself, creating an obvious blind spot; rate-limited, to prevent the audit mechanism itself from being used to harass or overload a specific member with repeated requests.

---

## 5. Discovery & Transport

### 5.1 Recommended Stack

Carried forward from prior prototyping (validated in an earlier implementation attempt, and a reasonable starting point rather than something to relitigate from scratch):

- **libp2p** as the networking substrate.
- **Transports:** TCP and QUIC, both IPv4 and IPv6, with Noise for transport security and Yamux for multiplexing.
- **Kademlia DHT** for WAN peer/content routing at scale.
- **mDNS** for LAN peer discovery — **must not auto-dial** discovered peers; LAN discovery informs address caching only, actual connections still flow through the invite/join authorization path (§2), so LAN visibility never bypasses membership control.
- **Identify + Ping protocols** for peer metadata exchange and liveness.

### 5.2 NAT Traversal — Concrete Connection Sequence

A node attempting to connect to a peer (whether the very first connection during a join, or any later peer connection) follows a strict, ordered sequence, attempting each tier only after the previous one fails:

1. **Direct dial, IPv6 addresses preferred over IPv4.** A node attempts a direct connection first, trying any IPv6 addresses it holds for the target before falling back to IPv4. This ordering matters in practice, not just in principle: two peers who both have real, globally-routable IPv6 addresses typically don't have a NAT problem to solve at all, since IPv6 mostly lacks the address-translation layer that makes IPv4 NAT traversal hard in the first place — direct IPv6 connectivity, when available, sidesteps hole-punching and relaying entirely.
2. **DCUtR hole-punch, negotiated peer-to-peer through a relay.** If direct dial fails, the two peers negotiate a hole-punch upgrade (Direct Connection Upgrade through Relay) using a relay node purely as a rendezvous/signaling point during negotiation — DCUtR is a **client-side-only** behavior; a relay node itself needs no DCUtR support to facilitate this (confirmed against a real implementation: a working relay's behavior set was `relay` + `rendezvous::server` + `identify` + `ping` + `kad`, deliberately with no `dcutr` feature, since that logic runs on the connecting peers, not the relay). If hole-punching succeeds, the connection becomes fully direct and the relay drops out of the data path entirely.
3. **Relay circuit, as the final fallback — a correctness guarantee, not a usable path.** If hole-punching also fails (common with symmetric NAT or certain CGNAT configurations), the connection falls back to a circuit relayed through the relay node. This is the only tier where the relay remains in the ongoing data path — tiers 1 and 2 either don't involve it or only involve it transiently.

   **This tier exists so that a connection is always eventually possible, not so that peers can live on it.** An earlier version of this section described the circuit as "sustained ... for the duration of the session", which contradicted §5.3's ceilings and the whole point of a bootstrap relay: a relay's job is connection-establishment assistance, not data transport (§4.4). The circuit is subject to §5.3's duration and byte ceilings like any other, and hitting them is expected rather than exceptional.

   **Two peers who can never hole-punch are expected to reach each other over IPv6, not over a relay.** This is the direct consequence of tier 1's IPv6-first ordering: a pair behind CGNAT typically cannot traverse IPv4 at all, but globally-routable IPv6 addresses need no traversal in the first place. Tier 3 keeps such a pair *correct* — they are never partitioned — while IPv6 is what makes them *usable*. A deployment that expects CGNAT users to depend on relayed circuits for ordinary traffic has misread this ordering, and will find the ceilings in §5.3 enforcing the point.

This tiered approach — and the fact that dual-stack (IPv4 + IPv6) TCP and QUIC listening plus this exact fallback sequence is achievable in practice — is carried forward directly from a working prior implementation, not a theoretical design.

This is a distinct capability from media relay — see §4.4.

### 5.3 Relay/Bootstrap Node Resource Limits and Identity-Keyed Rate Limiting

Any node offering `relay_bootstrap_willing` (§4.2) — including the network's initial bootstrap node (§5.5) — should enforce concrete resource limits, both to protect itself from abuse and to keep its behavior predictable. Reasonable baseline defaults, validated in a working prior implementation: a cap on total concurrent reservations (e.g. 128), a per-peer reservation cap (e.g. 4), a cap on concurrent relayed circuits (e.g. 32), a maximum circuit duration (e.g. 120 seconds) forcing periodic re-negotiation rather than indefinitely-held circuits, and a maximum bytes-per-circuit ceiling (e.g. 8MB) consistent with a relay's job being connection-establishment assistance, not sustained data transport (that's the separate, distinct media-relay role, §4.4).

**These ceilings are the design, not a throttle to be raised when users complain.** They are what keeps a bootstrap relay cheap enough to be disposable — small enough to run on a free hosting tier, stateless enough to replace (§5.4), and therefore genuinely optional rather than infrastructure the network depends on (§5.5). A relay that carried sessions would acquire exactly the cost, permanence and takedown surface this design exists to avoid. Where the ceilings bite, the answer is a direct connection — over IPv6 for a CGNAT pair (§5.2 tier 3) — or a member node volunteering as an additional relay, never a larger allowance on the hosted one.

**Rate limiting must be keyed by authenticated per-network identity (§1.2), never by bare libp2p peer ID.** A libp2p peer ID is free to regenerate — nothing stops a client from generating a fresh Ed25519 keypair for every connection attempt, which makes any peer-ID-keyed rate limit trivially bypassable and therefore not real protection, only the appearance of it. Per-network identity is meaningfully costlier to regenerate *for an already-admitted member*, since it requires clearing that network's admission process (§2.4) each time — a real cost an attacker can't route around by simply generating new key material. This is a hard requirement for this project's relay/bootstrap implementations, not an optional hardening step: a rate-limiting mechanism that doesn't actually key off something costly to regenerate provides no real protection regardless of how it's otherwise configured.

**This argument has a real gap under explicit-intake admission with a multi-use or bearer invite, and the rate-limiting scheme must account for it.** A waiting-room identity (Core Protocol §2.4) exists *before* admission completes — connecting and generating a per-network identity is, on its own, cheap; it's admission specifically that's costly, and a waiting-room identity by definition hasn't gone through it yet. Under a multi-use or bearer-style invite, an attacker can mint many such pre-admission identities freely, each one technically a distinct "per-network identity" but none of them having paid the cost the rate-limiting argument above actually relies on. To close this: **relay/bootstrap resource limits for connection-establishment activity performed by a not-yet-admitted identity must additionally be scoped per-invite (or per-issuing-context), not solely per-identity** — since the invite itself (or whatever issued it) is the actual scarce, harder-to-regenerate resource in the pre-admission case, not the freely-mintable waiting-room identity. Once an identity completes admission into a real group, ordinary per-identity rate limiting (as described above) applies as normal.

#### 5.3.1 Where Identity-Keyed Metering Can Actually Be Enforced — A Correction

**The two requirements above are stated as applying to every node offering `relay_bootstrap_willing`, including the stateless bootstrap node. That is not achievable, and this section corrects it rather than leaving a requirement standing that a conformant implementation cannot meet.**

Both requirements depend on a check neither states: that the identity or invite being metered is *real*. Per-identity metering rests on admission being costly, which is only true if somebody verifies the identity was admitted. Per-invite metering rests on an invite being scarce, which is only true if somebody verifies its issuer holds `approve-node`. Both are questions about governance state (§2.7), answerable only by replaying the log.

**A bootstrap relay holds no governance state, by deliberate design (§5.4), so it can answer neither.** It can verify an invite's *signature*, since that is self-contained, but not the *authority* behind it — an attacker generates a keypair, self-signs an invite naming it as issuer, and produces a structurally perfect credential. Metering per-invite against unverifiable invites, or per-identity against unverified identities, degrades to exactly the per-connection metering §5.3 above calls "not real protection, only the appearance of it." The paragraph's own reasoning applies to itself.

**The corrected requirement, split by what a node can actually verify:**

- **A stateless bootstrap relay enforces the global ceilings only** — total reservations, concurrent circuits, circuit duration, bytes per circuit. These need no governance state and bound the total resource an attacker can consume, even though they cannot allocate it fairly.
- **A member node offering `relay_bootstrap_willing` enforces per-identity and, for pre-admission activity, per-invite metering as specified above.** It replays the log already, so for it both checks are ordinary work, and the requirement stands unweakened where it is meaningful.

**Why this is an acceptable limit rather than a hole to be closed.** The failure mode is denial of service against a relay, not a compromise of anything: no admission, confidentiality, or key-material property depends on a relay's judgment. A forged invite is refused by the *receiving member* at redemption, against replayed state, which is where invite authority was always meant to be checked (§5.6) — the relay carries bytes and never inspects a join at all. What an attacker can do is exhaust a relay's ceilings and deny **cold start** to nodes that have no cached peers.

That is a cost this design already accepts everywhere else. A bootstrap relay is scaffolding, not infrastructure (§5.5): it holds no state, is never trusted with keys, and an established network does not depend on one. A relay under sustained attack is torn down and replaced, and a network can designate additional entry points — including member relays, where the metering above does apply. **Requiring a relay to hold governance state in order to meter fairly would trade the property that makes relays disposable for protection against an attack whose whole remedy is disposing of the relay.** That trade is refused here deliberately.

An implementation that *chooses* to give a bootstrap relay governance state may do so and gains the stronger metering; it would need the network's genesis entry hash as deployment configuration, since without a pinned root an attacker can present an entirely fabricated log for the same network id and the relay has no basis to prefer the real one. This is permitted, not required, and it is not the reference posture.

### 5.4 Relay Node Operational Recommendations

- **Statelessness is a deliberate design goal for a relay/bootstrap node, not an accident.** A relay's keypair and any in-memory routing/reservation state should be treated as fully disposable between restarts — this keeps the node cheap, replaceable, and consistent with its role as cold-start scaffolding rather than durable infrastructure (§5.5). A relay that persists no state across restarts is trivially interchangeable with any other relay a network designates, which directly reinforces the takedown-resistance goal.
- **Serve health/liveness checks before the node is fully initialized**, returning a placeholder status until setup (e.g. keypair loading, swarm construction) completes, rather than leaving a health endpoint unreachable during startup. This avoids a slow build/boot process being mistaken for a failed deployment by hosting-platform health checks, and is cheap to implement.
- **A relay should expose its own peer ID via some out-of-band, verifiable channel** (e.g. an HTTP endpoint returning its peer ID as JSON) so a client adding that relay as a bootstrap candidate can confirm it's connecting to the specific relay it intends to, not an impersonator — this is a lightweight trust-establishment step worth keeping regardless of hosting platform.
- **Deployment specifics (e.g. a specific low-cost host's networking configuration) are illustrative, not prescriptive** — any hosting approach that can expose a TCP (and ideally UDP, for QUIC) endpoint for libp2p traffic plus a lightweight verification/health channel is suitable; nothing about the protocol depends on any particular host.

### 5.5 Bootstrap Nodes: Scaffolding, Not Dependency

Every network needs *some* way for its very first two nodes to find each other, and for new joiners with no existing peer set to reach the network at all. This is solved with lightweight, cheaply-hosted **bootstrap nodes** (a small always-on relay/rendezvous service, per §5.2–5.4).

Critical architectural requirement, restated as a hard constraint: **bootstrap node dependency must be temporary per node, not permanent for the network.**
- On first join, a node dials a bootstrap node to reach its first peers.
- From that point on, the node caches enough peer addresses (and participates in the DHT) that it does **not** need to re-contact the bootstrap node to reconnect after a restart, as long as at least one previously-known peer is reachable.
- As a network matures, `relay_bootstrap_willing` nodes from the capability ledger (§4) become additional, decentralized entry points — new joiners can be handed a mix of the original bootstrap node and several willing member peers as candidate bootstrap targets, further diluting reliance on any single host over time.
- The bootstrap node should be understood, architecturally, as a **convenience for cold start**, never a component whose downtime prevents an established network from functioning. This is the direct answer to the takedown-resistance goal.

### 5.6 Invites

An invite is a signed, time-bounded, use-count-limited credential that allows a specific identity (or a bearer, depending on network policy) to join. It must carry:
- One or more bootstrap peer addresses (including, on first join, the network's bootstrap node) to dial.
- Enough network metadata (network ID, current epoch key delivery mechanism per §3.5) to complete the join handshake.
- A signature from an identity belonging to a group holding `approve-node` (or, under vote-based policy, a quorum certificate per §2.6.1), so any receiving node can independently verify the invite is legitimate without a central check.
- The issuing identity, retained and attached to the resulting membership record — required for the waiting-room visibility described in §2.4 under explicit-intake networks, and generally useful provenance regardless of admission mode.

The general *shape* of this flow (signed/expiring/use-limited invite → dial bootstrap peers → join handshake) is carried forward from prior prototyping. The *contents* differ from that prototype in one important way: the invite no longer carries a single shared static network key (rejected in §3.2) — instead it triggers the epoch-key delivery handshake in §3.5.

**What using an invite actually grants** is governed entirely by the network's admission-mode policy from §2.4, not by the invite itself: under auto-admit, a successful join immediately places the new identity in `everyone` and triggers epoch key delivery (§3.5) as part of the same step. Under explicit intake, a successful join establishes connectivity and a per-network identity **only** — the node enters the groupless waiting-room state and does **not** receive the epoch key at this stage, since holding the epoch key is equivalent to being able to decrypt network content regardless of group membership, and granting it prematurely would undermine the "essentially nothing" guarantee explicit intake is meant to provide. Epoch key delivery for a waiting-room node happens only once an admin actually admits it into `everyone` (or another group) — at that point it's treated exactly like an ordinary new join for key-delivery purposes.

### 5.7 The Invite's Job Ends at the First Connection — Everything Else Is Ordinary Post-Connection Sync

**Explicit design principle:** an invite's only responsibility is establishing the network's very first authenticated connection between the new node and an existing member (directly, or relayed per §5.2). This is deliberate, not incidental — the invite payload (§5.6) should never carry more than what's strictly required to make that first connection and verify its legitimacy (bootstrap addresses, network ID, signature, issuing identity). Everything else the new node needs — the rest of the peer set, the network's governance state, its capability ledger, any content it will go on to access — is obtained *after* that connection exists, from whichever node(s) it connected to, using mechanisms this document already specifies for ordinary, steady-state operation: none of it is special-cased to the join moment.

Concretely, once the first connection is live, the responding node(s) can push or the new node can pull (implementation detail — the point is these are ordinary protocol operations, not part of the invite/join handshake itself):

- **Further peer addresses**, so the new node can build out its own DHT routing table (§5.1) rather than remaining dependent on the node(s) it first connected through.
- **The governance log** (§2.7), so the new node can independently replay and verify the network's current authorization state rather than trusting any single peer's claim about it.
- **Capability ledger entries** (§4.5), via the same gossip mechanism used at steady state.
- **The epoch key**, if admission mode and current group membership call for it (§5.6 above).

**This is also the honest answer to "how does joining a network automatically show the associated app," without needing a separate mechanism for it.** If a network has registered a well-known/reserved app name (e.g. something like `index`) in its App Hosting name registry (App Hosting Spec §4.3–4.4) pointing at a default in-network application, a Sandbox-style generic client (Core Protocol Spec §0) simply resolves that name through the ordinary name-registry lookup and fetches the resulting app-bundle through ordinary swarm-serving (Storage Spec §4) — immediately after joining, the same as it would resolve and fetch any other named content on that network at any later point. No invite-carried app reference, no special first-join content-delivery path: the invite gets the node connected and admitted, and from there, "show me this network's default app, if it has one" is just an ordinary content lookup like any other. A network with no registered default app, or a Model B-only network with no `app-bundle` content at all, simply has nothing for that lookup to resolve to, and the client falls back accordingly.

---

## 6. Summary: What Other Specs Should Assume From This Document

- Every identity is a per-network-derived keypair off one unlinkable master seed (§1). Additional devices are independently seeded and linked via per-network certificates rather than ever holding the master seed themselves — a lost/stolen device is revoked by invalidating its certificate (no identity rotation needed) plus, if it may have cached decryption material, a self-initiated epoch rekey request (§1.3).
- Every authorization decision — node approval, revocation, content moderation, app publishing, whatever comes next — is a query against the group/capability/policy system in §2, not a bespoke role check. Capabilities are only ever held by groups (never individuals), groups are flat (no nesting), and group *definition* (§2.2, `define-group`) is deliberately higher-bar than group *membership management* (`manage-membership:<group>`) — this asymmetry is the structural guard against permission sprawl.
- Every network has two implicit groups: `Founders` (all capabilities, §2.3) and `everyone` (baseline membership for ordinary joiners, §2.4). `everyone`'s capabilities are network-configurable, but `everyone` may never hold any capability tagged **governance-tier** (§2.2, §2.4) — a class-based invariant, not a hardcoded list, so capabilities introduced later by consuming specs are automatically covered. `manage-membership:<group>` is governance-tier specifically when its target group holds governance-tier power, checked dynamically against replayed governance state.
- New-member admission is a network-wide setting, not an invite-level one: **auto-admit** (join → immediate `everyone` membership + epoch key) or **explicit intake** (join → groupless, keyless waiting-room state, visible to admins with issuer context, until manually admitted) — §2.4, §5.6. **Admission mode and governance policy are independent settings with one incompatible pairing**: member-vote (§2.6) cannot be combined with auto-admit, since one grants admission automatically and the other requires a quorum to decide it, and the combination must be refused where policy is set rather than where a joiner is turned away. Member-vote also cannot be a genesis-time choice, because its first admission would need a quorum of an electorate that does not exist yet — a network switches to it once it has a founding electorate.
- **A member's MLS group state must survive a restart** (§3.3.1). Holding the current epoch key is not the same as holding the group: a member that kept only the key can still read and can no longer rotate, welcome or revoke, so a restarted founder can never key anybody in and §3.1's revocation guarantee quietly becomes unavailable to the network. Consuming specs may assume a conformant member can be restarted; they should not assume the serialised state is portable between implementations, since it is private, never on a wire, and secret enough that storing it unsealed gives away the network.
- Membership-removal cascade defaults to non-cascading (§2.5), with an explicit, scoped opt-in for cascading removal — consuming specs should not assume removing someone automatically unwinds everything they did.
- Vote-based governance policy (§2.6.1) is decided by **quorum certificate existence**, not by each node's local ballot computation (which can diverge near the close boundary) — absence of a valid certificate at close time means the vote fails, fail-closed. The electorate can be `everyone` (direct) or a smaller designated group (representative); per-member delegate assignment (liquid democracy) is explicitly out of scope.
- Every network maintains a hash-chained governance log (§2.7) recording every membership, capability, group, policy, **moderation** (`ModerationEntry`, §2.7 — the concrete record behind "delisted," which Storage §2.5, Search §3.1/§6.1 and App Hosting §3.4 all resolve by replay rather than by any separate store), and epoch-rotation action — this is the network's decentralized "policy engine": any node can independently recompute current authorization state by replaying it. Concurrent/conflicting entries are resolved by an explicit fork-choice rule (§2.7.1: deterministic sibling tie-break; longest-branch reconciliation for deeper partitions, measured **only by capability-gated actions** — device-certificate entries don't count toward branch length, closing a free-grinding exploit) — entries unique to a losing branch are voided outright, not partially applied, with a **mandatory voided-actions report** so resubmission (especially of a voided revocation) is a defined, automatable client step, not something depending on someone noticing. **Reorg depth/age is bounded, and both bounds must be met**: a branch is final once it is buried under **k = 10 capability-gated governance actions** *and* is at least **T = 30 minutes** old (§2.7.1 — starting defaults, explicitly tunable, but concrete rather than abstract so downstream mechanisms can actually be built and tested against them). Past that point a branch can no longer be displaced, which is what gives MLS state a concrete point at which it's safe to stop retaining superseded epoch secrets (§3.3).
- A network's policy may carry **application-layer values** (§2.6.2): namespaced keys the protocol stores, orders, encodes and hash-covers **without interpreting**. This is how a consuming spec gets a setting every node must agree on — a validity rule such as a flood ceiling — without the platform acquiring fields shaped around one application. Absent means the consuming spec's default, unlike the capability registry where absent means refused.
- The log also carries **application-layer entries** (§2.7.2): namespace, kind, a declared capability and an opaque payload, which the protocol orders, hash-covers and authorizes without decoding. This is how a consuming spec gets durable ordered structure — which an append-set cannot provide, since its entries lapse — without the log acquiring that spec's record types. They do **not** count toward branch length, because whether one is cheap to mint depends on a tier the metric cannot resolve.
- Every network also maintains a governance-configured, protocol-enforced **content-type allowlist** (§2.8): any publish must declare a `content_type`, and publishes outside the network's current allowlist are rejected outright. This is what lets a network stay meaningfully scoped to a specific purpose (e.g. a chat-style network excluding `app-bundle` entirely). A **second, independent gate**, the parametrized `publish:<content_type>` capability, governs which specific groups may publish an allowed type — a type being on the allowlist does not itself grant publish rights; consuming specs (Storage, App Hosting) must check both gates, not just the allowlist.
- Group encryption uses MLS/TreeKEM (§3.3), not pairwise rekeying, giving O(log n) rekey cost — required at this project's target scale. **The epoch key wraps small per-object key material (envelope encryption); it does not directly encrypt content** — this is what makes rotation cheap. Members must **tentatively retain superseded-epoch MLS secrets until the corresponding rotation reaches finality** (§2.7.1's bounded reorg depth), enabling re-welcome if a tentative rotation is later voided. **Revocation's guarantee is now unconditional, not a per-network policy toggle**: a revoked member cannot obtain anything wrapped/served for the first time after removal, enforced regardless of network configuration — but *cannot* be made to un-know a key or forget content they already legitimately decrypted before removal. §3.4 (renamed from the earlier "retroactive opt-out" framing, which contradicted this) now covers a genuinely separate, still-configurable choice: how much *history* a brand-new member gets access to. Storage Spec §5 owns the concrete envelope-encryption mechanics this guarantee depends on, including a `read-content`-gated content-serving requirement (§2.2) that closes a residual gap DEK reuse would otherwise leave open.
- Any subsystem that needs to know what a node is willing to contribute reads from the capability ledger (§4) — don't invent a parallel resource-declaration mechanism. The ledger is a **per-node converging cache, not a shared authority** (§4.5): algorithms over it are deterministic given a ledger, and agree between nodes once their ledgers agree rather than instantaneously. `reliability_signal` (§4.6) is a locally-observed, opportunistic reputation signal derived from mandatory verification checks the protocol already performs. It is **local-only and never gossiped or advertised** (not "by default" — this is not relaxable), and consequently may feed **only local, per-node selection decisions** with no cross-node consistency requirement: swarm source selection (Storage Spec §4.3) and media relay selection (Real-Time Spec §2.3). It **must never be an input to a deterministic, cross-node-recomputed algorithm** — notably replica placement (Storage Spec §3.3) and live-stream first-tier assignment (Real-Time Spec §3.3), which weight gossiped capacity only, since a function fed by per-observer-private state cannot produce the identical result on every node that those mechanisms require. It never gates membership or capabilities and never triggers automated revocation. It's disclosable on demand to `audit-reputation` holders for large-network oversight, mandatory-but-rate-limited to respond.
- Connectivity is libp2p-based with a clear separation between transient NAT-traversal relaying and sustained media relaying (§4.4, §5.2). **Tier 3 is a correctness guarantee, not a path to live on**: a bootstrap relay establishes connections and gets out of the way, its circuits are capped (§5.3), and a pair that can never hole-punch — two behind CGNAT — is expected to reach each other over IPv6 rather than over a relay — these are different node roles even when the same physical node fills both. **Unlinkability requires a distinct libp2p PeerId per network** (§1.2), derived the same way as the per-network identity keypair — key-level unlinkability alone is void if the transport layer reuses one fingerprint everywhere. IP-level/timing correlation remains explicitly out of scope, stated honestly rather than silently assumed away.
- Relay/bootstrap rate limiting must key off authenticated per-network identity, never bare peer ID (§5.3) — but under explicit-intake admission with a multi-use/bearer invite, pre-admission identities are cheap to mint, so pre-admission connection activity must additionally be scoped per-invite, not solely per-identity. **Both requirements apply only where they can be verified, which means at a member node, not at a stateless bootstrap relay (§5.3.1).** Verifying that an identity was admitted, or that an invite's issuer holds `approve-node`, is a governance-state question, and a bootstrap relay deliberately holds no governance state (§5.4) — so it enforces the global ceilings only. Consuming specs should not assume a bootstrap relay meters fairly, and should not treat that as a gap: the failure mode is denial of cold start, no security property depends on a relay's judgment, and a relay under attack is replaced rather than hardened (§5.5).
- Bootstrap nodes are cold-start scaffolding only; no other component may assume one is reachable during steady-state operation (§5.5).
- An invite's payload carries only what's needed for the very first authenticated connection — nothing more (§5.7). Every other consequence of joining (peer discovery, governance log replay, capability ledger sync, epoch key delivery, and — if applicable — auto-resolving a network's default in-network app) is ordinary post-connection use of mechanisms this document already specifies, not special-cased join-time machinery. Consuming specs should not assume the invite itself carries anything beyond connection bootstrap data.

---

## 7. Explicitly Open Questions (flagged, not resolved, in this document)

None remaining at the architectural level.

**Previously open, now resolved:** concrete values for the bounded-finality reorg depth **k** and age threshold **T** (§2.7.1). These are now stated directly in §2.7.1 as **k = 10 capability-gated governance actions and T = 30 minutes, both required**. They remain explicitly tunable starting defaults, expected to be revised once the harness (Reference Test Harness Spec §2–3) produces realistic gossip-propagation and partition-duration data — but they are no longer an open architectural question, and implementation should proceed against these values rather than treating the threshold as undecided. Leaving them abstract was itself blocking: MLS secret retention (§3.3) and the harness's partition-with-competing-rotations test both need a concrete threshold to be implementable at all.

All other items originally flagged in this document (capability revocation cascade, member-vote quorum, group-rekeying primitive, multi-device identity linking) have been resolved in the sections above, along with several further corrections surfaced by subsequent review passes (the class-based `everyone` denylist, the `read-content` capability, the fork-choice grinding-attack fix, MLS state retention, the corrected unconditional framing of the revocation guarantee, the `ModerationEntry` record type §2.7, and the removal of local-only `reliability_signal` from all deterministic cross-node computations §4.2/§4.6). This document's interfaces should be treated as stable for the remaining specs and for implementation planning.
