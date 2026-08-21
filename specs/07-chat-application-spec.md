# Chat Application Specification

**Project:** Distributed Intranet
**Document status:** v0.1 — draft. A reference implementation is in progress (`ko-ls`); where the two differ, this document is normative and the divergence is recorded in the implementation.
**Depends on:** Core Protocol Spec (identity, governance, epoch keying, capability ledger, transport), Storage & Replication Spec (mutable pointers, append-sets, swarm serving, envelope encryption), Real-Time Transport Spec (calls, streams), Search & Indexing Spec (postings)
**Consumed by:** nothing yet — this is a leaf

---

## 0. Purpose and Scope

This is the first **application-layer** specification on this platform, and it does two
jobs that are worth separating before anything else:

1. It specifies a chat application — channels, messages, ordering, moderation, keying —
   as a consumer of the platform, in the manner Core Protocol Spec §0 anticipates for
   "native client applications" that use the protocol as a backend.
2. It specifies the **amendments to the platform** that application requires. Those are
   listed in §7 and are not optional reading: three of them change types the core specs
   own, and one is a correction to a mechanism that cannot express what a consuming spec
   needs.

**Why the second job belongs here rather than in a commit message.** This repository's
central claim is that the specs are authoritative and the code implements them. Adding
governance entry types, a capability vocabulary and two wire protocols in code alone would
make that claim false. Where this document requires a change to a core spec, it says so
explicitly and names the section.

Out of scope: client architecture, user interface, and packaging — the reference client
keeps those in its own design set. Also out of scope, permanently: anything cross-network.
A chat application inherits Core §1.2's unlinkability whole, so there is no global
identity, no cross-network conversation, and no directory of networks.

---

## 1. Networks, Profiles and Channels

### 1.1 A "server" is a network

One network per community: one governance log, one membership, one epoch key chain, one
DHT namespace, one search index. Roles are groups (Core §2.1), permissions are
capabilities (§4), bans are `revoke-node` with the epoch rotation that implies (Core §3.3),
and membership screening is the explicit-intake waiting room (Core §2.4). Nothing in this
document reimplements any of those.

### 1.2 Network profiles — `server` and `conversation`

**Decided: a network declares, at genesis, which of two shapes it is**, recorded as
`chat:network-profile` in the app-layer policy map (§7, E9) and therefore part of replayed
state:

| | `server` | `conversation` |
|---|---|---|
| Channels | Many, in categories | **Exactly one, implied** — never declared |
| Channel id | Per `ChannelDefinition` (§1.3) | Derived from the network id (§3.6) |
| Roles | Groups with capability sets | None beyond the implicit two |
| Membership | `Founders`, others, `everyone` | Every participant is a `Founder` (§1.5) |
| `app-bundle` | An allowlist choice | Never allowed |

**A channel entry in a `conversation`-profile network is invalid and MUST be rejected**,
by every reader that understands the `chat` namespace. The profile lives in replayed policy
state (Core §2.6.2), so every such reader reaches the same verdict.

**Honest scope, changed by E2's generalised form.** The rejection is an application-layer
rule, not a protocol-layer one: the protocol carries `chat`-namespace payloads without
decoding them, so it cannot enforce this and does not claim to. What that costs is bounded
— minting the entry still requires the declared capability, and every conformant client
refuses it — but a client that ignored the profile would see a channel where others see
none. This document previously said "rejected on replay" without qualifying whose replay,
which read as a stronger guarantee than any generic mechanism can offer.

A network with no profile declared is treated as `server`. That is the safe reading: it
permits channel entries rather than retroactively invalidating history a node legitimately
holds.

This is not permanence. A network's founders can change policy, and a conversation
deliberately reconfigured into a server becomes one. The profile declares what a network is
for and is enforced while it holds.

### 1.3 Channel definitions are governance-log anchored

A channel is defined by a governance log entry (§7, E2) — specifically an **application
entry** in the `chat` namespace (Core §2.7.2), not by an append-set. This follows
App Hosting Spec §4.3's correction exactly, for the same two reasons: an append-set has no
trustworthy ordering, so "who named this channel first" could be backdated; and its entries
lapse when unrefreshed, so a channel would silently vanish while its creator was offline.

```
ChannelDefinition { channel_id, name, category, kind, privacy, topic, slowmode }
```

Renames, re-categorisation, archival and deletion are further entries against the same
`channel_id`; current state is what replay produces.

**Two consequences of the generic form, both of which a client must handle.** The protocol
authorizes the capability an entry *declares*, so a reader must additionally check that a
`chat`-namespace entry declared the capability this document requires for its kind — the
mapping is fixed in §3.8 — and refuse it otherwise. Note what the check is *not*: the
protocol has already verified the author holds what the entry declared, so this is not a
second authorization pass. It closes the gap between holding *some* capability and holding
the *right* one, which a generic carrier cannot know. And application
entries do not count toward branch length (Core §2.7.2), so a partition may void channel
structure that a competing branch did not see; clients resubmit from the voided-actions
report, exactly as for any other voided action. A best-effort append-set at
`collection_id(network, "chat:channels")` mirrors every definition purely so a client can
enumerate channels without walking the log — it is never authoritative, and if it disagrees
with replay, replay wins.

### 1.4 Threads are derived, not declared

A thread's channel id is `H(domain ‖ parent_channel_id ‖ root_message_id)` (§3.6). It
inherits the parent's privacy, keying and permissions, and **writes nothing to the
governance log** — the first reply creates it implicitly. This is deliberate: a busy
network must not append a governance entry every time somebody replies in a side
conversation, since the log is replayed by every joiner and never shrinks.

### 1.5 Direct messages are their own networks

**Decided: a direct message conversation is a separate `conversation`-profile network**,
not a private channel inside a shared one. Three consequences, each of which is the reason:

- **Storage.** A private channel's messages replicate across whichever members offered
  storage — encrypted, unreadable to them, and still occupying their disks. A two-person
  network has exactly two eligible holders (Storage §3.2 degrades to as many nodes as
  exist), so the conversation is stored by the people having it.
- **Shared state.** No definitions, rosters or rotations enter a log every member of some
  larger network replays forever. A 500-member network has over 120,000 possible pairs;
  each writing structural entries into a shared log would dominate its growth.
- **Metadata.** Members of a shared network cannot see that a conversation exists.

Starting one requires delivering an invite to somebody reachable only inside a shared
network. That uses the direct protocol in §6.2 and a **voluntary identity link** (Core
§1.2's signed statement of common ownership), which is that mechanism's first real use.
Delivery requires both parties reachable; an undelivered request retries from the sender
and rests in no inbox, because an inbox would put the request back on other people's nodes.

**Honest limit on delivery generally:** a two-person network has two replica holders, so a
message reaches its recipient at the next overlap of the two nodes being online — not
necessarily at the next time the recipient opens their client. Sending does not require the
recipient present; *delivery* requires the sender reachable when the recipient returns.

---

## 2. The Message Model

### 2.1 Neither storage primitive fits a channel, and why

A **mutable pointer** (Storage §2.2) is single-writer by construction; a channel has many
writers. A **distributed append-set** (Storage §2.5) is multi-writer, but its entries lapse
when unrefreshed — and that document warns explicitly against relying on it "for anything
where losing an entry due to the publisher's node being offline would itself be a problem".
A message disappearing because its author took a holiday is exactly that.

**Decided: a channel is not one object. It is a set of single-writer logs that readers
merge.** Every property below follows from that one decision.

### 2.2 Author logs and segments

For each (channel, author) there is one **author log**: a chain of immutable **segment**
objects behind one mutable pointer.

```
Segment { channel_id, author, sequence, previous_segment: Option<Cid>, records: [Record] }
```

A segment is ordinary content (Storage §1): plaintext-chunked with CDC, each chunk
encrypted deterministically under the object's own DEK, content-addressed. Appending a
record republishes the *same object* under the *same* DEK, so every chunk before the change
re-derives to an identical CID and readers delta-fetch only the tail.

**Segments rather than one ever-growing object**, for three reasons, of which the third is
decisive: re-chunking cost grows with object size; manifests grow without bound; and
retention (§2.8) must be able to drop old history, which means old history must be separate
objects with separate DEKs. A single object cannot be partially forgotten.

Sealing thresholds (size, age) are **local publishing tuning**, not validity rules. The one
network-wide bound is `chat:segment-max-bytes` (§4.4), enforced by readers, so no author
can compel every reader to fetch an arbitrarily large object.

### 2.3 Pointer ids are derived

`pointer_id = H(domain ‖ channel_id ‖ author_id)` (§3.6), `owner_identity` is the author,
`content_type` is `chat-log`. Both publish gates apply (Core §2.8), which yields a useful
behaviour for free: removing `publish:chat-log` from an identity **freezes** their existing
logs — readable and servable, closed to new versions — which is what a timeout wants.

Derivation, rather than a random id plus a registry, is what gives channel reading an
authoritative enumeration path: for each member in replayed state, compute the pointer id
and ask for it. No index need be fresh or complete for that to work.

### 2.4 Participant discovery is an accelerator, never the authority

An append-set at `collection_id(network, "chat:authors:" ‖ hex(channel_id))` lets an author
announce having posted in a channel, so a reader need not walk the whole roster. It is
best-effort by construction, and **that is acceptable here only because §2.3's derivation
provides a complete fallback** — a stale or missing entry costs a slower first load, never a
lost message. A consuming design without such a fallback must not use an append-set this
way (Storage §2.5).

### 2.5 Records

```
Record = Message { body, reply_to, attachments } | Edit { target, body } | Tombstone { target }
       | Reaction { target, key, remove } | Pin { target, remove }
       | Redaction { target, governance_head }        — moderation logs only
```

Each carries `channel`, `author`, `device`, `hlc` and a **signature over all of it**.
Individual signatures are redundant for the durable path, where the pointer authenticates
the segment transitively — and are not redundant for the live path (§6.1), which delivers
records before any segment containing them exists.

The payoff is an invariant this document depends on throughout: **a record delivered live
and the same record read from a segment months later are byte-identical and independently
verifiable.** The live path may therefore be lossy, reordered or absent without changing
what any reader converges on.

Attachments are ordinary content objects referenced by CID, never embedded in segments — a
large file inside a segment would drag its whole chain into every reader's delta-fetch.

### 2.6 Ordering

Each record carries a hybrid logical clock, `(wall_millis, counter)`, advanced against the
highest reading its author has observed in that channel. Merge order is `wall_millis`, then
`counter`, then **ascending record hash** — the same lower-hash tie-break Core §2.7.1 uses
for sibling entries and Storage §2.2 for pointer collisions. No new rule.

What this delivers, precisely: an author's own records are exactly ordered; causality that
was actually observed is preserved regardless of skew; and genuinely concurrent records get
an arbitrary order every node agrees on and no author can bias by lying about the time.

**Readings strictly increase per (author, device, channel) — per device, not per author.**
One device knows its own last reading and can advance past it. Two devices of one identity,
writing concurrently, cannot without a lock across machines, and a merged segment (§2.9)
necessarily interleaves them. Cross-device ties break by record id.

**Clock-skew defence:** a record more than `chat:max-future-skew-millis` ahead of the
receiver's clock is **held, not dropped** — rendered once local time reaches it. An author
who spaces claimed timestamps to evade a rate limit therefore receives exactly the pacing
they claimed. A record far in the past is admitted and sorts where it claims; it cannot
displace history, because rendering is a function of the record set rather than of arrival.

**Honest limit:** without a central sequencer, no system can establish a true order between
two people typing at once. Systems that appear to are trusting a server's clock.

### 2.7 Edits, withdrawal and redaction

Three distinct actions, deliberately not collapsed:

- **An author edits or withdraws their own message** with an `Edit` or `Tombstone` in their
  own log. Self-service is structural — nobody else can write that log.
- **A moderator hides somebody else's message** with a `Redaction` in the moderator's own
  log (`content_type: chat-moderation`), carrying the governance head observed. A reader
  honours it if, as of that head, its author held moderation authority for the channel.
  This is durable (a pointer, not a lapsing append-set) and puts nothing per-message into
  the governance log.
- **A moderator removes an entire log** with a `ModerationEntry` (Core §2.7) delisting the
  pointer. The heavy instrument: it removes everything that author wrote in that channel.

**Authorship MUST be re-checked where an effect is applied, not only at admission.** An
impostor's `Edit` of another member's message is validly signed by a genuine member, so it
is legitimately admitted to the record set — and must then be ignored. One check keeps the
record set honest; the other keeps the rendering honest; neither alone suffices.

**Honest limit:** redaction and withdrawal cause conformant clients to stop displaying a
message. Neither retracts bytes anyone already holds, and no client can be made to. This is
the same floor Core §3.1 states for revocation and Real-Time §4.2 for VOD opt-out.

### 2.8 Retention and history are two orthogonal settings

- **Retention** (app-layer network policy): `Forever`, or a window of days. A window is
  enforced by ceasing to re-wrap old segments' DEKs on rotation — Storage §5.2 already
  specifies that unwrapped content goes dark, so retention needs no new mechanism.
- **Joiner access** (Core §3.4): `CurrentEpochForward` or `Full`.

Every history model a network might want is a combination of the two: `Forever` plus full
history; `Forever` plus join-forward; or a rolling window whose remaining history is fully
visible to joiners.

**Two windows, not one:** `chat:retain-messages-days` and `chat:retain-attachments-days`,
both defaulting to `Forever`. Text and attachments differ in cost by orders of magnitude —
a message is bounded at 8 KiB by `chat:message-max-bytes` and its flow is capped by §4.3's
rate limits, while one attachment may be 25 MiB with ten to a message — so a single shared
window is necessarily wrong for one of them, and a network bounding what it spends on other
members' disks nearly always means the attachments.

**A window is judged on a segment's newest record, not its oldest.** A segment somebody is
still appending to is live however far back it reaches, and retiring it because its first
message is old would drop an active conversation.

**Encoding, and the sentinel rule, which is normative because disagreement about it forks
history.** Both keys are ordinary app-layer policy values (Core §2.6.2) carrying a signed
day count. A key that is **absent, zero, negative, or too large to represent a day count
MUST read as `Forever`.** Two clients disagreeing about whether `0` means "expire
immediately" or "keep everything" would render different history from the same records,
which is the divergence §4.3 exists to prevent — and the fail-safe direction is forced
rather than chosen: retention can be switched on whenever a network decides it wants it,
and content already allowed to go dark cannot be brought back. A value that arrived
corrupted, or from a client with a different idea of the key, must not quietly start
discarding a network's history.

**`Forever` is the shipped default for both**, for that same asymmetry: a network that
never thinks about the setting keeps its history rather than silently losing what it
assumed it had.

**Retiring a superseded epoch key follows from retention rather than being its own
setting.** A key becomes droppable once nothing still inside the window is wrapped under
it, which the re-wrap-on-read path arranges. A separate key-lifetime knob could contradict
the window — keep content a year, drop its key at six months — and make retained content
silently unreadable.

**Honest limit:** retention is not deletion. A member who already fetched an old segment
and its DEK keeps both, permanently. And a reader reaching a segment it can no longer
unwrap MUST NOT report it as deleted: a retired segment, a wrapping under an epoch this
node has not caught up to, and history that simply has not arrived yet are
indistinguishable, and a client claiming otherwise asserts what it cannot know.

### 2.9 Concurrent versions of one log

Two devices of one identity can publish the same author log concurrently. Storage §2.2
settles which pointer record is canonical and states plainly that it supplies **no
content-merge semantics**, deferring to the application layer. This document supplies them:

**The losing side adopts the canonical pointer and republishes the union of both record
sets at the next version. Nothing is discarded.** Merging is a union by record id followed
by a sort — a segment is a set of independently signed, content-addressed records, not a
document, so there is no field-level conflict to invent a rule for. Discarding the loser's
records would be the one unacceptable outcome, since their author published validly and has
no way to learn they lost except by being told.

The canonical chunk set is recomputed locally rather than fetched: chunk encryption is
deterministic per (chunk, DEK), so re-encoding the canonical segment reproduces its chunks
exactly.

---

## 3. Canonical Encoding

**Normative.** Three things are functions of exact bytes: a record's id is their hash,
signatures verify against them, and the merge tie-break compares them. A one-byte
disagreement produces two ids for one message and references that silently fail to resolve.

### 3.1 Inherited rules

`Enc`/`Dec` as specified for every other type in this project: domain-separated, big-endian
fixed-width integers, `u64`-length-prefixed variable fields, discriminant before payload,
tagged options, deterministic sequence order. No floating point, no hash-ordered
collections, no clock read during encoding.

### 3.2 Domain tags

`intranet.chat-record.v1`, `intranet.chat-segment.v1`, `intranet.chat-channel-entry.v1`,
`intranet.chat-name-claim.v1`,
`intranet.chat-channel-id.v1`,
`intranet.chat-conversation-id.v1`, `intranet.chat-thread-id.v1`,
`intranet.chat-log-pointer.v1`, `intranet.chat-moderation-pointer.v1`,
`intranet.chat-channel-key.v1`, `intranet.chat-topic.v1`,
`intranet.wire.chat-live.v1`, `intranet.wire.chat-dm-invite.v1`.

A tag is permanent. Changing what one covers means a new tag at an incremented version.

### 3.3 Record header and kinds

```
domain ‖ channel_id(32) ‖ author(32) ‖ device(32) ‖ hlc(12) ‖ kind(1) ‖ body
```

`network_id` is **deliberately absent**: every channel id is derived from it (§3.6), so a
record already cannot be replayed into another network, and carrying it would restate a
fixed fact in every record. `device` is **present from v1** despite v1 implementations
shipping single-device, because adding an authenticated field later means two encodings
supported forever.

| Range | Class | Counted against |
|---|---|---|
| `0x01`–`0x3F` | message | `chat:message-rate-per-minute` |
| `0x40`–`0x7F` | reaction | `chat:reaction-rate-per-minute` |
| `0x80`–`0xBF` | control | Neither; capability-governed |
| `0xC0`–`0xFF` | reserved | Refused |

Allocated: `0x01` Message, `0x02` Edit, `0x03` Tombstone, `0x40` Reaction, `0x41` Pin,
`0x80` Redaction.

**The discriminant range carries the rate class, and this is load-bearing.** Rate ceilings
are validity rules (§4.4), so every node must count the same records — including nodes
predating a kind introduced later. Because class is a function of the tag's numeric range
alone, an old node counts a new kind correctly without understanding it. Had class been a
property of a variant's meaning, two implementations would reach different validity
verdicts on the same records.

### 3.4 The record id

`message_id = H(header ‖ body ‖ signature)` — signature included, matching
`AppendSetEntry::entry_id`. The id therefore commits to the exact bytes delivered rather
than to equal field values. Ed25519 is deterministic (RFC 8032), so this is stable.

### 3.5 Segments, and the one framing exception

```
domain ‖ channel_id(32) ‖ author(32) ‖ sequence(8) ‖ previous(1|33) ‖ record* 
```

Each record is embedded as its complete canonical bytes, signature included, so a segment
is self-verifying and any record re-emits byte-identically.

**The record list carries no count prefix. This is the only place this project departs from
its own framing rule, and the reason is measured rather than argued.** A count sits at the
head of the encoding and changes on every append, giving the first chunk a new CID every
time anybody sends a message — one whole chunk re-fetched by every reader, per message,
forever. With a count, appending one message to a full segment moved 51,405 bytes of
176,123. Without it: **1,556 of 176,115, one new chunk of eight.**

Framing stays injective: every record is already length-prefixed and the list runs to end of
input, with nothing following it to absorb bytes. Everything ahead of the list is
fixed-width, so an append changes only the tail.

**A segment carries no signature of its own.** Its authenticity comes from the pointer
naming its CID and from every record's own signature. A third signature over the same facts
would create a state where signers disagree with no rule saying which wins — the reasoning
`ModerationEntry` already gives for not carrying one inside a `LogEntry`.

**A record must belong to the segment carrying it:** verification MUST check that each
record's `channel` and `author` match the segment's. Otherwise a validly-signed record could
be lifted from one author's log into another's, carrying an authorship the pointer's owner
never had — and its signature stays genuine throughout, so signature checking alone does not
catch it.

### 3.6 Derived identifiers

Each is `H(domain ‖ inputs)`, domain-separated so none can be confused for another: channel
id (network id, nonce), conversation channel id (network id), thread channel id (parent,
root message), author log pointer (channel, author), moderation log pointer (channel,
moderator), gossip topic (channel). Collection ids use Storage §2.5's existing helper.

### 3.7 Evolution

A new kind takes the next discriminant **within its correct class range**; retired
discriminants are never reused. A changed shape is a new discriminant, or a new domain tag
at `.v2` with `.v1` decodable forever.

**An unknown kind is retained, counted by class, and not rendered** — not rejected, and not
dropped. Rejecting would make an old node refuse a segment over one new record beside valid
ones; dropping would let a node serve something different from what it received. Retention
keeps the record set, the ids and the ordering identical everywhere and confines the
difference to what each implementation *displays*. That is a presentation difference between
versions, not a consistency failure, and it is the only such difference this document
accepts.

---

### 3.8 Channel entry payloads

§1.3 puts channel structure in the governance log as application entries (Core §2.7.2), which carry `namespace`, `kind`, a declared `required` capability, and an opaque payload. This section fixes those bytes. It is normative for the same reason §3.3 is: replay must produce identical channel state on every node, and the entry's hash covers the payload.

```
domain ‖ channel_id(32) ‖ kind(1) ‖ body
```

The header mirrors §3.3's deliberately. `network_id` is absent for the same reason: a channel id is derived from it (§3.6), so an entry cannot be replayed into another network. The `channel_id` is inside the signed payload rather than only in the entry's envelope so that it is covered by the entry hash and cannot be edited by anything that relays the entry.

| `kind` (1) | `kind` string | Body | Required capability |
|---|---|---|---|
| `0x01` | `channel-definition` | `name ‖ category(1\|33) ‖ channel_kind(1) ‖ privacy(1) ‖ topic ‖ slowmode(4)` | `chat:create-channel:<scope>` |
| `0x02` | `channel-update` | `change(1) ‖ change_body` | `chat:manage-channel:<scope>` |
| `0x03` | `channel-membership` | `action(1) ‖ identity(32)` | `chat:manage-channel:<scope>` |
| `0x04` | `channel-rotation` | `commit_ref(32) ‖ reason` | `chat:manage-channel:<scope>` |

`channel_kind` is `0x01` Text, `0x02` Voice, `0x03` Stage. `privacy` is `0x01` Public, `0x02` Private. `action` is `0x01` Add, `0x02` Remove. `change` is `0x01` Rename (`name`), `0x02` Recategorise (`category(1|33)`), `0x03` SetTopic (`topic`), `0x04` SetSlowmode (`slowmode(4)`), `0x05` Archive, `0x06` Delete. Unallocated discriminants in any of these positions are **refused**, not ignored: unlike a record kind (§3.7), a channel entry carries structure a reader either applies correctly or must not apply at all, and silently skipping one would leave two nodes with different channel state.

**Creating is ordinary, changing is governance, and the split is deliberate.** `chat:create-channel` is Ordinary (§4.1) because a definition grants nobody access to anything — a new private channel has an empty roster until a separate `channel-membership` entry adds someone, and that entry requires the governance-tier capability. The tiering follows what an action can actually widen, not how consequential it sounds.

**A reader MUST check the declared capability matches this table**, refusing the entry otherwise. The protocol verified the author held what the entry *declared*; only a reader that understands `chat` knows what it *should* have declared. Without this check an author holding any registered `chat` capability — `chat:post:*`, the most ordinary grant a network issues — could mint channel structure by declaring that instead.

**A reader MUST also check the scope** the declared capability names: it must be the channel's own scope or the category the definition places it in. A capability for one channel must not authorize an entry against another, which exact-name matching gives directly (Core §2.2, and see §7 E11 on why the names are exact today).

**Every check in this section is application-layer.** The protocol carries these payloads without decoding them, so a client that skipped these checks would accept structure every conformant client refuses — the same honest limit §1.2 states for the profile rule, and for the same reason.

### 3.9 Member name claim payloads

A member's display name is a `chat` application entry, `kind` string `member-name`, discriminant `0x10`.

```
domain ‖ name
```

**The payload carries no identity, and that is the security property.** A claim binds the
identity that authored the entry, which the protocol has already verified. There is no field
in which to name somebody else, so claiming a name on another member's behalf is not refused —
it is unsayable. This is the same structural move §3.8 makes by putting the channel id inside
the signed payload rather than trusting an envelope.

**Why the governance log rather than a profile object.** A member's avatar and status live in
a mutable pointer they own, and a name could have too — except that uniqueness is a question
about the whole network at a moment in time, and a single-writer object cannot answer it. Two
members publishing the same name to their own pointers produces two nodes that disagree about
who is who, with nothing to settle it. Ordering is what makes uniqueness decidable, and the
log is what has ordering. This is the conclusion App Hosting §4.3 reached for app names and
§1.3 reached for channels, for the third time.

#### 3.9.1 Normalization

Uniqueness compares **normalized** forms; display uses the name exactly as claimed. A claim is
**refused** if normalization fails any step. The steps are ordered and exhaustive, because two
nodes that normalized differently would disagree about what is a duplicate — a consensus bug
wearing the clothes of a display concern:

1. **Reject** any name containing a Unicode `Cc` (control), `Cf` (format, including
   zero-width joiners and bidirectional overrides), `Cs` (surrogate), `Co` (private use) or
   `Cn` (unassigned) code point. These are invisible or unrenderable, and a name that cannot
   be seen cannot be checked by the person it misleads.
2. **Normalize** to Unicode **NFKC**.
3. **Trim** leading and trailing whitespace (`White_Space=Yes`), then **collapse** every
   internal run of whitespace to a single `U+0020`. Note what step 1 has already removed:
   tab, line feed and carriage return are control characters and were **refused**, not
   collapsed, so this step operates on separators alone. Refusing is the consistent answer —
   silently collapsing a character the claimant cannot see is exactly what step 1 exists to
   prevent, and doing it here would reintroduce it one line later.
4. **Lower-case** using the Unicode default lowercase mapping (`Lowercase_Mapping`, what
   Rust's `str::to_lowercase` implements). Deliberately *not* full case folding: folding is
   the more correct tool for caseless matching and differs from lowercasing for a handful of
   code points, but lowercasing is available identically in every environment likely to
   implement this, and a rule everybody applies the same way beats a better rule applied two
   ways. The visible consequence is that `ß` and `SS` are distinct keys.
5. **Reject** if the result is empty, or if the *claimed* form exceeds **64 bytes** of UTF-8
   or the normalized form exceeds **32 extended grapheme clusters**. Both bounds are checked:
   bytes bound what a node must store and relay, graphemes bound what a name can occupy on a
   screen, and neither implies the other.

The result is the **name key**. Two claims collide exactly when their name keys are equal.

**The name key is only as stable as the Unicode version a client embeds, and that is a real
limit rather than a theoretical one.** Step 1's categories and step 2's normalization are both
defined against a Unicode version, so two nodes on different versions can in principle disagree
about a name built from code points assigned between them — one refuses it as unassigned, the
other accepts and binds it. Three things bound the damage: the Unicode stability policy
guarantees normalization is fixed for code points that already exist, so only *newly assigned*
ones are in play; the disagreement is confined to the one name involved; and upgrading resolves
it. This is also precisely why §3.9.1 refuses to fold confusables — that table changes far more
than these do, and it would put the same hazard on names people actually use.

**What this does not catch, stated because a reader will assume otherwise.** Homoglyphs
survive: `alice` and `alicе` (Cyrillic `е`), or `l` against capital `I` in many typefaces, are
distinct keys and both may be held. Confusable-skeleton folding would close it and is
deliberately not specified here — the tables are large, they collide names across scripts that
have every right to exist, and two nodes on different table versions would disagree about what
is a duplicate, which turns a display nicety into a fork. **Interfaces are therefore expected
to render a name alongside enough of its identity to distinguish two holders** (§8).

#### 3.9.2 Uniqueness and permanence

On replay, in canonical order:

- A claim whose name key is **unheld** binds that key to the entry's author.
- A claim whose name key is **held by another identity** is **invalid and ignored**. It is not
  an error that stops replay; the entry stays in the log and has no effect, exactly as a
  channel entry from an unauthorized author does.
- A claim whose name key is **already held by the same author** re-displays under the newly
  claimed spelling, since the key is unchanged.
- A member may hold **several** keys over time by claiming new ones. The most recent claim is
  their current name.

**A name key is bound permanently, including after its holder leaves the network.** Releasing
it would let a later member inherit it, and history renders by author id with names resolved
at display time — so an inherited name silently relabels somebody else's past messages, and
every line stays honestly attributed while the conversation as a whole becomes a lie. The
registry therefore only grows. It grows by one entry per member per rename, which is bounded
by membership rather than by traffic.

**Removal does not free a name.** Neither does a member abandoning it for another.

## 4. Authorization

### 4.1 Vocabulary

Extension capabilities (Core §2.2), each tier-tagged as that section requires:

| Capability | Tier |
|---|---|
| `chat:create-channel:<scope>` | Ordinary |
| `chat:post:<scope>` | Ordinary |
| `chat:read:<scope>` | Ordinary |
| `chat:connect-voice:<scope>` / `chat:speak-voice:<scope>` | Ordinary |
| `chat:set-name:<scope>` | Ordinary |
| `chat:manage-channel:<scope>` | **Governance** |
| `chat:moderate:<scope>` | **Governance** |

`chat:set-name` is Ordinary and is expected to be granted to `everyone` at genesis. It
authorizes a claim on the claimant's *own* name and nothing else — §3.9's payload carries no
identity, so the capability cannot be used against another member however broadly it is
granted.

`chat:manage-channel` is governance-tier because it can add an identity to a private
channel's roster, which is the ability to widen access to content other members cannot see.
Anything that can do that is governance power however routine it feels, and tiering it
correctly is what keeps `everyone` from ever holding it (Core §2.4).

### 4.2 Scope resolution

Channel override, then category default, then network default, then denied. One level of
inheritance, no recursion: this is app-layer *name* resolution over flat capabilities and
does not nest groups.

**There is no deny capability.** A negative grant would need precedence rules over the
union-of-groups model, which is the sprawl Core §2.1 exists to prevent. Excluding somebody
from a broadly-granted category is done by binding a narrower group at the channel.

**Permissions bind at category scope by default**, per-channel only as an override,
because a group with rights on 300 channels otherwise holds 300 capability entries that
every node replays.

### 4.3 Rate limits are network policy, and why they must be

Every limit below is a network policy value with a shipped default, changeable by
`define-policy` holders:

`chat:message-rate-per-minute` (30), `chat:reaction-rate-per-minute` (60),
`chat:message-max-bytes` (8 KiB), `chat:attachment-max-bytes` (25 MiB),
`chat:attachment-max-count` (10), `chat:segment-max-bytes` (8 MiB),
`chat:max-future-skew-millis` (300 000), `chat:slowmode-max-seconds` (21 600),
`chat:retain-messages-days` (`Forever`), `chat:retain-attachments-days` (`Forever`).

The last two are §2.8's retention windows, listed here because they are network policy for
the same reasons and read by the same accessor — but note they are not ceilings on a
record, so nothing is *refused* for exceeding them. What they govern is what a network
keeps maintaining, and §2.8 carries their sentinel rule.

Two independent reasons, either sufficient. **They are validity rules** — a record past the
ceiling is refused by readers, so a local limit would mean two members rendering different
histories from the same records. **They spend other members' resources** — at replication
factor 3 a 25 MiB attachment costs 75 MiB network-wide.

The window is computed over **the author's own readings**, which are monotonic per device
(§2.6), so every node reaches the same verdict regardless of arrival order or skew.

**Per-channel slowmode is a separate, delegable knob** carried on the channel definition and
set by `chat:manage-channel` holders, bounded by `chat:slowmode-max-seconds`. A moderator
calming a channel should not need `define-policy`, which also governs admission mode and
governance model.

---

## 5. Confidentiality

### 5.1 Three keying tiers

| Tier | Used by | Key |
|---|---|---|
| Network | Public channels and their attachments | Per-object DEK under the epoch key (Storage §5) |
| Channel | Private channels, their attachments and voice | Per-channel MLS subgroup (§5.3) |
| Session | Voice in public channels | `CallKey` sealed per participant (Real-Time §1.3) |

### 5.2 Channel content key

Live-path payloads (§6.1) are sealed under
`keyed_hash(epoch_key_for(rotation_ref), domain ‖ channel_id ‖ rotation_ref)`. The
derivation adds no trust assumption — it uses a key the member legitimately holds — and
makes the public and private paths one code path with two key sources. Every payload carries
its `rotation_ref`, so a receiver mid-rotation selects the right key rather than failing.

### 5.3 Private channels

**Decided: each private channel gets its own MLS group** whose membership is the channel
roster, using the same machinery as the network group. The alternative — a symmetric key
sealed per member — costs O(n) per roster change against MLS's O(log n), offers no forward
secrecy, and would be a second key-management mechanism to get wrong. Core §3.2 already
rejects that scheme for the network, for the same reasons.

Channel rotations are anchored in the governance log (§7, E2), inheriting commit ordering,
fork choice, bounded finality and the tentative-retention discipline wholesale. This is the
scoped-key mechanism Real-Time §3.5 flags as necessary for restricted-audience broadcasts
and declines to specify; a private-channel stage uses it.

**Authorization and keys are separate and both required.** `chat:read` records who is
entitled; the MLS group decides who can decrypt. Where they disagree the design fails
closed, and a member with the capability but not yet in the group is in a normal
intermediate state, not an error.

**A private channel does not hide its existence, its name or its roster**, since its
definition is in the governance log. A network wanting a genuinely invisible space should
use a separate network, which is free.

**Removing a member from the network does not automatically remove them from private
channel groups.** Each channel's managers must act, so access is lost **convergently**, as
each rotation processes — not instantly.

### 5.4 Search must not leak private channels

**Fail-closed rule: content in a private channel is never announced to the network search
index.** Postings are announced under `hash(network_id ‖ term)` and readable by any member,
and while payloads are encrypted, the *association* between term and pointer is not. Private
channels are searchable only through a client's local index over what it holds, and a
conformant client must say so rather than imply completeness.

---

## 6. Transport

### 6.1 Live delivery

Chat's durable path costs a segment publish, a pointer update and a fetch — seconds, not
milliseconds. Records are therefore **also** published to a per-channel gossip topic
(§7, E4), `H(domain ‖ channel_id)`, subscribed on demand rather than for every channel a
member belongs to.

A payload is exactly the signed record of §2.5, sealed under §5.2's key. Receivers validate
signature, current membership and `chat:post` — the same three-part discipline Storage §2.5
requires of append-set entries, for the same reason.

**Nothing may depend on this path.** Missed records arrive with the next segment fetch;
duplicates are idempotent because records are content-addressed; out-of-order arrival is
irrelevant because order is computed. A client with gossip disabled is slower and completely
correct, and conformance MUST be testable with it disabled.

### 6.2 Direct message invitation

`/chat/dm-invite/1.0.0` (§7, E10), member to member, carrying a network invite (Core §5.6)
and a common-ownership proof (Core §1.2). **Nothing is stored by anyone but the two parties
and nothing enters any log.** Rate limiting applies per sending identity, or the protocol
becomes a spam channel.

### 6.3 What a reader must do in order

Three things must hold before a chunk fetch can succeed, in this order: governance replay
must admit the requester, because serving is gated on `read-content` (Storage §5.4); the
holder must have advertised capacity, because source selection drops a holder that never
volunteered; and only then can the fetch run. **A fetch that finds nothing is usually the
second, not a bug.** A manifest additionally needs its own fetch round before the chunks it
names can be requested.

---

## 7. Required Platform Amendments

| # | Amendment | Touches |
|---|---|---|
| **E2** | ✅ **Implemented, in generalised form.** Originally four chat-shaped entry variants; landed instead as **one generic application entry** (Core §2.7.2) carrying namespace, kind, required capability and an opaque payload. Chat's four records are payloads in the `chat` namespace, decoded by the client. Two consequences differ from the original proposal and are recorded in §1.3 and §1.2 | Core §2.7.2 |
| **E4** | ✅ **Implemented.** A publish/subscribe behaviour for live delivery, with per-topic subscribe/unsubscribe | Core §5.1 |
| **E9** | ✅ **Implemented.** An app-layer policy map in `NetworkPolicy`: namespaced keys the protocol **stores, orders and encodes but does not interpret**, exactly as it already does for `extension_capabilities`. Core §0 is explicit that the platform must not be shaped around one application, so `chat:`-named fields do not belong in the core policy record. Specified in Core §2.6.2 | Core §2.6.2 |
| **E10** | `/chat/dm-invite/1.0.0`, member to member | — |
| **E11** | ✅ **Implemented.** **Namespace registration for extension capabilities.** The tier registry matches names exactly, and every capability in §4.1 is parametrized by scope, so each scope would otherwise need a policy change. Resolution should take the **longest matching registered prefix**, so one entry per verb covers every scope of it. Note the platform did not encounter this itself because its own parametrized capabilities are built-in variants with computed tiers; `Extension(String)` plus exact match leaves a consuming spec nowhere to put them. Specified in Core §2.2.1 | Core §2.2.1 |
| **E12** | ✅ **Implemented.** **Peer discovery is optional.** §1.5 makes a direct message its own network, and a node's identity is per-network, so a client runs one node per conversation — each with a Kademlia routing table and mDNS multicast serving a network of two members who already know each other. A node MAY now be built without either, keeping everything else, with discovery operations reporting their absence rather than returning a query that never resolves. Specified in Core §5.1.1 | Core §5.1.1 |

Two amendments anticipated in earlier drafts proved unnecessary on inspection and are
recorded here so they are not re-proposed: the extension-capability tier registry already
exists, and `PointerId::from_bytes` already permits derived pointer ids.

**E12 is narrower than the request that produced it, deliberately.** It was raised as
*tiered node liveness* — a node holding a relay reservation without a full behaviour set,
so a quiet conversation stays reachable cheaply. Only the behaviour-set half is a platform
concern: the set is assembled here and a consuming client cannot assemble a partial one.
Whether a node exists at the moment, and whether it holds a reservation while nothing is
happening, is a client's policy over time and needs nothing from this platform — so the
tiering itself stays in the client and is not requested here.

---

## 8. Summary: What Other Specs Should Assume From This Document

- A channel is **many single-writer author logs merged by the reader**, not one object
  (§2.1–2.2). Any future application needing multi-writer append-mostly history should
  reuse that shape rather than reaching for an append-set, which lapses.
- **Ordering is HLC then lower record hash**, strict per (author, device) (§2.6). Concurrent
  records get an agreed arbitrary order; no stronger claim is made or achievable.
- **Encoding is normative** (§3), and the segment record list is the one count-free sequence
  in this project, for a measured reason (§3.5).
- **Rate limits and structural policy are network policy**, carried in an app-layer map the
  platform does not interpret (§4.3, §7 E9).
- **Private channels use scoped MLS subgroups** (§5.3) — the mechanism Real-Time §3.5 says a
  restricted-audience feature would need and declines to specify.
- **Direct messages are their own networks** (§1.5), so nothing about them burdens a shared
  log or a third party's disk.
- **The live path is an optimization and never a dependency** (§6.1).
- **A display name is unique per network, permanently bound, and not sufficient on its own**
  (§3.9). Uniqueness is decided on a normalized key that deliberately does not fold
  confusables, so an interface MUST render a name alongside enough of its holder's identity to
  tell two similar-looking names apart. A name is a convenience over an identity, never a
  replacement for one.

---

## 9. Explicitly Open Questions

1. **Moderation authority must be evaluated as of a cited governance head** (§2.7), which
   needs the log rather than one replayed state. An implementation answering from current
   state retroactively invalidates a demoted moderator's past redactions — the reference
   implementation currently does exactly that and flags it.
2. **Governance log growth from channel structure** at very large channel counts. Nothing
   per message, per thread or per direct message enters the log, so structure is the only
   contributor; checkpointed replay (Core §2.7) is the mitigation if measurement ever
   demands one.
3. **Segment sealing thresholds, gossip fanout and backfill depth** are unmeasured beyond a
   single spike. They are tuning, not architecture, and want real deployment data.
