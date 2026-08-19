//! Governance log entries — Core Protocol Spec §2.7.

use crate::{Capability, CapabilitySet, ContentType, GovernanceError, GroupId, NetworkPolicy};
use intranet_crypto::{Enc, Hash, Signature, Timestamp, hash_bytes, to_hex};
use intranet_identity::{
    DeviceCertificate, DeviceCertificateRevocation, NetworkId, PerNetworkIdentity,
    PerNetworkIdentityId,
};
use std::collections::BTreeSet;

/// Domain tag for governance log entry signatures.
const ENTRY_DOMAIN: &str = "intranet.governance-entry.v1";

/// Domain tag for governance log entry hashing.
const ENTRY_HASH_DOMAIN: &str = "intranet.governance-entry-hash.v1";

/// Domain tag for hashing an entry body as a vote subject.
const ACTION_HASH_DOMAIN: &str = "intranet.governance-action-hash.v1";

/// The identifier of a mutable pointer (Storage Spec §2.2).
///
/// Defined here rather than in a storage crate because moderation entries are
/// governance records that reference pointers, and governance cannot depend on
/// a storage layer that sits above it. The storage crate will re-export this
/// type rather than define a competing one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PointerId([u8; 32]);

impl PointerId {
    /// Wraps raw pointer identifier bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrows the raw identifier bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Renders the first 8 hex characters, for human-facing output.
    pub fn short(&self) -> String {
        to_hex(&self.0[..4])
    }
}

impl std::fmt::Display for PointerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", to_hex(&self.0))
    }
}

/// A human-shareable application name.
///
/// Names are compared exactly as given. Case folding or Unicode normalisation
/// would be a security decision, not a convenience one — collapsing distinct
/// names into one creates homograph confusion where a lookalike resolves to
/// somebody else's app — so it is deliberately not done here, and any such
/// policy belongs in a client's presentation layer where a human can see it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AppName(String);

impl AppName {
    /// Builds an application name.
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// The name text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for AppName {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl std::fmt::Display for AppName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Whether a moderation action delists or restores content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModerationAction {
    /// Stop this pointer being surfaced or served.
    Delist,
    /// Restore a previously delisted pointer.
    ///
    /// Moderation is reversible on the same terms it was applied: a mistaken or
    /// overturned delisting is corrected by appending, never by rewriting
    /// history, consistent with the log being append-only.
    Relist,
}

/// A moderation action against a published pointer — §2.7.
///
/// # Where the moderator's identity and signature live
///
/// The spec's record carries `moderator_identity` and `signature` alongside
/// `action` and `target_pointer_id`. Here those two fields are the enclosing
/// [`LogEntry`]'s `author` and `signature` rather than duplicated inside the
/// body. This is deliberate and semantically identical: a moderation entry is
/// only ever meaningful as a governance log entry, and carrying a second,
/// independently-forgeable signature over the same facts would create a state
/// where the inner and outer signers disagree, with no rule saying which wins.
/// One signature, one signer, no ambiguity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModerationEntry {
    /// Whether to delist or relist.
    pub action: ModerationAction,
    /// The pointer being moderated.
    pub target_pointer_id: PointerId,
}

/// Which invite a membership came from — §5.6.
///
/// "The issuing identity, retained and attached to the resulting membership
/// record" — required for waiting-room visibility under explicit intake, where
/// an admin reviewing a joiner needs to see which invite was used and who
/// issued it, and generally useful provenance regardless of admission mode.
///
/// It also makes invite use-counting answerable by replay: counting the
/// membership records naming a given invite is a computation over the log,
/// rather than a tally each node would otherwise have to keep privately and
/// could never reconcile with anyone else's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InviteProvenance {
    /// The invite that was used.
    pub invite_id: Hash,
    /// The identity that issued that invite.
    pub issuer: PerNetworkIdentityId,
}

impl InviteProvenance {
    /// Appends this provenance to a canonical encoding.
    pub fn encode(&self, enc: &mut Enc) {
        enc.fixed(self.invite_id.as_bytes());
        self.issuer.encode(enc);
    }
}

/// How a membership change alters a group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MembershipAction {
    /// Add the identity to the group.
    Add {
        /// The invite this membership came from, if any.
        ///
        /// `None` covers memberships that did not originate from an invite at
        /// all — a founder at genesis, or an admin adding an existing member to
        /// an additional group.
        via_invite: Option<InviteProvenance>,
    },
    /// Remove the identity from the group.
    Remove {
        /// Optional cascade, removing everyone this identity added — §2.5.
        ///
        /// `None` is the default, non-cascading behaviour: removing an identity
        /// removes only that identity, since anyone it added was validly added
        /// at the time. Cascading is specified explicitly at the moment of
        /// revocation, never as a standing group setting, so it is always a
        /// deliberate visible choice rather than a background policy someone
        /// forgets is active.
        cascade: Option<Cascade>,
    },
}

/// Scope of a cascading removal — §2.5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cascade {
    /// Only cascade memberships granted within this many milliseconds before
    /// the removal, or `None` to cascade the identity's entire history.
    ///
    /// The windowed form is the compromised-account case: "cascade everything
    /// added in the last 48 hours" undoes an attacker's additions without
    /// unwinding years of legitimate onboarding by the same account.
    pub window_millis: Option<i64>,
}

/// Why an epoch rotation was triggered — §3.3, §1.3 point 6.
///
/// # Why admission and revocation are separate reasons
///
/// §3.3 says "membership changes advance the epoch" and names `revoke-node` as
/// the trigger, but it says that in the context of *revocation*. Admission
/// advances the epoch too, and unavoidably: adding a member to an MLS group is
/// itself a commit. Collapsing both into one reason gated on `revoke-node`
/// would mean a group holding `approve-node` but not `revoke-node` — exactly
/// the delegated-moderation arrangement §2.6 describes — could admit a member
/// and then be unauthorized to deliver them a key, leaving the joiner admitted
/// and permanently unable to read anything.
///
/// **Flagged: the specs do not name the capability for an admission-driven
/// rotation.** Gating it on `approve-node` is the reading consistent with §2.2's
/// split between admitting and removing, and it keeps the rotation's authority
/// identical to the authority for the membership change that caused it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationReason {
    /// Rotation admitting a new member, requiring `approve-node`.
    MemberAdmitted,
    /// Rotation following a membership removal, requiring `revoke-node`.
    MemberRevoked,
    /// A member's own request to rotate, requiring no capability.
    ///
    /// Any identity may request this — it addresses the risk that one of their
    /// devices cached the current epoch key before being revoked. Gating it
    /// behind approval would discourage reporting a compromise, which is the
    /// wrong incentive to create.
    SelfInitiated,
}

/// The action an entry records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryBody {
    /// Network creation — the root of the log.
    Genesis {
        /// The network being created.
        network: NetworkId,
        /// The network's initial policy.
        policy: NetworkPolicy,
        /// Capabilities granted to `everyone` at genesis.
        ///
        /// Configurable per network, but subject to the hardcoded ceiling: no
        /// governance-tier capability, under any configuration.
        everyone_capabilities: BTreeSet<crate::Capability>,
    },
    /// Create a group, or change an existing group's capability set.
    DefineGroup {
        /// The group being defined.
        group: GroupId,
        /// Its new capability set.
        capabilities: CapabilitySet,
    },
    /// Add or remove an identity from a group.
    MembershipChange {
        /// The group being changed.
        group: GroupId,
        /// The identity being added or removed.
        identity: PerNetworkIdentityId,
        /// What to do.
        action: MembershipAction,
    },
    /// Replace the network's governance policy.
    PolicyChange {
        /// The new policy.
        policy: NetworkPolicy,
    },
    /// Replace the network's content-type allowlist.
    ContentTypePolicy {
        /// The new allowlist.
        allowlist: BTreeSet<ContentType>,
    },
    /// Advance the network's epoch.
    EpochRotation {
        /// Why the rotation happened, which determines what authorizes it.
        reason: RotationReason,
        /// The MLS commit this rotation produced.
        ///
        /// # Why the commit travels in the log entry
        ///
        /// Core Protocol Spec §3.3 replaces MLS's Delivery Service with this
        /// log, and a Delivery Service's whole job is imposing a strict *order*
        /// on commits. The log can only do that job for a commit it actually
        /// carries: two members applying the same set of commits in different
        /// orders derive different epoch keys, and MLS offers no way to
        /// reconcile that after the fact. §3.3 says as much directly — a
        /// rotation produces "one commit that gets appended to the log like any
        /// other governance action".
        ///
        /// Carrying it here also makes voiding coherent. A rotation on a losing
        /// branch is voided as an entry (§2.7.1, point 4), and because the
        /// commit *is* that entry, the commit is voided with it rather than
        /// surviving out-of-band as an orphan a member might still apply.
        ///
        /// Opaque bytes rather than a parsed type: this crate deliberately knows
        /// nothing about MLS, and validating the commit is the epoch layer's
        /// job. An unparseable commit is therefore a rejected *rotation* at that
        /// layer, never a rejected log entry here.
        commit: Vec<u8>,
    },
    /// Open a vote, freezing its electorate — §2.6.1, point 1.
    ///
    /// # Why opening is a log entry, and not just a message
    ///
    /// The electorate is "a snapshot of a specific group's membership, taken at
    /// a fixed version the moment a vote is proposed". If a proposal simply
    /// *asserted* its roster, a proposer could freeze a roster of keypairs they
    /// control, cast every ballot themselves, and produce a certificate that
    /// verifies perfectly against the roster it came with — forging any outcome
    /// they liked. The attested roster has to be checked against the membership
    /// the log actually had.
    ///
    /// Opening as an entry is what makes that check possible and cheap: replay
    /// processes entries in order, so at this entry it already holds the
    /// membership as of this point in the chain and can reject any proposal
    /// whose roster disagrees. No node has to re-replay to an arbitrary earlier
    /// version, and the fixed version §2.6.1 refers to is simply this entry's
    /// position.
    ///
    /// **Capability-free**, like a vote outcome: proposing costs nothing and
    /// decides nothing, since the electorate is what settles it. Current
    /// membership is still required — a non-member has no standing to put the
    /// network's electorate to work.
    VoteProposed {
        /// The proposal, whose roster is verified against replayed state here.
        proposal: crate::VoteProposal,
    },
    /// Record that a vote reached a decision — §2.6.1.
    ///
    /// # Why an outcome is recorded rather than recomputed
    ///
    /// §2.6.1 defines a vote's outcome as **certificate existence**, precisely
    /// because local tallying diverges: two honest nodes near the close boundary
    /// genuinely collect different ballot sets. Appending the certificate makes
    /// existence a fact of the log — replayable, ordered, and identical
    /// everywhere — rather than a question each node answers from whatever it
    /// happened to receive.
    ///
    /// It also gives ballots somewhere to stop. Ballots themselves are not log
    /// entries and never become any node's permanent responsibility; once a
    /// certificate is appended, the ballots behind it have done their work and
    /// can be dropped, since the certificate carries the ones that mattered.
    ///
    /// **Capability-free**, so it does not count toward branch length (§2.7.1,
    /// point 2). Assembling one is not free — it needs real ballots from a real
    /// frozen electorate — but it needs no capability either, and the
    /// anti-grinding rule counts only capability-gated actions. Treating it as
    /// gated would let a network with an active vote lengthen a branch by
    /// re-appending outcomes.
    VoteOutcome {
        /// The certificate that settles it.
        ///
        /// The proposal is *not* carried alongside. It was recorded when the
        /// vote opened, with its roster verified against the log at that point,
        /// so this references it by the `vote_id` the certificate already names.
        /// Re-carrying it would let a certificate arrive with a roster nobody
        /// checked — the exact hole opening-as-an-entry exists to close.
        certificate: crate::QuorumCertificate,
    },
    /// Record a device certificate — capability-free.
    DeviceEnrollment(DeviceCertificate),
    /// Record a device certificate revocation — capability-free.
    DeviceRevocation(DeviceCertificateRevocation),
    /// Delist or relist published content.
    Moderation(ModerationEntry),

    /// Claim or reassign a human-shareable application name.
    ///
    /// # Why this is a governance log entry rather than an append-set entry
    ///
    /// Two properties of the append-set primitive, both correct and desirable
    /// for a discovery index, are actively wrong for authoritative ownership:
    ///
    /// - **No trustworthy ordering.** "First registration wins by timestamp"
    ///   relies on a field the submitter attests to itself, so a squatter can
    ///   simply backdate a claim. The governance log supplies a tamper-evident
    ///   total order that cannot be backdated.
    /// - **TTL-based liveness.** An append-set entry expires unless
    ///   re-announced — right for search postings, dangerous for ownership,
    ///   since a legitimate registrant whose node is merely offline would have
    ///   their claim silently lapse and a standing competing entry would take
    ///   over by default. Log entries never lapse.
    ///
    /// The append-set is still used, purely as a best-effort discovery index
    /// (App Hosting Spec §4.4). It is never the source of truth for ownership.
    AppNameRegistration {
        /// The name being claimed or reassigned.
        name: AppName,
        /// The app this name should resolve to.
        app_id: PointerId,
    },
    /// A record belonging to a consuming spec, carried but not interpreted.
    ///
    /// # Why this is generic rather than one variant per record type
    ///
    /// An application layer needs durable, ordered, tamper-evident records for
    /// its own structure — a chat application's channel definitions, for
    /// instance, which an append-set cannot hold because its entries lapse when
    /// unrefreshed (Storage Spec §2.5). The governance log is the only place
    /// with those properties.
    ///
    /// Naming each such record here would shape this document around whichever
    /// applications happened to arrive first, which §0 says it must not be. It
    /// has already happened once: [`Self::AppNameRegistration`] is App Hosting's
    /// record sitting in the core enum, and adding four chat-shaped variants
    /// beside it would have made a pattern of an exception.
    ///
    /// So this variant is the door every application layer uses. The protocol
    /// **orders, hash-covers and authorizes** these entries; it does not decode
    /// `payload`, and a consuming spec owns what is inside it.
    ///
    /// # What the protocol still checks
    ///
    /// `required` is the capability the consuming spec says this record needs,
    /// and replay refuses the entry unless its author held that capability at
    /// that point in the chain. The protocol cannot tell whether a spec declared
    /// the *right* capability — a reader that understands the namespace must
    /// check that too — but it can and does enforce the one that was declared.
    AppEntry {
        /// The consuming spec's namespace, e.g. `chat`.
        namespace: String,
        /// Which record within that namespace, e.g. `channel-definition`.
        kind: String,
        /// The capability the consuming spec requires for this record.
        required: Capability,
        /// The record itself, opaque to this crate.
        payload: Vec<u8>,
    },
}

/// Largest payload an [`EntryBody::AppEntry`] may carry.
///
/// The governance log is replayed in full by every joiner and never shrinks, so
/// an unbounded payload would let one application make a network permanently
/// expensive to join. Application *content* belongs in storage, addressed by a
/// CID an entry can reference; this is for structure.
pub const MAX_APP_ENTRY_PAYLOAD_BYTES: usize = 8 * 1024;

/// Whether a namespace and kind are well-formed for an [`EntryBody::AppEntry`].
///
/// Both must be non-empty, and a namespace may not contain `:` — the separator
/// reserved for composing the two, so allowing it would make `a:b`/`c` and
/// `a`/`b:c` indistinguishable to anything that joins them.
pub fn is_valid_app_entry_name(namespace: &str, kind: &str) -> bool {
    !namespace.is_empty() && !kind.is_empty() && !namespace.contains(':')
}

impl EntryBody {
    /// Whether producing this entry requires holding a capability.
    ///
    /// This is what the fork-choice branch-length metric counts (§2.7.1, point
    /// 2). Only capability-gated actions count, because capability-*free* entries
    /// can be minted freely by any member, which would let an attacker grind an
    /// arbitrarily long branch during a partition and void an unfavourable
    /// revocation regardless of what governance actions the branch contained.
    ///
    /// The spec excludes device certificates by name and then generalizes: "any
    /// other future entry type that similarly requires no capability to
    /// produce". [`RotationReason::SelfInitiated`] is exactly such a type — any
    /// member may mint one without holding any capability — so it is excluded
    /// too. Counting it would reopen the grinding hole through a different
    /// entry type.
    pub fn is_capability_gated(&self) -> bool {
        match self {
            // Genesis is always the shared root, never on a competing branch.
            Self::Genesis { .. } => false,
            Self::DeviceEnrollment(_) | Self::DeviceRevocation(_) => false,
            Self::VoteProposed { .. } | Self::VoteOutcome { .. } => false,
            Self::EpochRotation { reason, .. } => match reason {
                RotationReason::MemberAdmitted | RotationReason::MemberRevoked => true,
                RotationReason::SelfInitiated => false,
            },
            Self::DefineGroup { .. }
            | Self::MembershipChange { .. }
            | Self::PolicyChange { .. }
            | Self::ContentTypePolicy { .. }
            | Self::Moderation(_)
            | Self::AppNameRegistration { .. } => true,

            // Deliberately **not** counted, which is the conservative reading.
            //
            // The metric exists to stop an attacker grinding a long branch from
            // entries that are free to mint (§2.7.1, point 2). Whether an app
            // entry is free depends on whether its declared capability is
            // scarce, and answering that means resolving the capability's tier
            // against replayed state — which this function deliberately cannot
            // do, being a pure function of the body.
            //
            // Excluding them fails closed against grinding. The cost is that
            // app-layer actions carry no weight in fork choice, so a partition
            // may void them; that is acceptable because everything which must
            // survive a partition — membership, revocation, policy, epoch
            // rotation — is a core entry that still counts, and a voided app
            // entry is resubmittable through the voided-actions report like any
            // other.
            Self::AppEntry { .. } => false,
        }
    }

    /// A short human-readable label, for voided-action reports and CLI output.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Genesis { .. } => "genesis",
            Self::DefineGroup { .. } => "define-group",
            Self::MembershipChange {
                action: MembershipAction::Add { .. },
                ..
            } => "membership-add",
            Self::MembershipChange {
                action: MembershipAction::Remove { .. },
                ..
            } => "membership-remove",
            Self::PolicyChange { .. } => "policy-change",
            Self::ContentTypePolicy { .. } => "content-type-policy",
            Self::EpochRotation { .. } => "epoch-rotation",
            Self::VoteProposed { .. } => "vote-proposed",
            Self::VoteOutcome { .. } => "vote-outcome",
            Self::DeviceEnrollment(_) => "device-enrollment",
            Self::DeviceRevocation(_) => "device-revocation",
            Self::Moderation(_) => "moderation",
            Self::AppNameRegistration { .. } => "app-name-registration",
            Self::AppEntry { .. } => "app-entry",
        }
    }

    /// This body's hash, as a vote's `subject` — §2.6.1.
    ///
    /// A vote is proposed *for a specific action*, and this is how the two are
    /// bound: the proposal's subject is the hash of the body the vote would
    /// authorize, so a passing certificate authorizes that body and nothing
    /// else. Without the binding a certificate would be a general licence,
    /// reusable to admit somebody the electorate never voted on.
    pub fn action_hash(&self) -> Hash {
        let mut e = Enc::domain(ACTION_HASH_DOMAIN);
        self.encode(&mut e);
        hash_bytes(&e.finish())
    }

    fn encode(&self, enc: &mut Enc) {
        match self {
            Self::Genesis {
                network,
                policy,
                everyone_capabilities,
            } => {
                enc.variant(0);
                network.encode(enc);
                policy.encode(enc);
                enc.seq(everyone_capabilities.iter(), |e, c| c.encode(e));
            }
            Self::DefineGroup {
                group,
                capabilities,
            } => {
                enc.variant(1).str(group.as_str());
                capabilities.encode(enc);
            }
            Self::MembershipChange {
                group,
                identity,
                action,
            } => {
                enc.variant(2).str(group.as_str());
                identity.encode(enc);
                match action {
                    MembershipAction::Add { via_invite } => {
                        enc.variant(0);
                        enc.option(via_invite.as_ref(), |e, p| p.encode(e));
                    }
                    MembershipAction::Remove { cascade } => {
                        enc.variant(1);
                        enc.option(cascade.as_ref(), |e, c| {
                            e.option(c.window_millis.as_ref(), |e, w| {
                                e.i64(*w);
                            });
                        });
                    }
                }
            }
            Self::PolicyChange { policy } => {
                enc.variant(3);
                policy.encode(enc);
            }
            Self::ContentTypePolicy { allowlist } => {
                enc.variant(4);
                enc.seq(allowlist.iter(), |e, t| {
                    e.str(t.as_str());
                });
            }
            Self::EpochRotation { reason, commit } => {
                enc.variant(5)
                    .u8(match reason {
                        // Tags 0 and 1 keep their original meaning; admission is
                        // appended as 2 rather than renumbering, since a tag is
                        // part of what every existing entry was signed over.
                        RotationReason::MemberRevoked => 0,
                        RotationReason::SelfInitiated => 1,
                        RotationReason::MemberAdmitted => 2,
                    })
                    // Inside the signed encoding, so the commit is bound to the
                    // rotation that authorized it. A commit swapped en route
                    // fails the entry's signature rather than quietly rekeying
                    // the network to a tree the author never committed to.
                    .bytes(commit);
            }
            Self::VoteProposed { proposal } => {
                enc.variant(10);
                proposal.encode(enc);
            }
            Self::VoteOutcome { certificate } => {
                enc.variant(11);
                certificate.encode(enc);
            }
            Self::DeviceEnrollment(cert) => {
                enc.variant(6);
                cert.network.encode(enc);
                cert.identity.encode(enc);
                cert.device.encode(enc);
                enc.str(&cert.label)
                    .i64(cert.issued_at.as_millis())
                    .fixed(cert.signature.as_bytes());
            }
            Self::DeviceRevocation(revocation) => {
                enc.variant(7);
                revocation.network.encode(enc);
                revocation.identity.encode(enc);
                revocation.device.encode(enc);
                enc.i64(revocation.revoked_at.as_millis())
                    .fixed(revocation.signature.as_bytes());
            }
            Self::AppNameRegistration { name, app_id } => {
                enc.variant(9)
                    .str(name.as_str())
                    .fixed(app_id.as_bytes());
            }
            Self::AppEntry {
                namespace,
                kind,
                required,
                payload,
            } => {
                enc.variant(12).str(namespace).str(kind);
                required.encode(enc);
                enc.bytes(payload);
            }
            Self::Moderation(moderation) => {
                enc.variant(8)
                    .u8(match moderation.action {
                        ModerationAction::Delist => 0,
                        ModerationAction::Relist => 1,
                    })
                    .fixed(moderation.target_pointer_id.as_bytes());
            }
        }
    }
}

/// A signed, hash-chained governance log entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    /// Hash of the immediately prior entry, or `None` for genesis.
    pub parent: Option<Hash>,
    /// When the acting identity created this entry.
    pub timestamp: Timestamp,
    /// The acting identity.
    ///
    /// For a moderation entry this is the `moderator_identity`; for a device
    /// record it is the identity enrolling or revoking its own device.
    pub author: PerNetworkIdentityId,
    /// The action recorded.
    pub body: EntryBody,
    /// The author's signature over everything above.
    pub signature: Signature,
}

impl LogEntry {
    /// Creates and signs an entry.
    pub fn create(
        author: &PerNetworkIdentity,
        parent: Option<Hash>,
        timestamp: Timestamp,
        body: EntryBody,
    ) -> Self {
        let author_id = author.id();
        let payload = Self::payload(parent.as_ref(), timestamp, &author_id, &body);
        Self {
            parent,
            timestamp,
            author: author_id,
            body,
            signature: author.sign(&payload),
        }
    }

    /// This entry's hash — its identity, and the fork-choice tie-break key.
    ///
    /// Covers the signature as well as the signed payload, so two entries that
    /// differ only in signature are distinct entries rather than colliding.
    pub fn hash(&self) -> Hash {
        let mut e = Enc::domain(ENTRY_HASH_DOMAIN);
        e.bytes(
            &Self::payload(self.parent.as_ref(), self.timestamp, &self.author, &self.body).finish(),
        );
        e.fixed(self.signature.as_bytes());
        hash_bytes(&e.finish())
    }

    /// Verifies the entry's signature against its stated author.
    pub fn verify_signature(&self) -> Result<(), GovernanceError> {
        let payload = Self::payload(
            self.parent.as_ref(),
            self.timestamp,
            &self.author,
            &self.body,
        );
        self.author
            .verifying_key()
            .verify(&payload, &self.signature)
            .map_err(|_| GovernanceError::BadSignature)
    }

    /// Whether this entry counts toward fork-choice branch length.
    pub fn is_capability_gated(&self) -> bool {
        self.body.is_capability_gated()
    }

    fn payload(
        parent: Option<&Hash>,
        timestamp: Timestamp,
        author: &PerNetworkIdentityId,
        body: &EntryBody,
    ) -> Enc {
        let mut e = Enc::domain(ENTRY_DOMAIN);
        e.option(parent, |e, hash| {
            e.fixed(hash.as_bytes());
        });
        e.i64(timestamp.as_millis());
        author.encode(&mut e);
        body.encode(&mut e);
        e
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use intranet_identity::MasterSeed;

    fn identity(seed: u8) -> PerNetworkIdentity {
        MasterSeed::from_entropy([seed; 32])
            .identity_for(&NetworkId::from_bytes([1u8; 32]))
            .unwrap()
    }

    fn moderation_body() -> EntryBody {
        EntryBody::Moderation(ModerationEntry {
            action: ModerationAction::Delist,
            target_pointer_id: PointerId::from_bytes([7u8; 32]),
        })
    }

    #[test]
    fn entry_signature_round_trips() {
        let author = identity(1);
        let entry = LogEntry::create(
            &author,
            Some(Hash::ZERO),
            Timestamp::from_millis(10),
            moderation_body(),
        );
        assert!(entry.verify_signature().is_ok());
    }

    #[test]
    fn tampering_with_any_field_breaks_the_signature() {
        let author = identity(1);
        let entry = LogEntry::create(
            &author,
            Some(Hash::ZERO),
            Timestamp::from_millis(10),
            moderation_body(),
        );

        let mut retimed = entry.clone();
        retimed.timestamp = Timestamp::from_millis(11);
        assert_eq!(retimed.verify_signature(), Err(GovernanceError::BadSignature));

        let mut reparented = entry.clone();
        reparented.parent = Some(intranet_crypto::hash_bytes(b"elsewhere"));
        assert_eq!(
            reparented.verify_signature(),
            Err(GovernanceError::BadSignature)
        );

        let mut retargeted = entry.clone();
        retargeted.body = EntryBody::Moderation(ModerationEntry {
            action: ModerationAction::Relist,
            target_pointer_id: PointerId::from_bytes([7u8; 32]),
        });
        assert_eq!(
            retargeted.verify_signature(),
            Err(GovernanceError::BadSignature)
        );
    }

    #[test]
    fn reattributing_an_entry_to_another_author_fails() {
        let entry = LogEntry::create(
            &identity(1),
            None,
            Timestamp::from_millis(10),
            moderation_body(),
        );
        let mut forged = entry;
        forged.author = identity(2).id();
        assert_eq!(forged.verify_signature(), Err(GovernanceError::BadSignature));
    }

    #[test]
    fn hashes_are_deterministic_and_distinguish_entries() {
        let author = identity(1);
        let a = LogEntry::create(&author, None, Timestamp::from_millis(1), moderation_body());
        let b = LogEntry::create(&author, None, Timestamp::from_millis(2), moderation_body());
        assert_eq!(a.hash(), a.hash());
        assert_ne!(a.hash(), b.hash());
    }

    #[test]
    fn capability_free_entry_types_do_not_count_toward_branch_length() {
        // This is the anti-grinding rule. Device records were the named case;
        // a self-initiated rotation is the generalized case, since any member
        // can mint one without holding any capability.
        assert!(
            !EntryBody::EpochRotation {
                reason: RotationReason::SelfInitiated,
                commit: Vec::new(),
            }
            .is_capability_gated()
        );
        assert!(
            EntryBody::EpochRotation {
                reason: RotationReason::MemberRevoked,
                commit: Vec::new(),
            }
            .is_capability_gated()
        );
    }

    #[test]
    fn capability_gated_entry_types_count() {
        assert!(moderation_body().is_capability_gated());
        assert!(
            EntryBody::DefineGroup {
                group: GroupId::new("g"),
                capabilities: CapabilitySet::empty(),
            }
            .is_capability_gated()
        );
    }

    #[test]
    fn device_records_are_capability_free() {
        let network = NetworkId::from_bytes([1u8; 32]);
        let author = identity(1);
        let device_seed = intranet_identity::DeviceSeed::from_entropy([5u8; 32]);
        let device_key = device_seed.key_for(&network).unwrap();
        let device = intranet_identity::DevicePublicKey::from_verifying_key(
            *device_key.id().verifying_key(),
        );

        let cert =
            DeviceCertificate::issue(&author, device, "laptop", Timestamp::from_millis(1));
        assert!(!EntryBody::DeviceEnrollment(cert).is_capability_gated());

        let revocation =
            DeviceCertificateRevocation::issue(&author, device, Timestamp::from_millis(2));
        assert!(!EntryBody::DeviceRevocation(revocation).is_capability_gated());
    }

    #[test]
    fn delist_and_relist_are_distinct_entries() {
        let author = identity(1);
        let delist = LogEntry::create(
            &author,
            None,
            Timestamp::from_millis(1),
            EntryBody::Moderation(ModerationEntry {
                action: ModerationAction::Delist,
                target_pointer_id: PointerId::from_bytes([1u8; 32]),
            }),
        );
        let relist = LogEntry::create(
            &author,
            None,
            Timestamp::from_millis(1),
            EntryBody::Moderation(ModerationEntry {
                action: ModerationAction::Relist,
                target_pointer_id: PointerId::from_bytes([1u8; 32]),
            }),
        );
        assert_ne!(delist.hash(), relist.hash());
    }
}
