//! Governance log entries — Core Protocol Spec §2.7.

use crate::{CapabilitySet, ContentType, GovernanceError, GroupId, NetworkPolicy};
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationReason {
    /// Rotation following a membership removal, requiring `revoke-node`.
    MembershipChange,
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
    },
    /// Record a device certificate — capability-free.
    DeviceEnrollment(DeviceCertificate),
    /// Record a device certificate revocation — capability-free.
    DeviceRevocation(DeviceCertificateRevocation),
    /// Delist or relist published content.
    Moderation(ModerationEntry),
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
            Self::EpochRotation { reason } => match reason {
                RotationReason::MembershipChange => true,
                RotationReason::SelfInitiated => false,
            },
            Self::DefineGroup { .. }
            | Self::MembershipChange { .. }
            | Self::PolicyChange { .. }
            | Self::ContentTypePolicy { .. }
            | Self::Moderation(_) => true,
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
            Self::DeviceEnrollment(_) => "device-enrollment",
            Self::DeviceRevocation(_) => "device-revocation",
            Self::Moderation(_) => "moderation",
        }
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
            Self::EpochRotation { reason } => {
                enc.variant(5).u8(match reason {
                    RotationReason::MembershipChange => 0,
                    RotationReason::SelfInitiated => 1,
                });
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
                reason: RotationReason::SelfInitiated
            }
            .is_capability_gated()
        );
        assert!(
            EntryBody::EpochRotation {
                reason: RotationReason::MembershipChange
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
