//! Governance errors.
//!
//! Every variant here represents a *refusal*, and refusals are the point: the
//! project's fail-closed principle says that anywhere the system is unsure
//! whether an operation is authorized, it must refuse rather than fall back to
//! something less secure. An unknown group, an unregistered extension
//! capability, or an unresolvable capability tier are all errors rather than
//! permissive defaults for exactly that reason.

use crate::{Capability, GroupId};
use intranet_identity::PerNetworkIdentityId;

/// An error produced while validating or applying a governance action.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GovernanceError {
    /// The first entry in a log was not a genesis entry.
    #[error("the first log entry must be a genesis entry")]
    ExpectedGenesis,

    /// A genesis entry appeared somewhere other than the start of the log.
    #[error("a genesis entry may only appear once, at the start of the log")]
    UnexpectedGenesis,

    /// An entry referenced a parent that is not present.
    #[error("entry references unknown parent {parent}")]
    UnknownParent {
        /// The missing parent hash, hex-encoded.
        parent: String,
    },

    /// A non-genesis entry had no parent.
    #[error("only a genesis entry may have no parent")]
    MissingParent,

    /// The acting identity does not hold the capability the action requires.
    #[error("identity {identity} is not authorized: requires {capability}")]
    Unauthorized {
        /// The acting identity.
        identity: String,
        /// The capability the action required.
        capability: Capability,
    },

    /// The acting identity is not a member of any group in this network.
    ///
    /// Distinct from [`Unauthorized`]: this is the "not a member at all" case,
    /// which matters for actions that require only current membership rather
    /// than a specific capability — a self-initiated epoch rekey request being
    /// the notable one (Core Protocol Spec §1.3, point 6).
    ///
    /// [`Unauthorized`]: Self::Unauthorized
    #[error("identity {identity} is not a current member of this network")]
    NotAMember {
        /// The acting identity.
        identity: String,
    },

    /// An action referenced a group that does not exist.
    #[error("unknown group '{0}'")]
    UnknownGroup(GroupId),

    /// An extension capability was used without being registered in policy.
    ///
    /// Fail-closed by design: a capability whose tier nobody declared cannot be
    /// safely evaluated against the `everyone` invariant, so it is refused
    /// rather than assumed ordinary. Assuming ordinary would be precisely the
    /// hole the class-based invariant exists to close.
    #[error("extension capability '{0}' is not registered in this network's policy")]
    UnregisteredExtensionCapability(String),

    /// A grant would have given `everyone` a governance-tier capability.
    ///
    /// This is the structural invariant from Core Protocol Spec §2.4: being
    /// admitted to a network can never itself confer governance power, no matter
    /// how permissively that network configures its default group.
    #[error("`everyone` may never hold governance-tier capability {capability}")]
    EveryoneGovernanceTier {
        /// The offending capability.
        capability: Capability,
    },

    /// A grant would have given `everyone` every capability.
    #[error("`everyone` may never hold the unrestricted capability set")]
    EveryoneUnrestricted,

    /// An entry's signature did not verify against its stated author.
    #[error("entry signature verification failed")]
    BadSignature,

    /// An embedded device certificate or revocation failed verification.
    #[error("device record verification failed: {reason}")]
    BadDeviceRecord {
        /// Why the record was rejected.
        reason: String,
    },

    /// A device record was submitted by an identity other than its subject.
    ///
    /// Only the identity itself (via a master-seed-holding device) may enroll or
    /// revoke its own devices; nobody else may do so on its behalf.
    #[error("device record for identity {subject} was submitted by {author}")]
    DeviceRecordAuthorMismatch {
        /// The identity the record concerns.
        subject: String,
        /// The identity that submitted it.
        author: String,
    },

    /// An entry belonged to a different network than the log it was applied to.
    #[error("entry is for network {entry_network}, log is for network {log_network}")]
    NetworkMismatch {
        /// Network named by the entry.
        entry_network: String,
        /// Network of the log.
        log_network: String,
    },

    /// A membership action targeted an identity that is not in the group.
    #[error("identity {identity} is not a member of group '{group}'")]
    NotInGroup {
        /// The identity.
        identity: String,
        /// The group.
        group: GroupId,
    },

    /// A quorum certificate failed verification.
    #[error("quorum certificate rejected: {reason}")]
    InvalidQuorumCertificate {
        /// Why the certificate was rejected.
        reason: String,
    },
}

impl GovernanceError {
    /// Builds an [`Unauthorized`](Self::Unauthorized) error for an identity.
    pub(crate) fn unauthorized(identity: &PerNetworkIdentityId, capability: Capability) -> Self {
        Self::Unauthorized {
            identity: identity.short(),
            capability,
        }
    }

    /// Builds a [`NotAMember`](Self::NotAMember) error for an identity.
    pub(crate) fn not_a_member(identity: &PerNetworkIdentityId) -> Self {
        Self::NotAMember {
            identity: identity.short(),
        }
    }
}
