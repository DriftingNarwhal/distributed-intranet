//! Group encryption and epoch keying — Core Protocol Spec §3.
//!
//! # What this layer owes the rest of the system
//!
//! Exactly one thing: a network epoch key, identified by the governance log
//! entry that produced it. Storage wraps per-object keys under it and knows
//! nothing else about how it arises.
//!
//! # Two halves, and neither is sufficient alone
//!
//! - [`group`] is the MLS/TreeKEM machinery: O(log n) rekey, which is a hard
//!   requirement at this project's target scale, with commit *ordering*
//!   delegated to the governance log rather than to a Delivery Service.
//! - [`keyring`] is the retention and finality layer, which MLS cannot provide
//!   because its forward-secrecy contract actively works against it.
//!
//! # The honest guarantee
//!
//! A revoked member cannot obtain any key wrapped for the first time after
//! removal. They **cannot** be made to un-know a key they already held, or to
//! forget content they already decrypted — no symmetric-key scheme can do that,
//! and this one does not claim to. Blocking their access to *new* ciphertext is
//! the serving gate's job (Storage Spec §5.4), not this layer's; the two
//! together are what make the guarantee real, and either alone leaves a gap.

pub mod group;
pub mod keyring;

pub use group::{GroupSession, PendingMember, Rotation};
pub use keyring::{EpochKeyring, EpochRecord, KeyringReconciliation, RotationStatus};

/// Errors produced by the epoch keying layer.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EpochError {
    /// An MLS operation failed.
    #[error("MLS error: {0}")]
    Mls(String),

    /// A join delivered no epoch keys at all.
    ///
    /// Fail-closed: a member with no keys cannot read anything, and silently
    /// accepting an empty delivery would leave them wondering why. Under
    /// explicit intake this is the correct state for a waiting-room node, which
    /// is why key delivery happens on *admission* rather than on join.
    #[error("no epoch keys were delivered")]
    NoKeysDelivered,
}
