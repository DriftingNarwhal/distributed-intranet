//! Identity model — Core Protocol Spec §1.
//!
//! Implements the four things §1 requires, and nothing above them:
//!
//! 1. **A master identity per person** ([`MasterSeed`]) — one high-entropy seed,
//!    never transmitted, recoverable from a backup phrase independently of any
//!    device.
//! 2. **Per-network identity derivation** ([`PerNetworkIdentity`]) — a distinct
//!    keypair per network, deterministically derived, unlinkable across networks,
//!    including at the transport layer via a distinct PeerId per network.
//! 3. **Multi-device linking** ([`DeviceSeed`], [`DeviceCertificate`]) — devices
//!    are independently seeded and then *authorized*, never derived from the
//!    master seed, so losing one device never forces an identity rotation.
//! 4. **Voluntary common-ownership proof** ([`CommonOwnershipProof`]) — the
//!    user-initiated escape hatch from unlinkability, which nobody else can
//!    produce or derive.
//!
//! # What this crate deliberately does not do
//!
//! Nothing here knows about groups, capabilities, or the governance log. A
//! device certificate is *created* and *verified* here, but whether a given
//! certificate is currently valid for a network is a governance-state question
//! (Core Protocol Spec §1.3, point 4), answered by `intranet-governance` after
//! replaying the log. Keeping that split means this crate stays pure key
//! material and signatures, with no notion of network state at all.

mod device;
mod linking;
mod network;
mod seed;

pub use device::{DeviceCertificate, DeviceCertificateRevocation, DevicePublicKey};
pub use linking::CommonOwnershipProof;
pub use network::NetworkId;
pub use seed::{DeviceSeed, MasterSeed, PerNetworkIdentity, PerNetworkIdentityId};

pub use libp2p_identity::PeerId;

/// Errors produced by the identity layer.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IdentityError {
    /// A backup phrase was not a valid BIP-39 mnemonic.
    #[error("invalid backup phrase: {0}")]
    InvalidBackupPhrase(String),

    /// A backup phrase decoded to the wrong amount of entropy.
    #[error("backup phrase decoded to {got} bytes of entropy, expected 32")]
    WrongEntropyLength {
        /// Entropy length actually decoded.
        got: usize,
    },

    /// A certificate or proof failed signature verification.
    #[error("signature verification failed for {what}")]
    BadSignature {
        /// What failed to verify.
        what: &'static str,
    },

    /// A certificate was presented for a network it was not issued against.
    ///
    /// Enrollment is per-network (Core Protocol Spec §1.3, point 7): a
    /// certificate authorizing a device for one network confers nothing in
    /// another, and honest code must refuse to evaluate it cross-network rather
    /// than silently accept it.
    #[error("certificate is for network {certificate_network}, not {expected_network}")]
    NetworkMismatch {
        /// Network the certificate was issued for.
        certificate_network: String,
        /// Network it was presented against.
        expected_network: String,
    },

    /// An underlying cryptographic operation failed.
    #[error(transparent)]
    Crypto(#[from] intranet_crypto::CryptoError),
}
