//! Storage and replication — Storage Spec.
//!
//! # The one idea the rest follows from
//!
//! Content is encrypted under a **per-object key** that never changes, and the
//! network's epoch key only ever wraps that small key. Everything good about
//! this layer falls out of that arrangement:
//!
//! - **Cheap rotation.** A revocation re-wraps each live object's 32-byte key
//!   record. It never touches content ciphertext, never recomputes a CID, and
//!   never re-replicates a byte. Rotation cost scales with the number of live
//!   objects, not with how much content the network holds.
//! - **Delta fetch.** Because the key is fixed for the object's life and chunk
//!   encryption is deterministic, two versions of an object produce identical
//!   ciphertext — and therefore identical addresses — for every chunk whose
//!   plaintext did not change.
//! - **No owner-offline blackout.** The owner commits to the key once, at
//!   creation. Any current member can later re-wrap it, because a wrapping is
//!   validated against that commitment rather than against a fresh signature
//!   from the owner.
//!
//! # Layout
//!
//! - [`chunk`] — content-defined chunking, on plaintext, before encryption.
//! - [`crypto`] — the per-object DEK, deterministic chunk encryption, and DEK
//!   wrapping under an epoch key.
//! - [`object`] — content addressing, manifests, encode and decode.
//!
//! - [`pointer`] — mutable pointers, and the commitment/wrapping split that
//!   makes re-wrapping by any current member possible without forging the
//!   owner's authority.
//! - [`appendset`] — the multi-writer collection primitive search and the app
//!   directory both build on.
//! - [`replication`] — holding announcements, under-replication detection, and
//!   the repair loop where unreliable nodes are actually corrected for.
//! - [`serving`] — the `read-content` gate, source selection, rarest-first.
//!
//! # Not implemented here
//!
//! The epoch key arrives as opaque material via [`EpochKey`]; how it is
//! derived, rotated, and distributed belongs to the group-keying layer, and
//! this crate deliberately knows nothing about it. Actual byte transfer belongs
//! to the transport layer; this crate decides *who* and *what*, not *how*.

pub mod appendset;
pub mod chunk;
pub mod crypto;
pub mod object;
pub mod pointer;
pub mod replication;
pub mod serving;

pub use appendset::{AppendSetEntry, AppendSetView, collection_id, validate_entry_context};
pub use chunk::ChunkSpec;
pub use crypto::{Dek, EpochKey};
pub use object::{Cid, EncodedObject, Manifest, decode, encode};
pub use pointer::{DekWrapping, MutablePointer, new_pointer_id};
pub use replication::{
    HoldingAnnouncement, RepairPlan, ReplicationHealth, ReplicationStatus, ReplicationView,
};
pub use serving::{ServingRefusal, may_serve};

/// Errors produced by the storage layer.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StorageError {
    /// The operating system entropy source failed.
    #[error("could not obtain entropy")]
    Entropy,

    /// A sealed blob was too short to contain its nonce.
    #[error("ciphertext is malformed")]
    MalformedCiphertext,

    /// Decryption or authentication failed.
    ///
    /// Deliberately does not distinguish "wrong key" from "tampered
    /// ciphertext": both mean the bytes cannot be trusted, and separating them
    /// would tell an attacker which of the two they achieved.
    #[error("decryption failed")]
    DecryptionFailed,

    /// A manifest could not be parsed.
    #[error("manifest is malformed")]
    MalformedManifest,

    /// A chunk named by a manifest was not available.
    #[error("chunk {cid} is missing")]
    MissingChunk {
        /// The missing chunk, abbreviated.
        cid: String,
    },

    /// A chunk's bytes did not match its content identifier.
    #[error("chunk {cid} failed verification against its content id")]
    ChunkVerificationFailed {
        /// The failing chunk, abbreviated.
        cid: String,
    },

    /// Reassembled content did not match the manifest's declared length.
    #[error("reassembled {got} bytes, manifest declared {expected}")]
    LengthMismatch {
        /// Length the manifest declared.
        expected: u64,
        /// Length actually reassembled.
        got: u64,
    },

    /// A signature failed to verify.
    #[error("signature verification failed")]
    BadSignature,

    /// The network's allowlist does not include this content type.
    #[error("content type '{content_type}' is not on this network's allowlist")]
    ContentTypeNotAllowed {
        /// The rejected type.
        content_type: String,
    },

    /// The publisher does not hold `publish:<content_type>`.
    #[error("identity {identity} may not publish '{content_type}'")]
    PublishNotPermitted {
        /// The publishing identity.
        identity: String,
        /// The type they attempted to publish.
        content_type: String,
    },

    /// Someone other than the owner attempted to update a pointer.
    #[error("pointer is owned by {owner}, update attempted by {attempted_by}")]
    NotPointerOwner {
        /// The pointer's owner.
        owner: String,
        /// Who attempted the update.
        attempted_by: String,
    },

    /// An unwrapped DEK did not match the owner's commitment.
    ///
    /// This is what makes a wrapping valid or not — never who signed it.
    #[error("unwrapped key does not match the owner's commitment")]
    CommitmentMismatch,

    /// An append-set entry's publisher is not a current member.
    #[error("append-set entry publisher {publisher} is not a current member")]
    PublisherNotAMember {
        /// The publishing identity.
        publisher: String,
    },

    /// An append-set entry references content that has been delisted.
    #[error("append-set entry references delisted pointer {pointer}")]
    ReferencesDelistedContent {
        /// The delisted pointer.
        pointer: String,
    },

    /// An entry was inserted into a view of a different collection.
    #[error("entry belongs to a different collection")]
    WrongCollection,
}
