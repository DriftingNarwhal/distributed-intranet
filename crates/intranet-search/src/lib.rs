//! Search and indexing — Search Spec.
//!
//! # Why this layer exists at all
//!
//! If this platform succeeds, it produces a large number of independent, small
//! networks. Without a native way to discover content *within* one, the
//! predictable failure mode is that somebody builds a crawler to compensate —
//! reintroducing exactly the bot-traffic problem the project exists partly to
//! avoid.
//!
//! The design principle that follows: **discoverability is a property of
//! publishing, not something bolted on afterwards by an external agent polling
//! the network.** A posting is derived from content in the same action that
//! publishes it, so there is nothing for a crawler to do.
//!
//! # Search is permanently single-network
//!
//! Not a current limitation — a consequence of decisions already locked in.
//! Every network is independently keyed, independently membered, and
//! deliberately unlinkable from any other a node participates in. A cross-network
//! index would require either a common index spanning independent trust
//! boundaries or a node correlating its own memberships across networks, and
//! both undo guarantees the identity model is built on.
//!
//! This is enforced structurally rather than by a check: a term's collection key
//! is derived from the network ID, and [`LocalIndex`] is scoped to one network
//! at construction. There is no API through which a cross-network query could be
//! expressed.
//!
//! # What this layer does not fix
//!
//! Signed postings and mandatory validation do **not** eliminate keyword
//! stuffing. A current, legitimate member can still self-attest misleading tags
//! to inflate their own ranking — the same SEO problem the ordinary web has.
//! That risk is accepted for the same reason it is accepted elsewhere: this is a
//! permissioned network of identity-gated members, and moderation provides a
//! real remedy, now backed by a fully enforced validation path rather than by
//! hoping a spammer stops re-announcing.

pub mod document;
pub mod index;
pub mod posting;
pub mod query;
pub mod tokenize;

pub use document::{ContentMetadata, Field, IndexDocument, IndexableContent};
pub use index::LocalIndex;
pub use posting::{DEFAULT_POSTING_TTL_MILLIS, Posting, TermStats};
pub use query::{SearchResult, SearchResults, search};
pub use tokenize::{Term, tokenize};

/// Errors produced by the search layer.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SearchError {
    /// A signature failed to verify.
    #[error("signature verification failed")]
    BadSignature,

    /// A posting failed the shared append-set validation checks.
    #[error(transparent)]
    Rejected(#[from] intranet_storage::StorageError),

    /// A posting was offered to an index for a different network.
    #[error("posting belongs to a different network")]
    WrongNetwork,
}
