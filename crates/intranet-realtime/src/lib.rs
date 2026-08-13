//! Real-time transport — Real-Time Spec.
//!
//! Three transport primitives that share machinery but not behaviour:
//!
//! - **Calls** ([`call`], [`keying`], [`relay`]) — symmetric, few-to-few,
//!   latency-critical. Direct mesh below a configured participant count, blind
//!   relay above it.
//! - **Live streams** ([`stream`]) — asymmetric, one-to-many, latency-tolerant
//!   by seconds. A live-propagating swarm where viewers redistribute as they
//!   receive.
//! - **VOD** ([`stream::VodRetention`]) — a finished broadcast becoming ordinary
//!   content, with no re-encryption and no new storage mechanism.
//!
//! # The confidentiality asymmetry, stated plainly
//!
//! Call relays are genuinely **blind**: call keys are scoped to the
//! participants, so a relay cannot decrypt what it forwards regardless of what
//! else it is a member of.
//!
//! Stream redistributors are **not**. They are ordinary network members who
//! legitimately hold the epoch key, so they *could* decrypt what they forward
//! even though nothing about forwarding requires it. That is acceptable for a
//! network-wide broadcast, where every redistributor is already entitled to the
//! content — but it is a different posture, and conflating the two would
//! overclaim the guarantee a stream provides.
//!
//! # Out of scope
//!
//! Codecs, segment durations, jitter buffers, and the calling UI. This layer
//! decides *who* media flows through and *how the topology changes*; it does not
//! encode anything.

pub mod call;
pub mod keying;
pub mod relay;
pub mod stream;

pub use call::{CallSession, ProposalOutcome, RenegotiationTrigger, Topology, TopologyProposal};
pub use keying::{CallId, CallKey, CallKeyEnvelope, MediaFrame};
pub use relay::{RelayChoice, RelayObservation};
pub use stream::{LiveStream, StreamConfidentiality, StreamId, VodRetention, assign_tier};

/// Errors produced by the real-time layer.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RealtimeError {
    /// The operating system entropy source failed.
    #[error("could not obtain entropy")]
    Entropy,

    /// A media frame failed authentication.
    ///
    /// Reported per frame so a receiver can distinguish a corrupted frame from a
    /// wholesale key mismatch — and so a relay attempting to inject or modify
    /// traffic is detected at the receiving participant rather than tolerated.
    #[error("media frame {sequence} failed authentication")]
    FrameAuthenticationFailed {
        /// The frame's sequence number.
        sequence: u64,
    },

    /// Key agreement or envelope handling failed.
    #[error("call key agreement failed")]
    KeyAgreementFailed,

    /// An envelope was opened by someone other than its recipient.
    #[error("this call key envelope is addressed to a different participant")]
    NotTheRecipient,

    /// A relay was needed but none was available.
    #[error("no eligible media relay is available")]
    NoRelayAvailable,

    /// A handover was completed with nothing pending.
    #[error("no topology handover is in progress")]
    NoHandoverPending,

    /// A broadcast with no chunks cannot become VOD.
    #[error("cannot convert an empty broadcast to VOD")]
    EmptyBroadcast,

    /// The chunk sequence has a hole in it.
    #[error("chunk sequence gap: {found} follows {after}")]
    ChunkSequenceGap {
        /// The last chunk before the gap.
        after: u64,
        /// The next chunk actually present.
        found: u64,
    },
}
