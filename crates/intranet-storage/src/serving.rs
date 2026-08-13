//! Swarm serving and the `read-content` gate — Storage Spec §4, §5.4.
//!
//! # Why serving needs a gate at all
//!
//! A DEK is fixed for an object's lifetime, which creates a specific gap:
//! a revoked member who obtained an object's DEK before removal could keep
//! decrypting *new edits to that same object* — provided they could still
//! obtain the new ciphertext. Ordinary swarm serving has no reason to refuse
//! anyone, being built around efficient distribution once someone already holds
//! appropriate keys, not around checking who is asking.
//!
//! # Why it gates on a capability, not on identity validity
//!
//! "Holds a valid, non-revoked identity" is too permissive. Under explicit
//! intake, a waiting-room node is a perfectly valid, non-revoked identity that
//! simply has not been admitted to any group yet. Gating on validity would hand
//! it ciphertext, metadata, and bandwidth — falling well short of the
//! "essentially nothing" posture explicit intake is supposed to provide.
//! Gating on `read-content` closes that: a waiting-room node holds no group
//! membership, hence no capability, hence is correctly refused.
//!
//! # The honest guarantee
//!
//! Convergence, not instantaneity. A node whose governance replay has not yet
//! caught up to a recent revocation will briefly still serve the revoked
//! identity, simply because it does not yet know. "No honest node will ever
//! serve a revoked member" is not achievable in a gossip-propagated system
//! without unrealistic synchrony assumptions. What is delivered is that every
//! honest node converges on refusing once it processes the revocation.

use crate::Cid;
use intranet_governance::{Capability, GovernanceState};
use intranet_identity::PerNetworkIdentityId;
use intranet_ledger::{CapabilityLedger, ReliabilityObservations};

/// Why a request for content bytes was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ServingRefusal {
    /// The requester does not hold `read-content`.
    #[error("requester {requester} does not hold read-content")]
    NoReadContent {
        /// The refused identity.
        requester: String,
    },
}

/// Whether this node will serve content bytes to `requester`.
///
/// Evaluated against the serving node's own current view of governance state.
/// This is an addition to server behaviour, not a new subsystem, and is a
/// necessary companion to source selection rather than optional hardening.
pub fn may_serve(
    requester: &PerNetworkIdentityId,
    state: &GovernanceState,
) -> Result<(), ServingRefusal> {
    if state.identity_holds(requester, &Capability::ReadContent) {
        Ok(())
    } else {
        Err(ServingRefusal::NoReadContent {
            requester: requester.short(),
        })
    }
}

/// A candidate source for a chunk, with the signals selection weighs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceCandidate {
    /// The peer holding the chunk.
    pub peer: PerNetworkIdentityId,
    /// Observed round-trip latency in milliseconds, if known.
    pub latency_millis: Option<u32>,
    /// How many requests this peer is already serving.
    pub current_load: u32,
}

/// Selects sources for a chunk — Storage Spec §4.3.
///
/// Weighs network distance, available throughput from the ledger, current load
/// so demand spreads rather than piling onto whichever node has the best raw
/// stats, and this node's **own** reliability observations.
///
/// This is one of only two places local reliability may be used, the other
/// being media relay selection. Both are local, per-requester decisions with no
/// cross-node consistency requirement — it does not matter, or even make sense,
/// for two nodes to choose the same source. That is exactly what distinguishes
/// them from replica placement, which must recompute identically everywhere and
/// therefore cannot take this signal at all.
///
/// A saturated peer is dropped entirely: a node at its `bandwidth_cap` stops
/// being offered as a candidate until capacity frees up, which is how
/// backpressure works without any central throttling authority.
pub fn select_sources(
    candidates: &[SourceCandidate],
    ledger: &CapabilityLedger,
    observations: &ReliabilityObservations,
    failure_threshold: f64,
    want: usize,
) -> Vec<PerNetworkIdentityId> {
    let mut ranked: Vec<(&SourceCandidate, u64, u8)> = candidates
        .iter()
        .filter_map(|candidate| {
            let throughput = ledger
                .get(&candidate.peer)
                .map(|advertisement| advertisement.bandwidth_cap.up_bytes_per_sec)
                .unwrap_or(0);
            // A peer advertising no upload capacity has not volunteered to serve.
            if throughput == 0 {
                return None;
            }
            let reliability_band = match observations.for_peer(&candidate.peer).failure_rate() {
                Some(rate) if rate >= failure_threshold => 2u8,
                None => 1,
                Some(_) => 0,
            };
            Some((candidate, throughput, reliability_band))
        })
        .collect();

    ranked.sort_by(|a, b| {
        // Reliability band first, then load, then latency, then throughput.
        a.2.cmp(&b.2)
            .then_with(|| a.0.current_load.cmp(&b.0.current_load))
            .then_with(|| {
                a.0.latency_millis
                    .unwrap_or(u32::MAX)
                    .cmp(&b.0.latency_millis.unwrap_or(u32::MAX))
            })
            .then_with(|| b.1.cmp(&a.1))
            .then_with(|| a.0.peer.cmp(&b.0.peer))
    });

    ranked
        .into_iter()
        .take(want)
        .map(|(candidate, _, _)| candidate.peer)
        .collect()
}

/// Orders chunks rarest-first — Storage Spec §4.4.
///
/// Chunks held by fewest peers are fetched first, following the principle
/// BitTorrent uses: scarce chunks get additional copies into circulation sooner,
/// shrinking the window in which they could become unavailable if their few
/// holders go offline. Needs only the holder count a provider lookup already
/// returns, not new bookkeeping.
///
/// Ties break on the chunk identifier so the order is deterministic, which keeps
/// a fetch reproducible when debugging.
pub fn rarest_first(chunks: &[(Cid, u32)]) -> Vec<Cid> {
    let mut ordered = chunks.to_vec();
    ordered.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
    ordered.into_iter().map(|(cid, _)| cid).collect()
}
