//! Live streaming and VOD conversion — Real-Time Spec §3, §4.
//!
//! # Why a stream is neither a call nor static content
//!
//! A call is symmetric and latency-critical: delay breaks conversation. A stream
//! is asymmetric and latency-*tolerant* by a few seconds, which is normal and
//! expected. But it is not static swarm-serving either — finished content sits
//! still, whereas a stream's most recent chunk did not exist a moment ago, so
//! viewers need chunks pushed to them promptly rather than fetched whenever
//! convenient.
//!
//! # The broadcaster's upload cost stays flat
//!
//! A viewer holding chunk N immediately becomes a source for chunk N while it is
//! still fresh — the same "anyone who fetched it can serve it" principle as
//! static content, applied to a live-advancing window. The broadcaster hands
//! each chunk to a first tier who forward it onward, so cost scales with the
//! swarm's capacity rather than the broadcaster's connection.

use crate::RealtimeError;
use intranet_crypto::Hash;
use intranet_identity::PerNetworkIdentityId;
use intranet_ledger::{CapabilityLedger, WeightField, placement};
use intranet_storage::{Cid, Manifest};
use std::collections::{BTreeMap, BTreeSet};

/// A live broadcast's identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, std::hash::Hash)]
pub struct StreamId(Hash);

impl StreamId {
    /// Wraps a hash as a stream identifier.
    pub const fn from_hash(hash: Hash) -> Self {
        Self(hash)
    }

    /// The underlying hash.
    pub const fn hash(&self) -> &Hash {
        &self.0
    }
}

/// Assigns a stream's first redistribution tier — §3.3.
///
/// Reuses the storage layer's HRW placement, weighted by `bandwidth_cap` rather
/// than `storage_offered`: this role forwards sustained throughput rather than
/// holding bytes, so weighting it by donated disk would rank nodes on a resource
/// the job never touches. The ranking logic itself is shared, not copied.
///
/// Being deterministic means any node computes the same tier from the stream id
/// and the current ledger — no "promote to redistributor" signalling, no
/// broadcaster decision-making, nothing to coordinate.
///
/// Local reliability is deliberately not an input, for the same reason it is not
/// an input to replica placement: every node must compute the same tier, and a
/// per-observer private signal would make them disagree.
pub fn assign_tier(
    stream: &StreamId,
    ledger: &CapabilityLedger,
    tier_size: usize,
) -> Vec<PerNetworkIdentityId> {
    placement::select(
        stream.hash().as_bytes(),
        ledger.media_relay_candidates(),
        WeightField::BandwidthUp,
        tier_size,
    )
}

/// A live broadcast in progress.
#[derive(Debug, Clone)]
pub struct LiveStream {
    stream: StreamId,
    tier: Vec<PerNetworkIdentityId>,
    tier_size: usize,
    /// Which chunks each participant is known to hold, for the live window.
    holders: BTreeMap<u64, BTreeSet<PerNetworkIdentityId>>,
    chunks: BTreeMap<u64, Cid>,
    window: usize,
}

impl LiveStream {
    /// Starts a broadcast, computing its first tier.
    ///
    /// The tier is computed **once per stream, not per chunk**. Recomputing
    /// constantly would have the broadcaster tearing down and rebuilding
    /// connections on a sub-second basis for no benefit; a stable tier lets it
    /// hold persistent connections to a small fixed set for the session.
    pub fn start(stream: StreamId, ledger: &CapabilityLedger, tier_size: usize, window: usize) -> Self {
        Self {
            stream,
            tier: assign_tier(&stream, ledger, tier_size),
            tier_size,
            holders: BTreeMap::new(),
            chunks: BTreeMap::new(),
            window,
        }
    }

    /// This stream's identifier.
    pub fn id(&self) -> &StreamId {
        &self.stream
    }

    /// The current first redistribution tier.
    pub fn tier(&self) -> &[PerNetworkIdentityId] {
        &self.tier
    }

    /// Records a freshly produced chunk.
    ///
    /// Older chunks fall out of the live window: a live-propagating swarm cares
    /// about what is still fresh, and everything else becomes VOD's problem.
    pub fn produce_chunk(&mut self, sequence: u64, cid: Cid) {
        self.chunks.insert(sequence, cid);
        self.holders.entry(sequence).or_default();

        while self.chunks.len() > self.window {
            let Some(oldest) = self.chunks.keys().next().copied() else {
                break;
            };
            self.chunks.remove(&oldest);
            self.holders.remove(&oldest);
        }
    }

    /// Records that a viewer now holds a chunk.
    ///
    /// From this moment they are a source for it to other viewers, with no
    /// explicit promotion — the same automatic swarm membership static content
    /// uses, applied to a live window.
    pub fn record_holder(&mut self, sequence: u64, viewer: PerNetworkIdentityId) {
        if self.chunks.contains_key(&sequence) {
            self.holders.entry(sequence).or_default().insert(viewer);
        }
    }

    /// Who can currently serve a chunk.
    pub fn sources_for(&self, sequence: u64) -> Vec<PerNetworkIdentityId> {
        self.holders
            .get(&sequence)
            .map(|set| set.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Chunks still inside the live window, oldest first.
    pub fn live_window(&self) -> Vec<(u64, Cid)> {
        self.chunks.iter().map(|(seq, cid)| (*seq, *cid)).collect()
    }

    /// Whether the tier needs recomputing.
    ///
    /// The same repair-trigger pattern storage uses, applied to a live context:
    /// react when a member actually drops out or stops being eligible, rather
    /// than recomputing on a timer.
    pub fn tier_needs_recompute(&self, ledger: &CapabilityLedger) -> bool {
        self.tier.iter().any(|node| {
            ledger
                .get(node)
                .is_none_or(|advertisement| !advertisement.relay_media_willing)
        })
    }

    /// Recomputes the tier after a member dropped out.
    pub fn recompute_tier(&mut self, ledger: &CapabilityLedger) {
        self.tier = assign_tier(&self.stream, ledger, self.tier_size);
    }

    /// Converts a finished broadcast into ordinary immutable content — §4.1.
    ///
    /// # No re-encryption, by construction
    ///
    /// The live chunks are already content-addressed ciphertext under the
    /// object's own key, so conversion is not a transformation at all: it is
    /// deciding to stop treating a live-advancing window as live and start
    /// treating a finished set as finished. The exact same bytes become the VOD.
    ///
    /// Requires the full chunk sequence, which a broadcaster retains as it goes.
    /// Passing only what is still in the live window would silently produce a
    /// truncated recording, so the caller supplies the whole thing explicitly.
    pub fn into_vod(
        self,
        all_chunks: &[(u64, Cid)],
        plaintext_len: u64,
        retention: VodRetention,
    ) -> Result<Option<Manifest>, RealtimeError> {
        if retention == VodRetention::Disabled {
            return Ok(None);
        }
        if all_chunks.is_empty() {
            return Err(RealtimeError::EmptyBroadcast);
        }

        let mut ordered: Vec<(u64, Cid)> = all_chunks.to_vec();
        ordered.sort_by_key(|(sequence, _)| *sequence);

        // A gap means the recording would be silently incomplete, which is worse
        // than refusing: a viewer cannot tell a missing middle from an edit.
        for pair in ordered.windows(2) {
            if pair[1].0 != pair[0].0 + 1 {
                return Err(RealtimeError::ChunkSequenceGap {
                    after: pair[0].0,
                    found: pair[1].0,
                });
            }
        }

        Ok(Some(Manifest {
            chunks: ordered.into_iter().map(|(_, cid)| cid).collect(),
            plaintext_len,
        }))
    }
}

/// Whether a finished broadcast is retained as VOD — §4.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VodRetention {
    /// Convert the finished broadcast into ordinary swarm-servable content.
    #[default]
    Enabled,
    /// Do not publish a discoverable record of the broadcast.
    ///
    /// # What this does and does not prevent
    ///
    /// It stops the *platform* surfacing a retrievable record. It does **not**,
    /// and cannot, stop a viewer who received the live chunks from keeping and
    /// republishing them. That is not a gap specific to this design: anything
    /// decrypted and shown to a legitimate viewer can be captured by that
    /// viewer, in any system. Presenting this as stronger than it is would
    /// mislead a broadcaster about a decision they may care about.
    Disabled,
}

/// A stream's confidentiality posture — §3.5.
///
/// Stated as a type so the asymmetry is hard to miss when wiring a stream up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamConfidentiality {
    /// Encrypted under the network epoch key, as all content is.
    ///
    /// **Redistributors are not blind.** A call relay genuinely cannot decrypt
    /// what it forwards, because call keys are scoped to the participants. A
    /// stream's first-tier nodes are ordinary network members who legitimately
    /// hold the epoch key, so they *could* decrypt what they forward even though
    /// nothing about forwarding requires it. "They don't need to decrypt" and
    /// "they cannot decrypt" are different claims and only the first is true
    /// here.
    ///
    /// Acceptable for a network-wide broadcast, where every redistributor is
    /// already entitled to the content. A future restricted-audience stream
    /// cannot reuse this: the epoch key is shared network-wide by definition, so
    /// such a feature would need its own scoped key, closer to how calls work.
    NetworkWide,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cid(n: u8) -> Cid {
        Cid::from_hash(Hash::from_bytes([n; 32]))
    }

    fn stream() -> StreamId {
        StreamId::from_hash(Hash::from_bytes([1u8; 32]))
    }

    fn empty_stream(window: usize) -> LiveStream {
        LiveStream {
            stream: stream(),
            tier: Vec::new(),
            tier_size: 3,
            holders: BTreeMap::new(),
            chunks: BTreeMap::new(),
            window,
        }
    }

    #[test]
    fn the_live_window_drops_the_oldest_chunks() {
        let mut live = empty_stream(3);
        for n in 1u8..=5 {
            live.produce_chunk(u64::from(n), cid(n));
        }
        let window = live.live_window();
        assert_eq!(window.len(), 3);
        assert_eq!(window[0].0, 3, "the oldest two have aged out");
    }

    #[test]
    fn a_viewer_becomes_a_source_with_no_explicit_promotion() {
        let mut live = empty_stream(5);
        live.produce_chunk(1, cid(1));
        let viewer = PerNetworkIdentityId::from_verifying_key(
            intranet_crypto::SecretKey::from_bytes([9u8; 32]).verifying_key(),
        );

        assert!(live.sources_for(1).is_empty());
        live.record_holder(1, viewer);
        assert_eq!(live.sources_for(1), vec![viewer]);
    }

    #[test]
    fn holding_a_chunk_outside_the_window_is_not_recorded() {
        let mut live = empty_stream(1);
        live.produce_chunk(1, cid(1));
        live.produce_chunk(2, cid(2));
        let viewer = PerNetworkIdentityId::from_verifying_key(
            intranet_crypto::SecretKey::from_bytes([9u8; 32]).verifying_key(),
        );
        live.record_holder(1, viewer);
        assert!(live.sources_for(1).is_empty(), "chunk 1 has aged out");
    }

    #[test]
    fn vod_conversion_preserves_the_exact_chunk_sequence() {
        let live = empty_stream(2);
        let all: Vec<(u64, Cid)> = (1u8..=4).map(|n| (u64::from(n), cid(n))).collect();
        let manifest = live
            .into_vod(&all, 4_000, VodRetention::Enabled)
            .unwrap()
            .expect("retention enabled");

        assert_eq!(manifest.chunks.len(), 4);
        assert_eq!(manifest.chunks[0], cid(1));
        assert_eq!(manifest.plaintext_len, 4_000);
    }

    #[test]
    fn vod_conversion_accepts_chunks_in_any_order() {
        let live = empty_stream(2);
        let mut all: Vec<(u64, Cid)> = (1u8..=4).map(|n| (u64::from(n), cid(n))).collect();
        all.reverse();
        let manifest = live.into_vod(&all, 100, VodRetention::Enabled).unwrap().unwrap();
        assert_eq!(manifest.chunks[0], cid(1), "sorted by sequence");
    }

    #[test]
    fn a_gap_in_the_sequence_is_refused_rather_than_silently_truncating() {
        // A viewer cannot tell a missing middle from an edit, so producing a
        // quietly incomplete recording is worse than producing none.
        let live = empty_stream(2);
        let gapped = vec![(1u64, cid(1)), (2, cid(2)), (4, cid(4))];
        assert!(matches!(
            live.into_vod(&gapped, 100, VodRetention::Enabled),
            Err(RealtimeError::ChunkSequenceGap { after: 2, found: 4 })
        ));
    }

    #[test]
    fn opting_out_produces_no_manifest() {
        let live = empty_stream(2);
        let all = vec![(1u64, cid(1))];
        assert!(
            live.into_vod(&all, 100, VodRetention::Disabled)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn an_empty_broadcast_cannot_become_vod() {
        let live = empty_stream(2);
        assert!(matches!(
            live.into_vod(&[], 0, VodRetention::Enabled),
            Err(RealtimeError::EmptyBroadcast)
        ));
    }
}
