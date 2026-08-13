//! Rendezvous hashing (HRW) — Storage Spec §3.3, Real-Time Spec §3.3.
//!
//! # One routine, two call sites, different weight fields
//!
//! Storage replica placement weights by `storage_offered`, because durability is
//! about who will *hold* bytes. Live-stream first-tier assignment weights by
//! `bandwidth_cap`, because redistribution is about who can *forward* sustained
//! throughput — weighting a media tier by donated disk would rank nodes on a
//! resource the role never consumes.
//!
//! The ranking logic itself is identical, so it lives here once and is
//! parameterized by [`WeightField`] rather than copied. The harness asserts the
//! two call sites genuinely share this routine, since a fork would let them
//! drift apart silently.
//!
//! # Why HRW rather than weighted-random
//!
//! It is **deterministic**: any node can independently recompute the identical
//! replica set from the key and the current ledger, with no gossip about "who
//! was assigned what" and nothing to store. Placement becomes a pure function
//! rather than a decision that has to be made once and remembered.
//!
//! # Why local reliability is not an input
//!
//! `reliability_signal` is local-only and never gossiped (Core Protocol Spec
//! §4.6). Feeding it into this function would mean every node computing a
//! different replica set from the same inputs, destroying the one property HRW
//! was chosen for. Unreliable nodes are corrected for by the repair loop
//! (Storage Spec §3.4) instead — remediation based on observed outcomes rather
//! than on evidence no two nodes share. Nothing in this module's signature can
//! accept a local observation, which is deliberate.

use crate::CapabilityAdvertisement;
use intranet_crypto::{Enc, hash_bytes};
use intranet_identity::PerNetworkIdentityId;

/// Which declared capacity a ranking weights by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WeightField {
    /// Bytes offered for replicated content — storage replica placement.
    StorageOffered,
    /// Upload throughput offered — live-stream redistribution tiers.
    BandwidthUp,
}

impl WeightField {
    /// Extracts this field's value from an advertisement.
    pub fn weight_of(self, advertisement: &CapabilityAdvertisement) -> u64 {
        match self {
            Self::StorageOffered => advertisement.storage_offered,
            Self::BandwidthUp => advertisement.bandwidth_cap.up_bytes_per_sec,
        }
    }
}

/// One candidate's computed placement score.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScoredCandidate {
    /// The candidate node.
    pub node: PerNetworkIdentityId,
    /// Its score for this key. Higher ranks earlier.
    pub score: u128,
}

/// Computes the HRW score for one candidate.
///
/// Follows the specs' formula directly: `hash(key, node_id) × weight`.
///
/// Arithmetic is integer throughout, in `u128` to hold the full product without
/// overflow. Floating point would introduce a portability question this design
/// cannot afford — two nodes disagreeing in the last bit of a score would
/// produce different replica sets, which is exactly the divergence HRW exists to
/// prevent.
pub fn score(key: &[u8], node: &PerNetworkIdentityId, weight: u64) -> u128 {
    let mut e = Enc::domain("intranet.hrw.v1");
    e.bytes(key);
    node.encode(&mut e);
    let digest = hash_bytes(&e.finish());

    let draw = u64::from_be_bytes(
        digest.as_bytes()[..8]
            .try_into()
            .expect("8-byte prefix of a 32-byte digest"),
    );
    u128::from(draw) * u128::from(weight)
}

/// Ranks candidates for `key`, highest score first.
///
/// Candidates whose weight is zero are **excluded entirely**, not merely ranked
/// last. Contribution is opt-in: a node declaring no storage has not volunteered
/// to hold replicas, and assigning it any would conscript it. This is why a
/// caller can receive fewer than it asked for, which §3.2 requires anyway.
///
/// Ties break on the node identifier ascending, so the ordering is total and
/// every node computes the same one.
pub fn rank<'a>(
    key: &[u8],
    candidates: impl IntoIterator<Item = &'a CapabilityAdvertisement>,
    weight_field: WeightField,
) -> Vec<ScoredCandidate> {
    let mut scored: Vec<ScoredCandidate> = candidates
        .into_iter()
        .filter_map(|advertisement| {
            let weight = weight_field.weight_of(advertisement);
            (weight > 0).then(|| ScoredCandidate {
                node: advertisement.node,
                score: score(key, &advertisement.node, weight),
            })
        })
        .collect();

    scored.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.node.cmp(&b.node)));
    scored
}

/// Selects the top `n` candidates for `key`.
///
/// Returns fewer than `n` when too few eligible nodes exist. That is a
/// deliberate, specified behaviour rather than an error (§3.2): a three-person
/// network should still function, just with weaker durability, and the protocol
/// must never punish a small network by refusing to operate. Callers are
/// expected to surface the shortfall so degraded durability is visible rather
/// than silent.
pub fn select<'a>(
    key: &[u8],
    candidates: impl IntoIterator<Item = &'a CapabilityAdvertisement>,
    weight_field: WeightField,
    n: usize,
) -> Vec<PerNetworkIdentityId> {
    rank(key, candidates, weight_field)
        .into_iter()
        .take(n)
        .map(|candidate| candidate.node)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BandwidthCap, ComputeClass};
    use intranet_crypto::Timestamp;
    use intranet_identity::{MasterSeed, NetworkId};

    const NETWORK: NetworkId = NetworkId::from_bytes([1u8; 32]);

    fn advert(seed: u8, storage: u64, up: u64) -> CapabilityAdvertisement {
        let node = MasterSeed::from_entropy([seed; 32])
            .identity_for(&NETWORK)
            .unwrap();
        CapabilityAdvertisement::create(
            &node,
            storage,
            BandwidthCap {
                up_bytes_per_sec: up,
                down_bytes_per_sec: up * 4,
                active_window: None,
            },
            false,
            true,
            ComputeClass::Modest,
            Timestamp::from_millis(0),
        )
    }

    fn pool() -> Vec<CapabilityAdvertisement> {
        (1u8..=12).map(|i| advert(i, 1_000_000, 500_000)).collect()
    }

    #[test]
    fn placement_is_deterministic_across_independent_computations() {
        let pool = pool();
        let a = select(b"cid-1", &pool, WeightField::StorageOffered, 3);
        let b = select(b"cid-1", &pool, WeightField::StorageOffered, 3);
        assert_eq!(a, b);
    }

    #[test]
    fn placement_does_not_depend_on_candidate_order() {
        // Two nodes hold their ledgers in different orders; they must still
        // compute the identical replica set.
        let pool = pool();
        let forward: Vec<&CapabilityAdvertisement> = pool.iter().collect();
        let mut reversed = forward.clone();
        reversed.reverse();

        assert_eq!(
            select(b"cid-1", forward, WeightField::StorageOffered, 4),
            select(b"cid-1", reversed, WeightField::StorageOffered, 4)
        );
    }

    #[test]
    fn different_keys_reshuffle_the_ranking() {
        // The anti-correlation property: a node that ranks first for one CID is
        // unlikely to rank first for most others, so the storage burden and the
        // practical takedown surface do not concentrate on a few nodes.
        let pool = pool();
        let mut firsts = std::collections::BTreeSet::new();
        for i in 0..40u32 {
            let key = format!("cid-{i}");
            if let Some(first) = select(key.as_bytes(), &pool, WeightField::StorageOffered, 1).first()
            {
                firsts.insert(*first);
            }
        }
        assert!(
            firsts.len() > 5,
            "expected the top slot to spread across the pool, saw {} distinct winners",
            firsts.len()
        );
    }

    #[test]
    fn higher_declared_capacity_earns_proportionally_more_assignments() {
        // The weighting is not discarded by the reshuffling: a node offering ten
        // times the capacity should win noticeably more often.
        let mut pool: Vec<CapabilityAdvertisement> =
            (1u8..=9).map(|i| advert(i, 1_000_000, 100_000)).collect();
        let generous = advert(50, 10_000_000, 100_000);
        let generous_node = generous.node;
        pool.push(generous);

        let mut wins = 0;
        for i in 0..200u32 {
            let key = format!("cid-{i}");
            if select(key.as_bytes(), &pool, WeightField::StorageOffered, 1)
                .first()
                .is_some_and(|node| *node == generous_node)
            {
                wins += 1;
            }
        }
        // Fair share for one of ten nodes is 20; ten times the weight should
        // clear that comfortably without being guaranteed every slot.
        assert!(
            wins > 40,
            "a node offering 10x capacity won only {wins}/200 top slots"
        );
    }

    #[test]
    fn nodes_offering_nothing_are_never_assigned() {
        // Contribution is opt-in. Assigning replicas to a node that declared no
        // storage would conscript it.
        let pool = vec![
            advert(1, 0, 500_000),
            advert(2, 0, 500_000),
            advert(3, 1_000_000, 500_000),
        ];
        let selected = select(b"cid-1", &pool, WeightField::StorageOffered, 3);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0], pool[2].node);
    }

    #[test]
    fn a_small_network_degrades_rather_than_failing() {
        // §3.2: replicate to as many nodes as are available rather than refusing
        // to operate. A three-person friend network must still work.
        let pool: Vec<CapabilityAdvertisement> =
            (1u8..=2).map(|i| advert(i, 1_000_000, 500_000)).collect();
        let selected = select(b"cid-1", &pool, WeightField::StorageOffered, 5);
        assert_eq!(selected.len(), 2, "returns what exists, does not error");
    }

    #[test]
    fn the_two_weight_fields_produce_different_rankings() {
        // Same routine, different field. A node generous with disk but stingy
        // with upload should rank differently for storage than for streaming.
        let pool = vec![
            advert(1, 10_000_000, 1_000),     // lots of disk, little upload
            advert(2, 1_000, 10_000_000),     // little disk, lots of upload
            advert(3, 1_000_000, 1_000_000),
        ];

        let storage = select(b"key", &pool, WeightField::StorageOffered, 1);
        let streaming = select(b"key", &pool, WeightField::BandwidthUp, 1);
        assert_eq!(storage, vec![pool[0].node]);
        assert_eq!(streaming, vec![pool[1].node]);
    }

    #[test]
    fn ranking_is_a_total_order_with_a_deterministic_tie_break() {
        // Equal weights leave scores decided purely by the hash; identical
        // scores (astronomically unlikely, but the ordering must still be total)
        // break on node id so every node agrees.
        let pool = pool();
        let ranked = rank(b"cid-1", &pool, WeightField::StorageOffered);
        for pair in ranked.windows(2) {
            let ordered = pair[0].score > pair[1].score
                || (pair[0].score == pair[1].score && pair[0].node < pair[1].node);
            assert!(ordered, "ranking must be a strict total order");
        }
    }

    #[test]
    fn over_replication_extends_the_same_ranking() {
        // §3.3.1: volunteer over-replication needs no separate workflow — the
        // same ranked list simply extends past the cutoff at N.
        let pool = pool();
        let minimum = select(b"cid-1", &pool, WeightField::StorageOffered, 3);
        let extended = select(b"cid-1", &pool, WeightField::StorageOffered, 6);

        assert_eq!(
            extended[..3],
            minimum[..],
            "extra copies must extend the guaranteed set, not reshuffle it"
        );
    }
}
