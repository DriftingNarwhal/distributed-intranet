//! Capability ledger — Core Protocol Spec §4.
//!
//! A single, consistent mechanism by which every node advertises what it is
//! willing to contribute, **per network**, that every other subsystem reads from
//! rather than each building its own resource-negotiation logic. Storage
//! placement, media relay selection, and swarm source selection are all
//! consumers; none of them should invent a parallel way to ask "what will this
//! node do for us".
//!
//! # The split that matters
//!
//! Two kinds of information live here and must not be confused:
//!
//! - [`CapabilityAdvertisement`] is **declared and gossiped** — what a node says
//!   it will contribute. Signed by the node, visible to everyone, and therefore
//!   usable as an input to deterministic cross-node computations like
//!   [`placement`].
//! - [`ReliabilityObservations`] is **observed and private** — what one node has
//!   seen about its peers. Never gossiped, never advertised, and therefore
//!   usable only for local selection decisions.
//!
//! Collapsing these was a real defect in an earlier draft of the specs: replica
//! placement was specified to weight by both, which would have made a
//! deliberately deterministic function depend on state no two nodes agree on.

mod advertisement;
pub mod placement;
pub mod reliability;
pub mod wire;

pub use advertisement::{BandwidthCap, CapabilityAdvertisement, ComputeClass, TimeOfDayWindow};
pub use placement::{ScoredCandidate, WeightField};
pub use wire::{
    LedgerRequest, LedgerResponse, MAX_ADVERTISEMENTS_PER_RESPONSE, decode_advertisement,
    encode_advertisement,
};
pub use reliability::{
    AuditRateLimit, AuditRequest, AuditResponse, PeerObservations, ReliabilityObservations,
};

use intranet_crypto::Timestamp;
use intranet_governance::GovernanceState;
use intranet_identity::{NetworkId, PerNetworkIdentityId};
use std::collections::BTreeMap;

/// Errors produced by the capability ledger.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LedgerError {
    /// A signature failed to verify.
    #[error("signature verification failed")]
    BadSignature,

    /// An advertisement was for a different network than the ledger.
    #[error("advertisement is for network {advertisement_network}, ledger is for {ledger_network}")]
    NetworkMismatch {
        /// Network named by the advertisement.
        advertisement_network: String,
        /// Network of the ledger.
        ledger_network: String,
    },

    /// The advertising identity is not a current member of the network.
    #[error("advertising identity {node} is not a current member")]
    NotAMember {
        /// The advertising identity.
        node: String,
    },

    /// An audit was requested by someone without `audit-reputation`.
    #[error("audit requester {requester} does not hold audit-reputation")]
    AuditNotAuthorized {
        /// The requesting identity.
        requester: String,
    },

    /// An audit requester exceeded its rate limit.
    #[error("audit requester {requester} exceeded {max_requests} requests per window")]
    AuditRateLimited {
        /// The requesting identity.
        requester: String,
        /// The configured ceiling.
        max_requests: u32,
    },
}

/// How long an advertisement stays usable without refresh.
///
/// **Flagged: §4.5 calls refresh cadence implementation-level tuning and gives
/// no number.** Thirty minutes is long enough that a node need not chatter, and
/// short enough that a departed node stops attracting placement decisions within
/// a window comparable to governance finality.
pub const DEFAULT_TTL_MILLIS: i64 = 30 * 60_000;

/// Locally cached view of what peers have advertised for one network.
///
/// There is deliberately no central store: advertisements are gossiped among
/// members and cached by whoever needs to make placement or selection decisions.
/// Staleness tolerance is a local matter, which is why the TTL is a parameter
/// here rather than network policy.
#[derive(Debug, Clone)]
pub struct CapabilityLedger {
    network: NetworkId,
    entries: BTreeMap<PerNetworkIdentityId, CapabilityAdvertisement>,
}

impl CapabilityLedger {
    /// Creates an empty ledger for a network.
    pub fn new(network: NetworkId) -> Self {
        Self {
            network,
            entries: BTreeMap::new(),
        }
    }

    /// The network this ledger describes.
    pub fn network(&self) -> &NetworkId {
        &self.network
    }

    /// Records an advertisement, replacing any older one from the same node.
    ///
    /// Validates three things, all necessary:
    ///
    /// 1. The signature, so an advertisement cannot be forged on a node's behalf
    ///    — otherwise anyone could inflate a victim's declared capacity and
    ///    steer placement onto it.
    /// 2. The network, so an advertisement from one network cannot be replayed
    ///    into another.
    /// 3. Current membership, so a revoked node stops attracting placement once
    ///    governance replay converges.
    ///
    /// A strictly older advertisement is ignored rather than treated as an
    /// error: gossip reordering is ordinary, not a fault.
    pub fn insert(
        &mut self,
        advertisement: CapabilityAdvertisement,
        state: &GovernanceState,
    ) -> Result<(), LedgerError> {
        advertisement.verify()?;

        if advertisement.network != self.network {
            return Err(LedgerError::NetworkMismatch {
                advertisement_network: advertisement.network.short(),
                ledger_network: self.network.short(),
            });
        }

        if !state.is_member(&advertisement.node) {
            return Err(LedgerError::NotAMember {
                node: advertisement.node.short(),
            });
        }

        match self.entries.get(&advertisement.node) {
            Some(existing) if existing.issued_at >= advertisement.issued_at => Ok(()),
            _ => {
                self.entries.insert(advertisement.node, advertisement);
                Ok(())
            }
        }
    }

    /// What this ledger holds, as `(node, issued_at)` pairs — §4.5.
    ///
    /// The timestamp is the part that matters. A digest carrying only identity
    /// would let a peer tell whether it had *heard of* a node but never whether
    /// its copy was current, so refreshes would never propagate: the ledger
    /// would populate on first contact and then silently freeze, with every node
    /// making placement decisions on whatever it happened to learn first.
    pub fn digest(&self) -> Vec<(PerNetworkIdentityId, Timestamp)> {
        self.entries
            .iter()
            .map(|(node, advertisement)| (*node, advertisement.issued_at))
            .collect()
    }

    /// Which of a peer's digest entries are worth asking for.
    ///
    /// Both the never-seen case and the have-an-older-copy case, which is what
    /// turns this from a one-shot population into an actual refresh mechanism.
    /// Entries the peer holds a *staler* copy of are deliberately not requested:
    /// [`Self::insert`] would discard them anyway, since an older advertisement
    /// must never displace a newer one.
    pub fn wanted_from(
        &self,
        digest: &[(PerNetworkIdentityId, Timestamp)],
    ) -> Vec<PerNetworkIdentityId> {
        digest
            .iter()
            .filter(|(node, issued_at)| {
                self.entries
                    .get(node)
                    .is_none_or(|held| held.issued_at < *issued_at)
            })
            .map(|(node, _)| *node)
            .collect()
    }

    /// Advertisements for `nodes`, capped at `max`.
    ///
    /// Returns `(advertisements, truncated)`. Unknown nodes are skipped rather
    /// than reported: a peer asking for something this node has never held is
    /// ordinary during propagation, not an error.
    pub fn fetch(
        &self,
        nodes: &[PerNetworkIdentityId],
        max: usize,
    ) -> (Vec<CapabilityAdvertisement>, bool) {
        let matched: Vec<CapabilityAdvertisement> = nodes
            .iter()
            .filter_map(|node| self.entries.get(node).cloned())
            .collect();
        let truncated = matched.len() > max;
        (matched.into_iter().take(max).collect(), truncated)
    }

    /// Removes a node's advertisement, for instance on revocation.
    pub fn remove(&mut self, node: &PerNetworkIdentityId) -> Option<CapabilityAdvertisement> {
        self.entries.remove(node)
    }

    /// Drops advertisements older than `ttl_millis`.
    ///
    /// The refresh-or-expire pattern used throughout this design: a publisher
    /// periodically re-announces, and un-refreshed entries fall out naturally
    /// with no separate deletion protocol.
    pub fn expire(&mut self, now: Timestamp, ttl_millis: i64) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|_, advertisement| !advertisement.is_stale(now, ttl_millis));
        before - self.entries.len()
    }

    /// Drops advertisements from identities that are no longer members.
    pub fn reconcile(&mut self, state: &GovernanceState) -> usize {
        let before = self.entries.len();
        self.entries.retain(|node, _| state.is_member(node));
        before - self.entries.len()
    }

    /// A node's current advertisement.
    pub fn get(&self, node: &PerNetworkIdentityId) -> Option<&CapabilityAdvertisement> {
        self.entries.get(node)
    }

    /// Every current advertisement.
    pub fn entries(&self) -> impl Iterator<Item = &CapabilityAdvertisement> {
        self.entries.values()
    }

    /// How many advertisements are held.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the ledger is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Nodes that have offered storage.
    pub fn storage_candidates(&self) -> impl Iterator<Item = &CapabilityAdvertisement> {
        self.entries
            .values()
            .filter(|advertisement| advertisement.storage_offered > 0)
    }

    /// Nodes willing to relay real-time media.
    ///
    /// Distinct from bootstrap relays: sustained bandwidth and latency demands
    /// versus short-lived connection assistance. A node may offer one, both, or
    /// neither (§4.4), so these are separate queries, never one.
    pub fn media_relay_candidates(&self) -> impl Iterator<Item = &CapabilityAdvertisement> {
        self.entries
            .values()
            .filter(|advertisement| advertisement.relay_media_willing)
    }

    /// Nodes willing to assist NAT traversal.
    pub fn bootstrap_relay_candidates(&self) -> impl Iterator<Item = &CapabilityAdvertisement> {
        self.entries
            .values()
            .filter(|advertisement| advertisement.relay_bootstrap_willing)
    }

    /// Selects replica holders for a content ID — Storage Spec §3.3.
    pub fn select_replicas(&self, cid: &[u8], count: usize) -> Vec<PerNetworkIdentityId> {
        placement::select(
            cid,
            self.storage_candidates(),
            WeightField::StorageOffered,
            count,
        )
    }

    /// Selects a live stream's first redistribution tier — Real-Time Spec §3.3.
    ///
    /// Same HRW routine as [`select_replicas`], weighted by upload throughput
    /// rather than storage, and drawn from media-relay volunteers rather than
    /// every storage contributor.
    ///
    /// [`select_replicas`]: Self::select_replicas
    pub fn select_stream_tier(&self, stream_id: &[u8], count: usize) -> Vec<PerNetworkIdentityId> {
        placement::select(
            stream_id,
            self.media_relay_candidates(),
            WeightField::BandwidthUp,
            count,
        )
    }
}
