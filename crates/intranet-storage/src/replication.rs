//! Replica maintenance and repair — Storage Spec §3.1–3.4.
//!
//! # Detection without a coordinator
//!
//! Nodes periodically announce which content they hold. An announcement expires
//! unless refreshed, so a node going offline stops announcing and its holdings
//! simply age out — under-replication becomes visible without anyone reporting a
//! failure, and without a coordinator tracking liveness.
//!
//! # Repair is where unreliable nodes are corrected for
//!
//! Placement deliberately ignores reputation: it must recompute identically on
//! every node, and local reliability observations are private per observer
//! (Core Protocol Spec §4.6), so feeding them in would make two nodes disagree
//! about who holds what. Repair closes that loop from the other side. A node
//! that is assigned replicas but repeatedly fails to hold or serve them shows up
//! here as ordinary under-replication, which every node sees identically, and
//! repair re-places that content onto the next nodes in the same deterministic
//! ranking. Remediation by observed outcome, not by contested opinion.
//!
//! # Degraded is not broken
//!
//! A network with fewer eligible nodes than its replication target replicates to
//! as many as exist and accepts reduced durability. That is a deliberate design
//! choice, not a failure: a three-person friend network should still function.
//! The protocol must never punish a small network by refusing to operate — but
//! the shortfall must be *visible* rather than silent, which is why
//! [`ReplicationHealth`] distinguishes it from genuine under-replication.

use crate::{Cid, StorageError};
use intranet_crypto::{Enc, Signature, Timestamp};
use intranet_governance::GovernanceState;
use intranet_identity::{NetworkId, PerNetworkIdentity, PerNetworkIdentityId};
use intranet_ledger::{CapabilityLedger, WeightField, placement};
use std::collections::{BTreeMap, BTreeSet};

/// Domain tag for holding announcements.
const HOLDING_DOMAIN: &str = "intranet.holding-announcement.v1";

/// How long a holding announcement stays live without refresh.
///
/// **Flagged: the specs call refresh cadence implementation-level tuning.**
/// Fifteen minutes is short enough that a departed node's holdings clear
/// promptly, and long enough that announcing is cheap background traffic.
pub const DEFAULT_HOLDING_TTL_MILLIS: i64 = 15 * 60_000;

/// A signed statement that a node currently holds some content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoldingAnnouncement {
    /// The network this applies to.
    pub network: NetworkId,
    /// The announcing node.
    pub node: PerNetworkIdentityId,
    /// Content the node holds.
    pub holdings: BTreeSet<Cid>,
    /// When the announcement was made.
    pub announced_at: Timestamp,
    /// The node's signature.
    pub signature: Signature,
}

impl HoldingAnnouncement {
    /// Creates and signs an announcement.
    pub fn create(
        node: &PerNetworkIdentity,
        holdings: BTreeSet<Cid>,
        announced_at: Timestamp,
    ) -> Self {
        let node_id = node.id();
        let payload = Self::payload(node.network(), &node_id, &holdings, announced_at);
        Self {
            network: *node.network(),
            node: node_id,
            holdings,
            announced_at,
            signature: node.sign(&payload),
        }
    }

    /// Verifies the announcement's signature.
    pub fn verify(&self) -> Result<(), StorageError> {
        let payload = Self::payload(
            &self.network,
            &self.node,
            &self.holdings,
            self.announced_at,
        );
        self.node
            .verifying_key()
            .verify(&payload, &self.signature)
            .map_err(|_| StorageError::BadSignature)
    }

    fn payload(
        network: &NetworkId,
        node: &PerNetworkIdentityId,
        holdings: &BTreeSet<Cid>,
        announced_at: Timestamp,
    ) -> Enc {
        let mut e = Enc::domain(HOLDING_DOMAIN);
        network.encode(&mut e);
        node.encode(&mut e);
        e.seq(holdings.iter(), |e, cid| {
            e.fixed(cid.hash().as_bytes());
        });
        e.i64(announced_at.as_millis());
        e
    }
}

/// How a piece of content is doing against its replication target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplicationHealth {
    /// At or above target.
    Healthy,
    /// Below target, but no eligible node is left to place it on.
    ///
    /// Accepted, not repaired: the network is simply smaller than its target.
    /// Reported so the shortfall is observable rather than silent.
    Degraded,
    /// Below target with eligible nodes available — repairable.
    UnderReplicated,
    /// No node is known to hold this content at all.
    ///
    /// Distinct from under-replication, and not repairable: repair works by
    /// copying from an existing holder, so with no holder there is nothing to
    /// copy from. Reporting a repair plan here would describe work that cannot
    /// be performed — placement can say *where* a copy should go, but no
    /// placement can conjure bytes nobody has.
    ///
    /// Surfaced as its own state because it means something operationally
    /// urgent that the other states do not: either the content was never
    /// published, or every copy of it is gone.
    Lost,
}

/// A content item's current replication standing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicationStatus {
    /// The content assessed.
    pub cid: Cid,
    /// The network's configured replication target.
    pub target: usize,
    /// Nodes assigned this content by placement that are currently holding it.
    pub durable_holders: Vec<PerNetworkIdentityId>,
    /// Nodes holding it that placement did not assign.
    ///
    /// Opportunistic copies from swarm participation, plus volunteer
    /// over-replication. These serve requests exactly like assigned replicas —
    /// storage does not force-distinguish them — but they do **not** count
    /// toward the durability guarantee, because a demand-driven copy disappears
    /// when interest does. Counting them would let transient popularity mask a
    /// genuine durability shortfall.
    pub opportunistic_holders: Vec<PerNetworkIdentityId>,
    /// How many eligible nodes exist at all.
    pub eligible: usize,
    /// Overall standing.
    pub health: ReplicationHealth,
}

impl ReplicationStatus {
    /// Total copies known to exist, durable and opportunistic together.
    pub fn total_copies(&self) -> usize {
        self.durable_holders.len() + self.opportunistic_holders.len()
    }

    /// A short human-readable summary, e.g. `2 of target 3`.
    ///
    /// Replication status should be observable so degraded durability is
    /// visible rather than silent, even though it never blocks publishing.
    pub fn summary(&self) -> String {
        format!(
            "{} of target {} ({} eligible, {} opportunistic)",
            self.durable_holders.len(),
            self.target,
            self.eligible,
            self.opportunistic_holders.len()
        )
    }
}

/// Work needed to restore a content item to its replication target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairPlan {
    /// The content to repair.
    pub cid: Cid,
    /// Nodes that should take a copy, in placement order.
    pub assign_to: Vec<PerNetworkIdentityId>,
}

/// A node's local view of who holds what.
#[derive(Debug, Clone)]
pub struct ReplicationView {
    network: NetworkId,
    /// `cid -> node -> most recent announcement time`.
    holders: BTreeMap<Cid, BTreeMap<PerNetworkIdentityId, Timestamp>>,
    ttl_millis: i64,
}

impl ReplicationView {
    /// Creates an empty view.
    pub fn new(network: NetworkId) -> Self {
        Self {
            network,
            holders: BTreeMap::new(),
            ttl_millis: DEFAULT_HOLDING_TTL_MILLIS,
        }
    }

    /// Sets how long announcements stay live without refresh.
    pub fn with_ttl(mut self, ttl_millis: i64) -> Self {
        self.ttl_millis = ttl_millis;
        self
    }

    /// Records an announcement after validating it.
    ///
    /// Rejects announcements from non-members, so a revoked node cannot keep
    /// appearing to hold content and thereby suppress a repair that should
    /// happen.
    pub fn record(
        &mut self,
        announcement: &HoldingAnnouncement,
        state: &GovernanceState,
    ) -> Result<(), StorageError> {
        announcement.verify()?;

        if announcement.network != self.network {
            return Err(StorageError::WrongCollection);
        }
        if !state.is_member(&announcement.node) {
            return Err(StorageError::PublisherNotAMember {
                publisher: announcement.node.short(),
            });
        }

        for cid in &announcement.holdings {
            let entry = self.holders.entry(*cid).or_default();
            // Gossip reorders; keep the freshest announcement rather than the
            // last-arrived, so an out-of-order stale one cannot age out a node
            // that is in fact still holding the content.
            entry
                .entry(announcement.node)
                .and_modify(|current| *current = (*current).max(announcement.announced_at))
                .or_insert(announcement.announced_at);
        }
        Ok(())
    }

    /// Drops announcements that have aged out.
    ///
    /// This is what turns "a node went away" into "content is under-replicated"
    /// with no failure report and no liveness tracker.
    pub fn expire(&mut self, now: Timestamp) -> usize {
        let mut dropped = 0;
        self.holders.retain(|_, nodes| {
            let before = nodes.len();
            nodes.retain(|_, announced| now.millis_since(*announced) <= self.ttl_millis);
            dropped += before - nodes.len();
            !nodes.is_empty()
        });
        dropped
    }

    /// Drops holdings announced by identities that are no longer members.
    pub fn reconcile(&mut self, state: &GovernanceState) -> usize {
        let mut dropped = 0;
        self.holders.retain(|_, nodes| {
            let before = nodes.len();
            nodes.retain(|node, _| state.is_member(node));
            dropped += before - nodes.len();
            !nodes.is_empty()
        });
        dropped
    }

    /// Nodes currently known to hold `cid`.
    pub fn holders_of(&self, cid: &Cid) -> Vec<PerNetworkIdentityId> {
        self.holders
            .get(cid)
            .map(|nodes| nodes.keys().copied().collect())
            .unwrap_or_default()
    }

    /// Every content item this view knows about.
    pub fn tracked(&self) -> impl Iterator<Item = &Cid> {
        self.holders.keys()
    }

    /// Assesses one content item against the replication target.
    pub fn assess(&self, cid: &Cid, ledger: &CapabilityLedger, target: usize) -> ReplicationStatus {
        let ranked = placement::rank(
            cid.hash().as_bytes(),
            ledger.storage_candidates(),
            WeightField::StorageOffered,
        );
        let eligible = ranked.len();

        // Placement recomputes from whoever is currently eligible, so a node
        // that has withdrawn simply drops out of the ranking and the next node
        // moves up. Repair needs no memory of who was assigned previously.
        let assigned: BTreeSet<PerNetworkIdentityId> = ranked
            .iter()
            .take(target)
            .map(|candidate| candidate.node)
            .collect();

        let holders = self.holders_of(cid);
        let (durable, opportunistic): (Vec<_>, Vec<_>) = holders
            .into_iter()
            .partition(|node| assigned.contains(node));

        let attainable = target.min(eligible);
        let health = if durable.is_empty() && opportunistic.is_empty() {
            ReplicationHealth::Lost
        } else if durable.len() >= attainable && durable.len() >= target {
            ReplicationHealth::Healthy
        } else if eligible <= durable.len() {
            // Every eligible node already holds it; the network is simply
            // smaller than its target.
            ReplicationHealth::Degraded
        } else if durable.len() >= attainable {
            ReplicationHealth::Degraded
        } else {
            ReplicationHealth::UnderReplicated
        };

        ReplicationStatus {
            cid: *cid,
            target,
            durable_holders: durable,
            opportunistic_holders: opportunistic,
            eligible,
            health,
        }
    }

    /// Plans repair for one content item, or `None` if none is needed.
    ///
    /// Assignments come from the same deterministic ranking placement uses, so
    /// two nodes planning repair independently produce the same plan and
    /// redundant repair converges rather than conflicting.
    pub fn plan_repair(
        &self,
        cid: &Cid,
        ledger: &CapabilityLedger,
        target: usize,
    ) -> Option<RepairPlan> {
        let status = self.assess(cid, ledger, target);
        // Only under-replication is repairable. `Degraded` means there is
        // nobody left to place onto, and `Lost` means there is nothing to copy
        // from — neither is work a plan could describe.
        if status.health != ReplicationHealth::UnderReplicated {
            return None;
        }

        let holders: BTreeSet<PerNetworkIdentityId> = self.holders_of(cid).into_iter().collect();
        let ranked = placement::rank(
            cid.hash().as_bytes(),
            ledger.storage_candidates(),
            WeightField::StorageOffered,
        );

        // Walk the ranking and take the highest-ranked nodes not already
        // holding it, until the target is met. Extending past the original
        // cutoff is exactly how a failed holder is replaced: the node that was
        // next in line simply becomes the new assignee.
        let needed = target.saturating_sub(status.durable_holders.len());
        let assign_to: Vec<PerNetworkIdentityId> = ranked
            .iter()
            .map(|candidate| candidate.node)
            .filter(|node| !holders.contains(node))
            .take(needed)
            .collect();

        (!assign_to.is_empty()).then_some(RepairPlan {
            cid: *cid,
            assign_to,
        })
    }

    /// Plans repair for everything this view tracks.
    pub fn plan_all_repairs(
        &self,
        ledger: &CapabilityLedger,
        target: usize,
    ) -> Vec<RepairPlan> {
        self.tracked()
            .filter_map(|cid| self.plan_repair(cid, ledger, target))
            .collect()
    }
}

/// Whether a node has opted in to running repair scans — §3.4.
///
/// Repair is opt-in like every other contribution: not every node needs to run
/// repair-scanning logic, though at least some willing nodes per network should.
/// Declared storage is the signal, since a node offering none has not
/// volunteered for storage duty at all and assigning it repair work would
/// conscript it into exactly the role it declined.
pub fn runs_repair(node: &PerNetworkIdentityId, ledger: &CapabilityLedger) -> bool {
    ledger
        .get(node)
        .is_some_and(|advertisement| advertisement.storage_offered > 0)
}
