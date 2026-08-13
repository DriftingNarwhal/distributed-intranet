//! The explicit-intake waiting room — Core Protocol Spec §2.4, §5.6.
//!
//! Under explicit intake, successfully using a valid invite establishes
//! connectivity and a per-network identity and **nothing else**: no group
//! membership, no capabilities, no epoch key. The joiner sits here until an
//! admin explicitly admits them.
//!
//! # Why this is local node state rather than a governance log entry
//!
//! Waiting-room occupancy is not an authorization fact — it is precisely the
//! *absence* of one. A node in the waiting room holds no membership and no
//! capability, so there is nothing about it for the governance log to record; the
//! log's job is making the sequence of *authorized actions* tamper-evident, and
//! entering a waiting room is not an authorized action, it is the state of not
//! having been authorized yet.
//!
//! Admission, by contrast, *is* an authorized action, and is recorded as an
//! ordinary `MembershipChange` carrying the invite's provenance (§5.6), at which
//! point the identity leaves this structure.
//!
//! **Flagged:** the specs describe the waiting room as a state a node is in and
//! require it to be "discoverable by anyone holding `manage-membership:everyone`"
//! with issuer context, but do not specify the discovery mechanism. This models
//! it as node-local state intended to be served to authorized admins on request;
//! gossiping it network-wide is deliberately not assumed.

use intranet_crypto::{Hash, Timestamp};
use intranet_governance::{Capability, GovernanceState, GroupId, InviteProvenance};
use intranet_identity::PerNetworkIdentityId;
use std::collections::BTreeMap;

/// A node awaiting explicit admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaitingRoomEntry {
    /// The joiner's per-network identity.
    pub identity: PerNetworkIdentityId,
    /// Which invite was used, and who issued it.
    ///
    /// This is the "basic context" §2.4 requires an admin to see: an admin
    /// reviewing a joiner needs to know who vouched for them, which is the
    /// accountability the invite provenance exists to carry.
    pub provenance: InviteProvenance,
    /// When the joiner entered the waiting room.
    pub arrived_at: Timestamp,
}

/// Node-local record of identities awaiting admission.
#[derive(Debug, Clone, Default)]
pub struct WaitingRoom {
    occupants: BTreeMap<PerNetworkIdentityId, WaitingRoomEntry>,
}

impl WaitingRoom {
    /// Creates an empty waiting room.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a joiner as awaiting admission.
    ///
    /// Re-entry by an identity already present keeps the original arrival time,
    /// so that reconnecting cannot be used to appear freshly arrived and slip
    /// past an admin reviewing oldest-first.
    pub fn admit_to_waiting(
        &mut self,
        identity: PerNetworkIdentityId,
        provenance: InviteProvenance,
        arrived_at: Timestamp,
    ) {
        self.occupants
            .entry(identity)
            .or_insert(WaitingRoomEntry {
                identity,
                provenance,
                arrived_at,
            });
    }

    /// Removes an identity, for instance once it has been admitted to a group.
    pub fn remove(&mut self, identity: &PerNetworkIdentityId) -> Option<WaitingRoomEntry> {
        self.occupants.remove(identity)
    }

    /// Whether an identity is currently waiting.
    pub fn contains(&self, identity: &PerNetworkIdentityId) -> bool {
        self.occupants.contains_key(identity)
    }

    /// How many identities are waiting.
    pub fn len(&self) -> usize {
        self.occupants.len()
    }

    /// Whether the waiting room is empty.
    pub fn is_empty(&self) -> bool {
        self.occupants.is_empty()
    }

    /// Everyone currently waiting, oldest arrival first.
    pub fn occupants(&self) -> Vec<&WaitingRoomEntry> {
        let mut entries: Vec<&WaitingRoomEntry> = self.occupants.values().collect();
        entries.sort_by_key(|entry| (entry.arrived_at, entry.identity));
        entries
    }

    /// Drops anyone who has since become a member of any group.
    ///
    /// Keeps this local view consistent with replayed governance state without
    /// the caller having to observe each admission individually — an admission
    /// may well have been performed by a different admin on a different node.
    pub fn reconcile(&mut self, state: &GovernanceState) {
        self.occupants
            .retain(|identity, _| !state.is_member(identity));
    }

    /// Whether `requester` may view the waiting room — §2.4.
    ///
    /// Visibility is gated on `manage-membership:everyone`, since that is the
    /// capability that lets someone actually act on what they see by admitting a
    /// joiner. Exposing the queue more widely would leak who is trying to join a
    /// network to members who could do nothing about it.
    pub fn visible_to(&self, requester: &PerNetworkIdentityId, state: &GovernanceState) -> bool {
        state.identity_holds(
            requester,
            &Capability::ManageMembership(GroupId::everyone()),
        )
    }

    /// Everyone who joined using a specific invite.
    ///
    /// Feeds relay rate limiting: pre-admission identities are free to mint
    /// under a bearer invite, so the invite is the scarce resource to meter
    /// against, not the identity (§5.3).
    pub fn arrivals_for_invite(&self, invite_id: &Hash) -> usize {
        self.occupants
            .values()
            .filter(|entry| entry.provenance.invite_id == *invite_id)
            .count()
    }
}
