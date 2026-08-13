//! Calls, topology, and renegotiation — Real-Time Spec §1, §2.
//!
//! # One mechanism for two events
//!
//! Crossing the mesh/relay threshold and losing a relay look like different
//! problems, but they are the same underlying event: the call's active transport
//! topology needs to change without interrupting the conversation. They
//! therefore share one mechanism — trigger, propose, converge, make-before-break
//! — rather than each having its own, which is what keeps a mid-call transition
//! and a failover from behaving differently under stress.

use crate::{RealtimeError, relay::RelayChoice};
use intranet_crypto::Timestamp;
use intranet_identity::PerNetworkIdentityId;
use std::collections::BTreeSet;

/// How a call's media is currently routed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Topology {
    /// Every participant connects directly to every other.
    ///
    /// Lowest latency, simplest path, and no third party touches the media even
    /// in encrypted form. Costs each participant N-1 simultaneous upload
    /// streams, which is why it does not scale past a small group.
    Mesh,
    /// Media flows through a blind relay.
    Relayed {
        /// The relay carrying this call.
        relay: PerNetworkIdentityId,
    },
}

impl Topology {
    /// Whether a third party is in the media path at all.
    pub fn involves_relay(&self) -> bool {
        matches!(self, Self::Relayed { .. })
    }
}

/// Why a call's topology needs to change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenegotiationTrigger {
    /// Participant count reached the configured threshold.
    ThresholdReached,
    /// Participant count fell back below the threshold.
    ///
    /// Returning to mesh is worth doing rather than staying relayed out of
    /// inertia: it removes a third party from the media path and drops a hop of
    /// latency once the call is small enough to afford it.
    BelowThreshold,
    /// The active relay became unreachable or exceeded its capacity.
    RelayUnavailable,
}

/// A proposal to move the call to a different topology.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopologyProposal {
    /// Who proposed it.
    pub proposer: PerNetworkIdentityId,
    /// What they propose.
    pub topology: Topology,
    /// Why.
    pub trigger: RenegotiationTrigger,
    /// When the proposer sent it.
    pub proposed_at: Timestamp,
}

/// The outcome of receiving a proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalOutcome {
    /// This proposal is now the one being converged on.
    Accepted,
    /// A proposal already in flight won the tie-break.
    Superseded,
    /// The call is already in the proposed topology.
    AlreadySettled,
}

/// One participant's view of a call.
#[derive(Debug, Clone)]
pub struct CallSession {
    call_participants: BTreeSet<PerNetworkIdentityId>,
    threshold: u8,
    active: Topology,
    /// A topology being established but not yet switched to.
    ///
    /// Make-before-break: every participant establishes the new transport
    /// *before* tearing down the old one, so the conversation never has a gap.
    /// Holding both is the whole point — collapsing this into a single field
    /// would make every transition a break-before-make.
    pending: Option<Topology>,
    /// The winning proposal, and when it was received locally.
    in_flight: Option<(TopologyProposal, Timestamp)>,
}

impl CallSession {
    /// Opens a call in mesh topology.
    pub fn open(participants: impl IntoIterator<Item = PerNetworkIdentityId>, threshold: u8) -> Self {
        Self {
            call_participants: participants.into_iter().collect(),
            threshold,
            active: Topology::Mesh,
            pending: None,
            in_flight: None,
        }
    }

    /// Current participants.
    pub fn participants(&self) -> &BTreeSet<PerNetworkIdentityId> {
        &self.call_participants
    }

    /// The topology media is currently flowing over.
    pub fn active_topology(&self) -> Topology {
        self.active
    }

    /// The topology being established, if a handover is in progress.
    pub fn pending_topology(&self) -> Option<Topology> {
        self.pending
    }

    /// Adds a participant.
    pub fn join(&mut self, participant: PerNetworkIdentityId) {
        self.call_participants.insert(participant);
    }

    /// Removes a participant.
    pub fn leave(&mut self, participant: &PerNetworkIdentityId) {
        self.call_participants.remove(participant);
    }

    /// How many upload streams mesh topology would cost each participant.
    ///
    /// The number the threshold exists to bound: it grows linearly with the
    /// call, against a resource that does not.
    pub fn mesh_upload_streams(&self) -> usize {
        self.call_participants.len().saturating_sub(1)
    }

    /// Whether the topology should change, and why.
    ///
    /// Returns `None` when the current topology is right for the call as it
    /// stands. `relay_reachable` is the caller's own observation of the active
    /// relay, since liveness is something each participant sees for itself.
    pub fn evaluate(&self, relay_reachable: bool) -> Option<RenegotiationTrigger> {
        let count = self.call_participants.len();
        let at_threshold = count >= usize::from(self.threshold);

        match self.active {
            Topology::Mesh if at_threshold => Some(RenegotiationTrigger::ThresholdReached),
            Topology::Relayed { .. } if !relay_reachable => {
                Some(RenegotiationTrigger::RelayUnavailable)
            }
            Topology::Relayed { .. } if !at_threshold => {
                Some(RenegotiationTrigger::BelowThreshold)
            }
            _ => None,
        }
    }

    /// Builds a proposal for the topology this trigger calls for.
    ///
    /// `choice` supplies the relay to move to, which the caller obtains from
    /// [`crate::relay::select`] — evaluated across all participants' vantage
    /// points rather than the proposer's alone, since a relay that is close to
    /// the proposer and far from everyone else is a bad choice for the call.
    pub fn propose(
        &self,
        proposer: PerNetworkIdentityId,
        trigger: RenegotiationTrigger,
        choice: Option<RelayChoice>,
        proposed_at: Timestamp,
    ) -> Result<TopologyProposal, RealtimeError> {
        let topology = match trigger {
            RenegotiationTrigger::BelowThreshold => Topology::Mesh,
            RenegotiationTrigger::ThresholdReached | RenegotiationTrigger::RelayUnavailable => {
                let relay = choice.ok_or(RealtimeError::NoRelayAvailable)?;
                Topology::Relayed { relay: relay.relay }
            }
        };

        Ok(TopologyProposal {
            proposer,
            topology,
            trigger,
            proposed_at,
        })
    }

    /// Receives a proposal and converges on a winner.
    ///
    /// # Tie-break
    ///
    /// Near-simultaneous proposals converge on whichever was received first,
    /// falling back to the lexicographically lower proposer when timing is
    /// genuinely ambiguous. Deliberately far lighter than the governance log's
    /// ordering rules: a wrong pick here costs one quick reselect, not a lasting
    /// inconsistency in durable state, so reusing the heavier mechanism would be
    /// unwarranted overhead for an ephemeral per-call decision.
    pub fn receive_proposal(
        &mut self,
        proposal: TopologyProposal,
        received_at: Timestamp,
    ) -> ProposalOutcome {
        if self.active == proposal.topology && self.pending.is_none() {
            return ProposalOutcome::AlreadySettled;
        }

        if let Some((existing, existing_received)) = &self.in_flight {
            let incoming_wins = match received_at.cmp(existing_received) {
                std::cmp::Ordering::Less => true,
                std::cmp::Ordering::Greater => false,
                // Same instant: fall back to a stable, agreed-on ordering so
                // every participant picks the same winner.
                std::cmp::Ordering::Equal => proposal.proposer < existing.proposer,
            };
            if !incoming_wins {
                return ProposalOutcome::Superseded;
            }
        }

        self.pending = Some(proposal.topology);
        self.in_flight = Some((proposal, received_at));
        ProposalOutcome::Accepted
    }

    /// Completes a handover once the new transport is established.
    ///
    /// Called only after the new path is up. Until then the old one is still
    /// carrying media, which is what make-before-break means in practice.
    pub fn complete_handover(&mut self) -> Result<Topology, RealtimeError> {
        let pending = self.pending.take().ok_or(RealtimeError::NoHandoverPending)?;
        self.active = pending;
        self.in_flight = None;
        Ok(pending)
    }

    /// Abandons an in-progress handover, leaving the current topology intact.
    ///
    /// The failure mode make-before-break exists to survive: if the new
    /// transport never comes up, the call carries on over the old one rather
    /// than being left with neither.
    pub fn abandon_handover(&mut self) {
        self.pending = None;
        self.in_flight = None;
    }
}
