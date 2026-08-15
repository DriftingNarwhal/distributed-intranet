//! Member-vote quorum mechanism — Core Protocol Spec §2.6.1.
//!
//! # The outcome is certificate existence, not local tallying
//!
//! The correction this section turns on: different nodes observe different
//! ballot sets near a vote's close boundary, because of ordinary clock skew and
//! gossip propagation delay. So a node computing an outcome from *its own*
//! collected ballots is not a reliable source of truth — two honest nodes can
//! genuinely disagree.
//!
//! What is deterministic is a [`QuorumCertificate`]: any node checking the same
//! certificate against the same frozen electorate and the same ballot timestamps
//! always reaches the same answer. Local ballot collection is therefore only ever
//! a tool for *constructing* a candidate certificate, never the outcome itself.
//!
//! Two consequences the code below enforces directly:
//!
//! - **Assembly time is irrelevant.** A certificate assembled long after close,
//!   from ballots cast before it, is valid. Only the referenced ballots' own
//!   timestamps decide whether they qualify.
//! - **No certificate means the vote failed.** There is no ambiguous "maybe it
//!   passed for some nodes" state, and no deadline pressure on assembly.

use crate::{GovernanceError, GovernanceState, GroupId};
use intranet_crypto::{Enc, Hash, Signature, Timestamp, hash_bytes, merkle_root};
use intranet_identity::{PerNetworkIdentity, PerNetworkIdentityId};
use std::collections::{BTreeMap, BTreeSet};

/// Domain tag for ballot signatures.
const BALLOT_DOMAIN: &str = "intranet.ballot.v1";

/// Domain tag for vote proposal identifiers.
const PROPOSAL_DOMAIN: &str = "intranet.vote-proposal.v1";

/// The result of checking a quorum certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoteOutcome {
    /// A valid certificate carrying at least the required approvals.
    Passed,
    /// A structurally valid certificate that did not reach quorum.
    Failed,
}

/// An open vote, defined against a frozen electorate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteProposal {
    /// What is being voted on, as a hash of the proposed action.
    pub subject: Hash,
    /// Which group's membership formed the electorate.
    pub electorate: GroupId,
    /// The frozen roster of eligible voters.
    ///
    /// A snapshot taken when the vote was proposed. Nobody can be added to or
    /// removed from the electorate mid-vote to influence the outcome, because
    /// the vote is defined against this fixed roster from the start.
    pub electorate_snapshot: BTreeSet<PerNetworkIdentityId>,
    /// The governance log entry the snapshot was taken at.
    pub snapshot_ref: Hash,
    /// Ballots cast after this time do not qualify.
    pub close_time: Timestamp,
    /// Approvals required to pass.
    pub quorum: u32,
}

impl VoteProposal {
    /// Opens a vote, freezing the current membership of `electorate`.
    pub fn open(
        subject: Hash,
        electorate: GroupId,
        state: &GovernanceState,
        snapshot_ref: Hash,
        close_time: Timestamp,
        quorum: u32,
    ) -> Result<Self, GovernanceError> {
        let group = state
            .groups
            .get(&electorate)
            .ok_or_else(|| GovernanceError::UnknownGroup(electorate.clone()))?;

        Ok(Self {
            subject,
            electorate,
            electorate_snapshot: group.members.keys().copied().collect(),
            snapshot_ref,
            close_time,
            quorum,
        })
    }

    /// Appends this proposal to a canonical encoding.
    ///
    /// Public because a vote outcome is a log entry, and an entry's signature is
    /// over its canonical bytes — so the proposal has to be encodable by the
    /// entry that carries it, in exactly the form its `vote_id` is derived from.
    pub fn encode(&self, e: &mut Enc) {
        e.fixed(self.subject.as_bytes())
            .str(self.electorate.as_str());
        e.seq(self.electorate_snapshot.iter(), |e, voter| voter.encode(e));
        e.fixed(self.snapshot_ref.as_bytes())
            .i64(self.close_time.as_millis())
            .u32(self.quorum);
    }

    /// This proposal's identifier, derived from its own contents.
    ///
    /// Deriving rather than assigning means a ballot's `vote_id` binds to the
    /// exact electorate, close time, and quorum being voted under — so ballots
    /// cannot be replayed against a proposal with, say, a lower quorum.
    pub fn vote_id(&self) -> Hash {
        let mut e = Enc::domain(PROPOSAL_DOMAIN);
        self.encode(&mut e);
        hash_bytes(&e.finish())
    }
}

/// One voter's signed ballot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ballot {
    /// The proposal this ballot is cast under.
    pub vote_id: Hash,
    /// The voter.
    pub voter: PerNetworkIdentityId,
    /// Whether the voter approves.
    pub approve: bool,
    /// When the voter cast the ballot, per the voter's own clock.
    ///
    /// This is what decides whether the ballot qualifies, not when any node
    /// observed it or assembled a certificate from it.
    pub cast_at: Timestamp,
    /// The voter's signature.
    pub signature: Signature,
}

impl Ballot {
    /// Casts and signs a ballot.
    pub fn cast(
        voter: &PerNetworkIdentity,
        vote_id: Hash,
        approve: bool,
        cast_at: Timestamp,
    ) -> Self {
        let voter_id = voter.id();
        let payload = Self::payload(&vote_id, &voter_id, approve, cast_at);
        Self {
            vote_id,
            voter: voter_id,
            approve,
            cast_at,
            signature: voter.sign(&payload),
        }
    }

    /// Verifies the ballot's signature.
    pub fn verify(&self) -> Result<(), GovernanceError> {
        let payload = Self::payload(&self.vote_id, &self.voter, self.approve, self.cast_at);
        self.voter
            .verifying_key()
            .verify(&payload, &self.signature)
            .map_err(|_| GovernanceError::BadSignature)
    }

    /// This ballot's hash, used as a Merkle leaf.
    pub fn hash(&self) -> Hash {
        let mut e = Self::payload(&self.vote_id, &self.voter, self.approve, self.cast_at);
        e.fixed(self.signature.as_bytes());
        hash_bytes(&e.finish())
    }

    fn payload(
        vote_id: &Hash,
        voter: &PerNetworkIdentityId,
        approve: bool,
        cast_at: Timestamp,
    ) -> Enc {
        let mut e = Enc::domain(BALLOT_DOMAIN);
        e.fixed(vote_id.as_bytes());
        voter.encode(&mut e);
        e.bool(approve).i64(cast_at.as_millis());
        e
    }
}

/// An independently verifiable bundle of qualifying ballots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuorumCertificate {
    /// The proposal this certificate is for.
    pub vote_id: Hash,
    /// The ballots, in canonical (hash-ascending) order.
    pub ballots: Vec<Ballot>,
    /// Merkle root over the ballot hashes.
    pub merkle_root: Hash,
}

impl Ballot {
    /// Appends this ballot to a canonical encoding.
    pub fn encode(&self, e: &mut Enc) {
        e.fixed(self.vote_id.as_bytes());
        self.voter.encode(e);
        e.bool(self.approve)
            .i64(self.cast_at.as_millis())
            .fixed(self.signature.as_bytes());
    }
}

impl QuorumCertificate {
    /// Appends this certificate to a canonical encoding.
    pub fn encode(&self, e: &mut Enc) {
        e.fixed(self.vote_id.as_bytes());
        e.seq(self.ballots.iter(), |e, ballot| ballot.encode(e));
        e.fixed(self.merkle_root.as_bytes());
    }

    /// Assembles a certificate from collected ballots.
    ///
    /// Ballots are sorted by hash so that two nodes assembling from the same set
    /// produce byte-identical certificates. Duplicate voters are collapsed,
    /// keeping the earliest-cast ballot — a voter who submits twice should not
    /// gain a second vote, nor be able to overwrite their own earlier ballot
    /// after seeing how a vote is trending.
    pub fn assemble(proposal: &VoteProposal, ballots: impl IntoIterator<Item = Ballot>) -> Self {
        let vote_id = proposal.vote_id();

        let mut by_voter: BTreeMap<PerNetworkIdentityId, Ballot> = BTreeMap::new();
        for ballot in ballots {
            if ballot.vote_id != vote_id {
                continue;
            }
            by_voter
                .entry(ballot.voter)
                .and_modify(|existing| {
                    if (ballot.cast_at, ballot.hash()) < (existing.cast_at, existing.hash()) {
                        *existing = ballot.clone();
                    }
                })
                .or_insert(ballot);
        }

        let mut ballots: Vec<Ballot> = by_voter.into_values().collect();
        ballots.sort_by_key(Ballot::hash);
        let leaves: Vec<Hash> = ballots.iter().map(Ballot::hash).collect();

        Self {
            vote_id,
            ballots,
            merkle_root: merkle_root(&leaves),
        }
    }

    /// Verifies this certificate against the proposal it claims to settle.
    ///
    /// Note what is deliberately *not* checked: when the certificate was
    /// assembled, or when this node first saw it. A certificate assembled well
    /// after close, from ballots validly cast before it, is fully valid.
    pub fn verify(&self, proposal: &VoteProposal) -> Result<VoteOutcome, GovernanceError> {
        let expected_id = proposal.vote_id();
        if self.vote_id != expected_id {
            return Err(GovernanceError::InvalidQuorumCertificate {
                reason: "certificate is for a different proposal".into(),
            });
        }

        if self.ballots.is_empty() {
            return Err(GovernanceError::InvalidQuorumCertificate {
                reason: "certificate contains no ballots".into(),
            });
        }

        let mut seen: BTreeSet<PerNetworkIdentityId> = BTreeSet::new();
        let mut approvals: u32 = 0;

        for ballot in &self.ballots {
            if ballot.vote_id != expected_id {
                return Err(GovernanceError::InvalidQuorumCertificate {
                    reason: "certificate contains a ballot for a different proposal".into(),
                });
            }
            ballot
                .verify()
                .map_err(|_| GovernanceError::InvalidQuorumCertificate {
                    reason: format!("ballot from {} has an invalid signature", ballot.voter.short()),
                })?;

            if !proposal.electorate_snapshot.contains(&ballot.voter) {
                return Err(GovernanceError::InvalidQuorumCertificate {
                    reason: format!("{} is not in the frozen electorate", ballot.voter.short()),
                });
            }

            // The rule that makes outcomes deterministic across nodes: the
            // ballot's own signed timestamp decides eligibility.
            if ballot.cast_at > proposal.close_time {
                return Err(GovernanceError::InvalidQuorumCertificate {
                    reason: format!("ballot from {} was cast after close", ballot.voter.short()),
                });
            }

            if !seen.insert(ballot.voter) {
                return Err(GovernanceError::InvalidQuorumCertificate {
                    reason: format!("{} appears more than once", ballot.voter.short()),
                });
            }

            if ballot.approve {
                approvals += 1;
            }
        }

        let leaves: Vec<Hash> = self.ballots.iter().map(Ballot::hash).collect();
        if merkle_root(&leaves) != self.merkle_root {
            return Err(GovernanceError::InvalidQuorumCertificate {
                reason: "merkle root does not match the included ballots".into(),
            });
        }

        Ok(if approvals >= proposal.quorum {
            VoteOutcome::Passed
        } else {
            VoteOutcome::Failed
        })
    }
}
