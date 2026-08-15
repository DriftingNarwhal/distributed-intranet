//! Member-vote admission across nodes — Core Protocol Spec §2.6, §2.6.1.
//!
//! # What was missing
//!
//! The quorum mechanism was complete in one process — proposals, ballots,
//! certificates, the close-boundary rules — and connected to nothing. Two
//! separate gaps sat behind that: `authorize` never consulted the network's
//! governance model, so a vote could pass and change nothing; and ballots had no
//! transport, so a certificate could only ever be assembled by whoever happened
//! to hold every ballot already.
//!
//! # Why ballots pull rather than broadcast
//!
//! §2.6.1 is explicit that a certificate assembled *after* close, from ballots
//! validly cast before it, is valid — assembly time is irrelevant, only the
//! ballots' own timestamps matter. That is only reachable if the ballots can
//! still be obtained late. A broadcast has no history, so a node that was
//! partitioned during the voting window could never assemble the certificate the
//! spec says is valid. `a_certificate_assembled_after_close_still_passes` is the
//! test that would fail against a fire-and-forget design.

use intranet_crypto::{Hash, Timestamp};
use intranet_governance::{
    Ballot, Capability, EntryBody, GovernanceModel, GroupId, LogEntry, MembershipAction,
    NetworkPolicy, VoteOutcome, VoteProposal,
};
use intranet_identity::{MasterSeed, NetworkId, PerNetworkIdentity};
use intranet_transport::{MemberNode, NodeEvent};
use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;
use std::time::Duration;

const NETWORK: NetworkId = NetworkId::from_bytes([42u8; 32]);

fn identity(n: u8) -> PerNetworkIdentity {
    MasterSeed::from_entropy([n; 32]).identity_for(&NETWORK).unwrap()
}

fn at(millis: i64) -> Timestamp {
    Timestamp::from_millis(millis)
}

/// The admission a vote is held about.
fn admission_of(newcomer: &PerNetworkIdentity) -> EntryBody {
    EntryBody::MembershipChange {
        group: GroupId::everyone(),
        identity: newcomer.id(),
        action: MembershipAction::Add { via_invite: None },
    }
}

/// Builds a member-vote network's log: admit under capability rules, then switch.
///
/// The order is forced, not stylistic. A network that opened under member-vote
/// could never admit anybody — admission would need a quorum of an electorate
/// with no members in it. Switching once a founding electorate exists is the
/// bootstrap path.
fn voting_log(founder: &PerNetworkIdentity, voters: &[u8], quorum: u32) -> Vec<LogEntry> {
    let mut chain = vec![LogEntry::create(
        founder,
        None,
        at(0),
        EntryBody::Genesis {
            network: NETWORK,
            policy: NetworkPolicy::conservative_default(),
            everyone_capabilities: [Capability::ReadContent].into_iter().collect(),
        },
    )];
    for (n, seed) in voters.iter().enumerate() {
        let parent = chain.last().unwrap().hash();
        chain.push(LogEntry::create(
            founder,
            Some(parent),
            at(10 + n as i64),
            admission_of(&identity(*seed)),
        ));
    }
    let mut policy = NetworkPolicy::conservative_default();
    policy.governance_model = GovernanceModel::MemberVote {
        electorate: GroupId::everyone(),
        quorum,
        window_millis: 72_000,
    };
    let parent = chain.last().unwrap().hash();
    chain.push(LogEntry::create(
        founder,
        Some(parent),
        at(50),
        EntryBody::PolicyChange { policy },
    ));
    chain
}

async fn node(seed: u8) -> (MemberNode, Multiaddr) {
    let identity = identity(seed);
    let mut node = MemberNode::new(&identity).unwrap();
    node.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap()).unwrap();

    let address = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let NodeEvent::Listening(address) = node.next_event().await
                && address.iter().any(|p| matches!(p, Protocol::Tcp(_)))
            {
                return address;
            }
        }
    })
    .await
    .expect("the node should listen");

    (node, address.with(Protocol::P2p(identity.peer_id())))
}

async fn drive(
    a: &mut MemberNode,
    b: &mut MemberNode,
    limit: Duration,
    done: impl Fn(&MemberNode, &MemberNode) -> bool,
) -> bool {
    tokio::time::timeout(limit, async {
        loop {
            if done(a, b) {
                return true;
            }
            tokio::select! {
                _ = a.next_event() => {}
                _ = b.next_event() => {}
            }
        }
    })
    .await
    .unwrap_or(false)
}

fn same_log(a: &MemberNode, b: &MemberNode) -> bool {
    a.governance_log().len() == b.governance_log().len()
}

/// Opens a vote on `newcomer`'s admission, appending the proposal to `node`.
fn open_vote(
    node: &mut MemberNode,
    proposer: &PerNetworkIdentity,
    newcomer: &PerNetworkIdentity,
    quorum: u32,
) -> VoteProposal {
    let state = node.governance_log().replay_canonical().unwrap();
    let tip = node.governance_log().canonical_chain().last().copied().unwrap();
    let proposal = VoteProposal::open(
        admission_of(newcomer).action_hash(),
        GroupId::everyone(),
        &state,
        tip,
        at(72_000),
        quorum,
    )
    .unwrap();
    node.append_entry(LogEntry::create(
        proposer,
        Some(tip),
        at(100),
        EntryBody::VoteProposed {
            proposal: proposal.clone(),
        },
    ))
    .unwrap();
    proposal
}

#[tokio::test]
async fn ballots_cast_on_one_node_reach_another_and_settle_the_vote() {
    // The round trip the whole feature exists for: two members vote on separate
    // nodes, one collects the other's ballot, assembles a certificate, and the
    // admission it authorizes becomes valid on both.
    let founder = identity(1);
    let voter_a = identity(10);
    let voter_b = identity(11);
    let newcomer = identity(200);

    let (mut a, _) = node(10).await;
    let (mut b, b_addr) = node(11).await;
    for entry in voting_log(&founder, &[10, 11], 2) {
        a.append_entry(entry.clone()).unwrap();
        b.append_entry(entry).unwrap();
    }

    let proposal = open_vote(&mut a, &voter_a, &newcomer, 2);
    let vote_id = proposal.vote_id();

    a.dial_candidates([b_addr]).unwrap();
    assert!(drive(&mut a, &mut b, Duration::from_secs(20), same_log).await);

    // Each votes on its own node. Neither can settle it alone: quorum is two.
    a.cast_ballot(vote_id, true, at(1_000), &voter_a).unwrap();
    b.cast_ballot(vote_id, true, at(1_100), &voter_b).unwrap();
    assert_eq!(a.ballots_for(&vote_id).len(), 1);
    assert_eq!(
        a.assemble_certificate(&vote_id)
            .unwrap()
            .verify(&proposal)
            .unwrap(),
        VoteOutcome::Failed,
        "one ballot cannot reach a quorum of two"
    );

    // A collects B's ballot by asking for it.
    a.sync_ballots_with(voter_b.id().peer_id(), vote_id);
    assert!(
        drive(&mut a, &mut b, Duration::from_secs(20), |a, _| {
            a.ballots_for(&vote_id).len() == 2
        })
        .await,
        "the ballot cast on B should reach A"
    );

    let certificate = a.assemble_certificate(&vote_id).unwrap();
    assert_eq!(certificate.verify(&proposal).unwrap(), VoteOutcome::Passed);

    // Recording the outcome is what makes the admission authorized — and any
    // member may do it, holding no capability.
    let tip = a.governance_log().canonical_chain().last().copied().unwrap();
    a.append_entry(LogEntry::create(
        &voter_a,
        Some(tip),
        at(2_000),
        EntryBody::VoteOutcome { certificate },
    ))
    .unwrap();

    let tip = a.governance_log().canonical_chain().last().copied().unwrap();
    a.append_entry(LogEntry::create(
        &voter_a,
        Some(tip),
        at(2_100),
        admission_of(&newcomer),
    ))
    .expect("a passing vote authorizes the admission");

    // And B reaches the same conclusion from the entries alone.
    b.sync_with(voter_a.id().peer_id());
    assert!(drive(&mut a, &mut b, Duration::from_secs(20), same_log).await);
    let b_state = b.governance_log().replay_canonical().unwrap();
    assert!(
        b_state.is_member(&newcomer.id()),
        "both nodes must agree the newcomer was admitted"
    );
    assert_eq!(
        a.governance_log().replay_canonical().unwrap().state_hash(),
        b_state.state_hash(),
        "and agree on the whole state, which is the deterministic check"
    );
}

#[tokio::test]
async fn a_certificate_assembled_after_close_still_passes() {
    // §2.6.1's corrected rule: assembly time is irrelevant, only the ballots'
    // own timestamps decide. This is the case a broadcast cannot serve — the
    // assembler was not listening when the ballots were cast, and obtains them
    // afterwards.
    let founder = identity(1);
    let voter_a = identity(10);
    let voter_b = identity(11);
    let newcomer = identity(200);

    let (mut a, _) = node(10).await;
    let (mut b, b_addr) = node(11).await;
    for entry in voting_log(&founder, &[10, 11], 2) {
        a.append_entry(entry.clone()).unwrap();
        b.append_entry(entry).unwrap();
    }
    let proposal = open_vote(&mut a, &voter_a, &newcomer, 2);
    let vote_id = proposal.vote_id();

    // Both ballots are cast on B, before close, while A is not connected — the
    // partition case, modelled as two nodes that have not met.
    a.dial_candidates([b_addr]).unwrap();
    assert!(drive(&mut a, &mut b, Duration::from_secs(20), same_log).await);
    b.cast_ballot(vote_id, true, at(1_000), &voter_b).unwrap();
    b.record_ballot(Ballot::cast(&voter_a, vote_id, true, at(1_100)));
    assert_eq!(b.ballots_for(&vote_id).len(), 2);
    assert!(a.ballots_for(&vote_id).is_empty());

    // A collects them long after close and assembles from them anyway.
    a.sync_ballots_with(voter_b.id().peer_id(), vote_id);
    assert!(
        drive(&mut a, &mut b, Duration::from_secs(20), |a, _| {
            a.ballots_for(&vote_id).len() == 2
        })
        .await
    );

    let certificate = a.assemble_certificate(&vote_id).unwrap();
    assert_eq!(
        certificate.verify(&proposal).unwrap(),
        VoteOutcome::Passed,
        "a certificate assembled after close, from ballots cast before it, is valid"
    );
    assert!(
        certificate.ballots.iter().all(|ballot| ballot.cast_at <= proposal.close_time),
        "and every ballot in it qualified on its own timestamp"
    );
}

#[tokio::test]
async fn ballots_from_outside_the_frozen_electorate_are_refused() {
    // A collection is only useful if what it holds can go into a certificate.
    // Accepting a ballot from a non-voter would hand an assembler material that
    // makes the certificate they build invalid — a failure that would surface
    // far from its cause.
    let founder = identity(1);
    let voter_a = identity(10);
    let outsider = identity(99);
    let newcomer = identity(200);

    let (mut a, _) = node(10).await;
    for entry in voting_log(&founder, &[10, 11], 2) {
        a.append_entry(entry).unwrap();
    }
    let proposal = open_vote(&mut a, &voter_a, &newcomer, 2);
    let vote_id = proposal.vote_id();

    assert!(
        !a.record_ballot(Ballot::cast(&outsider, vote_id, true, at(1_000))),
        "a ballot from outside the frozen electorate must be refused"
    );
    assert!(
        !a.record_ballot(Ballot::cast(&identity(11), vote_id, true, at(80_000))),
        "a ballot cast after close must be refused"
    );
    assert!(
        !a.record_ballot(Ballot::cast(&voter_a, Hash::from_bytes([9u8; 32]), true, at(1_000))),
        "a ballot for a vote this node does not know is open must be refused"
    );
    assert!(a.ballots_for(&vote_id).is_empty());
}

#[tokio::test]
async fn a_non_member_is_refused_ballots() {
    // **Flagged: §2.6.1 names no gate for ballot access.** Membership is the
    // floor used here — the electorate is drawn from members, and ballots reveal
    // how individuals voted, which the log itself never discloses.
    let founder = identity(1);
    let voter_a = identity(10);
    let newcomer = identity(200);
    let outsider = identity(99);

    let (mut a, _) = node(10).await;
    let (mut outsider_node, outsider_addr) = node(99).await;
    for entry in voting_log(&founder, &[10, 11], 2) {
        a.append_entry(entry).unwrap();
    }
    let proposal = open_vote(&mut a, &voter_a, &newcomer, 2);
    let vote_id = proposal.vote_id();
    a.cast_ballot(vote_id, true, at(1_000), &voter_a).unwrap();

    a.dial_candidates([outsider_addr]).unwrap();
    assert!(drive(&mut a, &mut outsider_node, Duration::from_secs(20), same_log).await);

    outsider_node.sync_ballots_with(voter_a.id().peer_id(), vote_id);
    let refusal = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            tokio::select! {
                _ = a.next_event() => {}
                event = outsider_node.next_event() => {
                    match event {
                        NodeEvent::BallotSyncRefused { reason, .. } => return Some(reason),
                        NodeEvent::BallotsReceived { accepted, .. } => {
                            return None.filter(|_: &String| accepted == 0);
                        }
                        _ => {}
                    }
                }
            }
        }
    })
    .await
    .expect("the serving node should answer");

    let reason = refusal.expect("a non-member must be refused ballots");
    assert!(reason.contains("member"), "got: {reason}");
    assert!(outsider_node.ballots_for(&vote_id).is_empty());
    let _ = outsider;
}
