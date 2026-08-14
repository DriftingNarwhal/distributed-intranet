//! The join handshake across nodes — Core Protocol Spec §5.6–5.7, §2.4, §5.3.
//!
//! # What was missing
//!
//! `intranet-invite` held the credential and the waiting-room state machine, and
//! both were well covered in isolation. What did not exist was the sequence that
//! turns a redeemed invite into either `everyone` membership or a waiting-room
//! place — so an invite could be issued and validated but never actually
//! *presented* to anybody.
//!
//! # The distinction these tests exist to protect
//!
//! §2.4's two admission modes differ in exactly one way that matters, and it is
//! the thing easiest to get quietly wrong: under explicit intake a joiner comes
//! away holding **nothing** — no group, no capability, and no epoch key, because
//! holding the key is equivalent to being able to decrypt regardless of
//! membership. A build that admitted waiting-room nodes to `everyone` would pass
//! any test that only checked "did the join succeed".

use intranet_crypto::{Hash, Timestamp};
use intranet_governance::{
    AdmissionMode, Capability, CapabilitySet, EntryBody, GroupId, LogEntry, MembershipAction,
    NetworkPolicy,
};
use intranet_identity::{MasterSeed, NetworkId, PerNetworkIdentity};
use intranet_invite::{Invite, InviteSubject};
use intranet_transport::{MemberNode, NodeEvent};
use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;
use std::time::Duration;

const NETWORK: NetworkId = NetworkId::from_bytes([42u8; 32]);

fn identity(n: u8) -> PerNetworkIdentity {
    MasterSeed::from_entropy([n; 32]).identity_for(&NETWORK).unwrap()
}

fn genesis(founder: &PerNetworkIdentity, mode: AdmissionMode) -> LogEntry {
    let mut policy = NetworkPolicy::conservative_default();
    policy.admission_mode = mode;
    LogEntry::create(
        founder,
        None,
        Timestamp::from_millis(0),
        EntryBody::Genesis {
            network: NETWORK,
            policy,
            everyone_capabilities: [Capability::ReadContent].into_iter().collect(),
        },
    )
}

fn invite(issuer: &PerNetworkIdentity, subject: InviteSubject, max_uses: u32) -> Invite {
    Invite::issue(
        issuer,
        vec!["/ip4/127.0.0.1/tcp/4001".to_owned()],
        subject,
        Timestamp::from_millis(0),
        Timestamp::from_millis(100_000),
        max_uses,
    )
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

fn same_length(a: &MemberNode, b: &MemberNode) -> bool {
    a.governance_log().len() == b.governance_log().len()
}

/// What a joiner came away with.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Admitted(Hash),
    Waiting,
    Refused(String),
}

/// Drives a join to completion, answering on the host's behalf.
async fn present_invite(
    host_node: &mut MemberNode,
    host: &PerNetworkIdentity,
    joiner_node: &mut MemberNode,
    joiner: &PerNetworkIdentity,
    invite: Invite,
    at: i64,
) -> Outcome {
    joiner_node.request_join(host.id(), invite, joiner);
    let mut answered = false;
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            tokio::select! {
                event = host_node.next_event() => {
                    if let NodeEvent::JoinRequested { request, .. } = event && !answered {
                        answered = true;
                        host_node
                            .answer_join(request, host, Timestamp::from_millis(at))
                            .expect("the host should answer");
                    }
                }
                event = joiner_node.next_event() => {
                    match event {
                        NodeEvent::Admitted { entry, .. } => return Outcome::Admitted(entry),
                        NodeEvent::AwaitingAdmission { .. } => return Outcome::Waiting,
                        NodeEvent::JoinRefused { reason, .. } => return Outcome::Refused(reason),
                        _ => {}
                    }
                }
            }
        }
    })
    .await
    .expect("the join should be answered")
}

#[tokio::test]
async fn auto_admit_turns_a_redeemed_invite_into_membership_and_then_a_key() {
    // The full §5.6–5.7 sequence: present an invite, become a member, and then
    // reach the epoch key through the *ordinary* delivery protocol rather than
    // anything join-specific.
    let founder = identity(1);
    let joiner = identity(2);
    let (mut founder_node, _) = node(1).await;
    let (mut joiner_node, joiner_addr) = node(2).await;

    founder_node
        .append_entry(genesis(&founder, AdmissionMode::AutoAdmit))
        .unwrap();
    founder_node.create_epoch_group(&founder).unwrap();

    founder_node.dial_candidates([joiner_addr]).unwrap();
    assert!(drive(&mut founder_node, &mut joiner_node, Duration::from_secs(20), same_length).await);

    let outcome = present_invite(
        &mut founder_node,
        &founder,
        &mut joiner_node,
        &joiner,
        invite(&founder, InviteSubject::Bearer, 4),
        50,
    )
    .await;
    let entry = match outcome {
        Outcome::Admitted(entry) => entry,
        other => panic!("auto-admit should admit immediately, got {other:?}"),
    };

    // Membership is a governance fact, verifiable by the joiner's own replay
    // rather than on the responder's word.
    joiner_node.sync_with(founder.peer_id());
    assert!(
        drive(&mut founder_node, &mut joiner_node, Duration::from_secs(20), |_, b| {
            b.governance_log().get(&entry).is_some()
        })
        .await,
        "the admission entry should reach the joiner"
    );
    let state = joiner_node.governance_log().replay_canonical().unwrap();
    assert!(
        state.is_member(&joiner.id()),
        "the joiner should be a member by its own replay"
    );
    assert!(
        state.identity_holds(&joiner.id(), &Capability::ReadContent),
        "and hold what everyone holds"
    );

    // Membership alone still reads nothing — §5.7's point that the invite's job
    // ends at the connection.
    assert!(
        !joiner_node.holds_epoch_key(),
        "admission grants membership, not a key"
    );

    // The key arrives over the ordinary protocol, no join-time special case.
    joiner_node.request_epoch_key(founder.id(), &joiner).unwrap();
    let mut answered = false;
    let keyed = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            tokio::select! {
                event = founder_node.next_event() => {
                    if let NodeEvent::EpochKeyRequested { request, .. } = event && !answered {
                        answered = true;
                        founder_node
                            .answer_epoch_key(request, &founder, Timestamp::from_millis(60))
                            .unwrap();
                    }
                }
                event = joiner_node.next_event() => {
                    match event {
                        NodeEvent::EpochKeyDelivered { .. } => return true,
                        NodeEvent::EpochKeyUnavailable { .. } => return false,
                        _ => {}
                    }
                }
            }
        }
    })
    .await
    .unwrap_or(false);
    assert!(keyed, "an admitted member can obtain the epoch key");
}

#[tokio::test]
async fn explicit_intake_grants_a_waiting_place_and_nothing_else() {
    // The mode that is easiest to get quietly wrong. A joiner here holds no
    // group, no capability, and — the part that would matter most — no key.
    let founder = identity(3);
    let joiner = identity(4);
    let (mut founder_node, _) = node(3).await;
    let (mut joiner_node, joiner_addr) = node(4).await;

    founder_node
        .append_entry(genesis(&founder, AdmissionMode::ExplicitIntake))
        .unwrap();
    founder_node.create_epoch_group(&founder).unwrap();

    founder_node.dial_candidates([joiner_addr]).unwrap();
    assert!(drive(&mut founder_node, &mut joiner_node, Duration::from_secs(20), same_length).await);

    let ticket = invite(&founder, InviteSubject::Bearer, 4);
    let invite_id = ticket.invite_id();
    let outcome = present_invite(
        &mut founder_node,
        &founder,
        &mut joiner_node,
        &joiner,
        ticket,
        50,
    )
    .await;
    assert_eq!(outcome, Outcome::Waiting);

    // Nothing was granted.
    let state = founder_node.governance_log().replay_canonical().unwrap();
    assert!(
        !state.is_member(&joiner.id()),
        "explicit intake grants no membership"
    );
    assert!(
        !state.identity_holds(&joiner.id(), &Capability::ReadContent),
        "and therefore no read-content"
    );

    // The admin can see who is waiting, with the issuer context §2.4 requires.
    let waiting = founder_node
        .waiting_room_for(&founder.id())
        .expect("the founder holds manage-membership:everyone");
    assert_eq!(waiting.len(), 1);
    assert_eq!(waiting[0].identity, joiner.id());
    assert_eq!(waiting[0].provenance.invite_id, invite_id);
    assert_eq!(waiting[0].provenance.issuer, founder.id());

    // And a key delivery is refused, which is the consequence that matters:
    // a waiting-room identity is valid and non-revoked, and must still get
    // nothing.
    joiner_node.request_epoch_key(founder.id(), &joiner).unwrap();
    let refused = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            tokio::select! {
                _ = founder_node.next_event() => {}
                event = joiner_node.next_event() => {
                    match event {
                        NodeEvent::EpochKeyUnavailable { reason, .. } => return Some(reason),
                        NodeEvent::EpochKeyDelivered { .. } => return None,
                        _ => {}
                    }
                }
            }
        }
    })
    .await
    .expect("the founder should answer");
    assert!(
        refused.is_some(),
        "a waiting-room identity must not be keyed in"
    );
    assert!(!joiner_node.holds_epoch_key());
}

#[tokio::test]
async fn an_admin_admitting_from_the_waiting_room_clears_the_queue() {
    // Admission *is* an authorized action, so it is an ordinary
    // `MembershipChange` — and once it lands, the local waiting-room view
    // reconciles against replayed state rather than needing to observe the
    // admission itself.
    let founder = identity(5);
    let joiner = identity(6);
    let (mut founder_node, _) = node(5).await;
    let (mut joiner_node, joiner_addr) = node(6).await;

    let parent = founder_node
        .append_entry(genesis(&founder, AdmissionMode::ExplicitIntake))
        .unwrap();
    founder_node.dial_candidates([joiner_addr]).unwrap();
    assert!(drive(&mut founder_node, &mut joiner_node, Duration::from_secs(20), same_length).await);

    present_invite(
        &mut founder_node,
        &founder,
        &mut joiner_node,
        &joiner,
        invite(&founder, InviteSubject::Bearer, 4),
        50,
    )
    .await;
    assert_eq!(founder_node.waiting_room().len(), 1);

    founder_node
        .append_entry(LogEntry::create(
            &founder,
            Some(parent),
            Timestamp::from_millis(60),
            EntryBody::MembershipChange {
                group: GroupId::everyone(),
                identity: joiner.id(),
                action: MembershipAction::Add { via_invite: None },
            },
        ))
        .unwrap();

    let state = founder_node.governance_log().replay_canonical().unwrap();
    assert!(state.is_member(&joiner.id()));

    // The waiting room is a local view of "not yet authorized", so it drops
    // anyone replay says is now a member.
    let mut room = founder_node.waiting_room().clone();
    room.reconcile(&state);
    assert!(room.is_empty(), "an admitted joiner leaves the queue");
}

#[tokio::test]
async fn a_bearer_invite_cannot_fill_the_waiting_room_past_what_it_could_admit() {
    // §5.3's gap, concretely. A waiting-room identity is free to mint under a
    // bearer invite, so per-identity metering catches nothing here; the invite
    // is the scarce resource. The ceiling is the invite's own remaining uses,
    // since an invite that can admit no more members has no reason to
    // accumulate further pre-admission arrivals.
    let founder = identity(7);
    let (mut founder_node, _) = node(7).await;

    founder_node
        .append_entry(genesis(&founder, AdmissionMode::ExplicitIntake))
        .unwrap();

    let ticket = invite(&founder, InviteSubject::Bearer, 2);

    // Two arrivals fit; the third is refused, because the invite could only ever
    // have admitted two.
    let mut outcomes = Vec::new();
    for seed in [10u8, 11, 12] {
        let joiner = identity(seed);
        let (mut joiner_node, joiner_addr) = node(seed).await;
        founder_node.dial_candidates([joiner_addr]).unwrap();
        assert!(
            drive(&mut founder_node, &mut joiner_node, Duration::from_secs(20), same_length).await
        );
        outcomes.push(
            present_invite(
                &mut founder_node,
                &founder,
                &mut joiner_node,
                &joiner,
                ticket.clone(),
                50,
            )
            .await,
        );
    }

    assert_eq!(outcomes[0], Outcome::Waiting);
    assert_eq!(outcomes[1], Outcome::Waiting);
    match &outcomes[2] {
        Outcome::Refused(reason) => assert!(
            reason.contains("ceiling"),
            "the third should hit the per-invite ceiling, got: {reason}"
        ),
        other => panic!("a third pre-admission arrival should be refused, got {other:?}"),
    }
    assert_eq!(
        founder_node.waiting_room().len(),
        2,
        "the queue holds only what the invite could actually admit"
    );
}

#[tokio::test]
async fn an_exhausted_or_expired_invite_is_refused() {
    let founder = identity(8);
    let joiner = identity(9);
    let (mut founder_node, _) = node(8).await;
    let (mut joiner_node, joiner_addr) = node(9).await;

    founder_node
        .append_entry(genesis(&founder, AdmissionMode::AutoAdmit))
        .unwrap();
    founder_node.dial_candidates([joiner_addr]).unwrap();
    assert!(drive(&mut founder_node, &mut joiner_node, Duration::from_secs(20), same_length).await);

    // Presented after its expiry, evaluated against the responder's clock.
    let expired = Invite::issue(
        &founder,
        vec!["/ip4/127.0.0.1/tcp/4001".to_owned()],
        InviteSubject::Bearer,
        Timestamp::from_millis(0),
        Timestamp::from_millis(10),
        4,
    );
    let outcome = present_invite(
        &mut founder_node,
        &founder,
        &mut joiner_node,
        &joiner,
        expired,
        5_000,
    )
    .await;
    match outcome {
        Outcome::Refused(reason) => assert!(reason.contains("validate"), "got: {reason}"),
        other => panic!("an expired invite must be refused, got {other:?}"),
    }
    assert!(
        !founder_node
            .governance_log()
            .replay_canonical()
            .unwrap()
            .is_member(&joiner.id())
    );
}

#[tokio::test]
async fn an_invite_naming_someone_else_is_refused() {
    // A targeted invite is not a bearer invite. Presenting one issued to another
    // identity must fail even though the invite itself is perfectly valid.
    let founder = identity(13);
    let intended = identity(14);
    let interloper = identity(15);
    let (mut founder_node, _) = node(13).await;
    let (mut interloper_node, interloper_addr) = node(15).await;

    founder_node
        .append_entry(genesis(&founder, AdmissionMode::AutoAdmit))
        .unwrap();
    founder_node.dial_candidates([interloper_addr]).unwrap();
    assert!(
        drive(&mut founder_node, &mut interloper_node, Duration::from_secs(20), same_length).await
    );

    let targeted = invite(&founder, InviteSubject::Identity(intended.id()), 4);
    let outcome = present_invite(
        &mut founder_node,
        &founder,
        &mut interloper_node,
        &interloper,
        targeted,
        50,
    )
    .await;
    match outcome {
        Outcome::Refused(reason) => assert!(reason.contains("validate"), "got: {reason}"),
        other => panic!("a targeted invite must not admit somebody else, got {other:?}"),
    }
}

#[tokio::test]
async fn an_invite_from_a_stripped_issuer_stops_working() {
    // Authority is evaluated at redemption, not issuance: revoking an admin has
    // to invalidate their outstanding invites, or revocation leaves a live door
    // behind it.
    let founder = identity(16);
    let admin = identity(17);
    let joiner = identity(18);
    let (mut founder_node, _) = node(16).await;
    let (mut joiner_node, joiner_addr) = node(18).await;

    let parent = founder_node
        .append_entry(genesis(&founder, AdmissionMode::AutoAdmit))
        .unwrap();
    // An admin group holding approve-node, with the admin in it.
    let parent = founder_node
        .append_entry(LogEntry::create(
            &founder,
            Some(parent),
            Timestamp::from_millis(5),
            EntryBody::DefineGroup {
                group: GroupId::new("admins"),
                capabilities: CapabilitySet::explicit([Capability::ApproveNode]),
            },
        ))
        .unwrap();
    let parent = founder_node
        .append_entry(LogEntry::create(
            &founder,
            Some(parent),
            Timestamp::from_millis(6),
            EntryBody::MembershipChange {
                group: GroupId::new("admins"),
                identity: admin.id(),
                action: MembershipAction::Add { via_invite: None },
            },
        ))
        .unwrap();

    let ticket = invite(&admin, InviteSubject::Bearer, 4);

    // Strip the admin's authority before the invite is presented.
    founder_node
        .append_entry(LogEntry::create(
            &founder,
            Some(parent),
            Timestamp::from_millis(7),
            EntryBody::MembershipChange {
                group: GroupId::new("admins"),
                identity: admin.id(),
                action: MembershipAction::Remove { cascade: None },
            },
        ))
        .unwrap();

    founder_node.dial_candidates([joiner_addr]).unwrap();
    assert!(drive(&mut founder_node, &mut joiner_node, Duration::from_secs(20), same_length).await);

    let outcome = present_invite(
        &mut founder_node,
        &founder,
        &mut joiner_node,
        &joiner,
        ticket,
        50,
    )
    .await;
    match outcome {
        Outcome::Refused(reason) => assert!(reason.contains("validate"), "got: {reason}"),
        other => panic!("a stripped issuer's invite must stop working, got {other:?}"),
    }
}
