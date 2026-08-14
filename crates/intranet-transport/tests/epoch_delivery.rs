//! Epoch key delivery over libp2p — Core Protocol Spec §3.5, §5.6, Harness §3.
//!
//! # The gap these close
//!
//! Every layer below this one could already be exercised across two nodes: the
//! governance log syncs, the ledger gossips, chunks transfer. None of that let a
//! second node *read* anything. It could join a network, replay the log, fetch
//! every byte of content and open none of it, because nothing carried a Welcome
//! or a commit between nodes — the MLS machinery and the retention rules existed
//! with no transport under them.
//!
//! So the load-bearing test here is not that a message arrives. It is
//! [`a_second_node_can_decrypt_content_published_by_the_first`]: the round trip
//! from "two independent nodes" to "both hold the same epoch key and one can
//! open what the other sealed". Everything else in this file guards a way that
//! round trip could be reached by something that should not have been allowed.

use intranet_crypto::{Hash, Timestamp};
use intranet_epoch::{GroupSession, identity_label};
use intranet_governance::{
    Capability, EntryBody, GroupId, HistoryAccess, InviteProvenance, LogEntry, MembershipAction,
    NetworkPolicy,
};
use intranet_identity::{MasterSeed, NetworkId, PerNetworkIdentity};
use intranet_storage::Dek;
use intranet_transport::{MemberNode, NodeEvent};
use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;
use std::time::Duration;

const NETWORK: NetworkId = NetworkId::from_bytes([42u8; 32]);

fn identity(n: u8) -> PerNetworkIdentity {
    MasterSeed::from_entropy([n; 32]).identity_for(&NETWORK).unwrap()
}

/// A genesis entry granting `everyone` the capability that gates key delivery.
fn genesis(founder: &PerNetworkIdentity, history: HistoryAccess) -> LogEntry {
    let mut policy = NetworkPolicy::conservative_default();
    policy.history_access = history;
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

/// Admits `joiner` into `everyone`, which is what grants it `read-content`.
fn admit(
    founder: &PerNetworkIdentity,
    joiner: &PerNetworkIdentity,
    parent: Hash,
    at: i64,
) -> LogEntry {
    LogEntry::create(
        founder,
        Some(parent),
        Timestamp::from_millis(at),
        EntryBody::MembershipChange {
            group: GroupId::everyone(),
            identity: joiner.id(),
            action: MembershipAction::Add {
                via_invite: Some(InviteProvenance {
                    invite_id: Hash::from_bytes([7u8; 32]),
                    issuer: founder.id(),
                }),
            },
        },
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

/// Drives both nodes until the founder is asked for a key, then answers.
///
/// The founder must keep being polled after answering: the Welcome travels on
/// its swarm, so a test that stopped driving it at the moment it answered would
/// hang waiting for a message that was never actually written.
async fn deliver_key(
    founder_node: &mut MemberNode,
    founder: &PerNetworkIdentity,
    joiner_node: &mut MemberNode,
    at: i64,
) -> Result<Hash, String> {
    let mut answered: Option<Hash> = None;
    let outcome = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            tokio::select! {
                event = founder_node.next_event() => {
                    if let NodeEvent::EpochKeyRequested { request, .. } = event
                        && answered.is_none()
                    {
                        match founder_node.answer_epoch_key(
                            request,
                            founder,
                            Timestamp::from_millis(at),
                        ) {
                            Ok(hash) => answered = Some(hash),
                            Err(error) => return Err(error.to_string()),
                        }
                    }
                }
                event = joiner_node.next_event() => {
                    match event {
                        NodeEvent::EpochKeyDelivered { rotation_ref, .. } => {
                            return Ok(rotation_ref);
                        }
                        NodeEvent::EpochKeyUnavailable { reason, .. } => {
                            return Err(reason);
                        }
                        _ => {}
                    }
                }
            }
        }
    })
    .await;

    match outcome {
        Ok(result) => result,
        Err(_) => Err("timed out waiting for a key delivery".to_owned()),
    }
}

fn same_length(a: &MemberNode, b: &MemberNode) -> bool {
    a.governance_log().len() == b.governance_log().len()
}

/// Pulls `from`'s log into `puller`, and waits for convergence.
///
/// Needed whenever an entry is appended to a peer that is *already* connected.
/// Sync is pull-based and runs on connection (see `intranet_transport::sync`),
/// so nothing propagates an entry appended afterwards until somebody asks — a
/// property of the design, not a gap: a push would have no history, and entries
/// written during a partition would never reach the other side on heal.
async fn resync(puller: &mut MemberNode, other: &mut MemberNode, from: &PerNetworkIdentity) {
    puller.sync_with(from.peer_id());
    assert!(
        drive(puller, other, Duration::from_secs(20), same_length).await,
        "an explicit sync should converge the logs"
    );
}

/// Founder creates a network and its group; joiner is admitted and synced.
///
/// Returns both nodes ready for a key request, with the log converged — which is
/// the state §5.7 describes as ordinary post-connection sync, not join-time
/// machinery.
async fn network_with_admitted_joiner(
    history: HistoryAccess,
) -> (MemberNode, PerNetworkIdentity, MemberNode, PerNetworkIdentity) {
    let founder = identity(1);
    let joiner = identity(2);
    let (mut founder_node, _) = node(1).await;
    let (mut joiner_node, joiner_addr) = node(2).await;

    let parent = founder_node.append_entry(genesis(&founder, history)).unwrap();
    founder_node.create_epoch_group(&founder).unwrap();
    founder_node
        .append_entry(admit(&founder, &joiner, parent, 10))
        .unwrap();

    founder_node.dial_candidates([joiner_addr]).unwrap();
    assert!(
        drive(&mut founder_node, &mut joiner_node, Duration::from_secs(20), same_length).await,
        "the joiner should receive the governance log before asking for a key"
    );

    (founder_node, founder, joiner_node, joiner)
}

#[tokio::test]
async fn a_second_node_can_decrypt_content_published_by_the_first() {
    // The whole point. Before key delivery existed, a joiner could reach this
    // state — admitted, log synced — and still open nothing.
    let (mut founder_node, founder, mut joiner_node, joiner) =
        network_with_admitted_joiner(HistoryAccess::CurrentEpochForward).await;

    assert!(
        founder_node.holds_epoch_key(),
        "the founder holds the epoch its own genesis produced"
    );
    assert!(
        !joiner_node.holds_epoch_key(),
        "the joiner must hold nothing before delivery — a synced log is not a key"
    );

    joiner_node
        .request_epoch_key(founder.id(), &joiner)
        .unwrap();
    let rotation_ref = deliver_key(&mut founder_node, &founder, &mut joiner_node, 20)
        .await
        .expect("the joiner should be keyed in");

    assert!(joiner_node.holds_epoch_key(), "the joiner now holds a key");

    // Both derived the same key independently — the founder from its own commit,
    // the joiner from the Welcome. Compared by fingerprint because epoch keys
    // deliberately expose no equality-friendly form.
    let founder_key = founder_node.epoch_keyring().current().unwrap().1.clone();
    let joiner_key = joiner_node.epoch_keyring().current().unwrap().1.clone();
    assert_eq!(
        founder_key.fingerprint(),
        joiner_key.fingerprint(),
        "both nodes must be on the same epoch, or neither can read the other's content"
    );

    // And the key actually opens what the other sealed: a DEK wrapped under the
    // founder's epoch key unwraps under the joiner's.
    let pointer = intranet_governance::PointerId::from_bytes([5u8; 32]);
    let dek = Dek::generate().unwrap();
    let wrapped = founder_key.wrap(&pointer, &dek);
    let unwrapped = joiner_key
        .unwrap_dek(&pointer, &wrapped)
        .expect("the joiner's epoch key must open the founder's wrapping");
    assert_eq!(
        unwrapped.commitment(),
        dek.commitment(),
        "the unwrapped DEK must be the one the founder wrapped"
    );

    // The admitting rotation is in the log, so every other member can order it.
    assert!(
        founder_node.governance_log().get(&rotation_ref).is_some(),
        "the rotation must be an entry, since the log is what orders commits"
    );
}

#[tokio::test]
async fn a_waiting_room_identity_is_refused_a_key() {
    // §2.4's "essentially nothing" posture, at the one place it would hurt most
    // to get wrong. A waiting-room identity is valid and non-revoked; what it
    // lacks is any group, therefore `read-content`, therefore a key.
    let founder = identity(1);
    let waiting = identity(3);
    let (mut founder_node, _) = node(1).await;
    let (mut waiting_node, waiting_addr) = node(3).await;

    founder_node
        .append_entry(genesis(&founder, HistoryAccess::CurrentEpochForward))
        .unwrap();
    founder_node.create_epoch_group(&founder).unwrap();

    founder_node.dial_candidates([waiting_addr]).unwrap();
    assert!(
        drive(&mut founder_node, &mut waiting_node, Duration::from_secs(20), same_length).await,
        "the log should sync even to a node that will be refused a key"
    );

    waiting_node
        .request_epoch_key(founder.id(), &waiting)
        .unwrap();
    let outcome = deliver_key(&mut founder_node, &founder, &mut waiting_node, 20).await;

    let reason = outcome.expect_err("a waiting-room identity must not be keyed in");
    assert!(
        reason.contains("read-content"),
        "refusal should name the gate that refused, got: {reason}"
    );
    assert!(
        !waiting_node.holds_epoch_key(),
        "a refused node must come away with nothing"
    );
}

#[tokio::test]
async fn a_key_package_naming_someone_else_is_refused() {
    // The credential binding. The request signature already stops an attacker
    // naming a victim while presenting their own package; this is the converse —
    // presenting a package built under the victim's label. Without the check the
    // attacker is welcomed into the group as them.
    let (mut founder_node, founder, mut joiner_node, joiner) =
        network_with_admitted_joiner(HistoryAccess::CurrentEpochForward).await;

    // A package labelled as the founder, presented by the joiner.
    let impostor = GroupSession::prepare_join(&identity_label(&founder.id())).unwrap();
    let request =
        intranet_epoch::EpochKeyRequest::create(&joiner, impostor.key_package().unwrap());
    joiner_node.send_epoch_request(founder.id(), request);

    let outcome = deliver_key(&mut founder_node, &founder, &mut joiner_node, 20).await;
    let reason = outcome.expect_err("a mislabelled key package must be refused");
    assert!(
        reason.contains("credential"),
        "refusal should name the credential mismatch, got: {reason}"
    );
}

#[tokio::test]
async fn full_history_delivers_superseded_keys_sealed_to_the_joiner() {
    // §3.4's opt-in. The current key comes from the Welcome under either policy;
    // what full history adds is the superseded epochs MLS has already discarded,
    // which travel sealed under §3.5's authenticated channel.
    let (mut founder_node, founder, mut joiner_node, joiner) =
        network_with_admitted_joiner(HistoryAccess::FullHistory).await;

    // Give the founder a superseded epoch to have history *of*.
    let rotation = founder_node.rotate_epoch(&founder, Timestamp::from_millis(15)).unwrap();
    assert_eq!(
        founder_node.epoch_keyring().len(),
        2,
        "the founder retains the superseded key through the tentative window"
    );
    assert!(founder_node.governance_log().get(&rotation).is_some());

    resync(&mut joiner_node, &mut founder_node, &founder).await;

    joiner_node.request_epoch_key(founder.id(), &joiner).unwrap();
    deliver_key(&mut founder_node, &founder, &mut joiner_node, 20)
        .await
        .expect("the joiner should be keyed in");

    assert!(
        joiner_node.epoch_keyring().len() >= 2,
        "a full-history joiner receives superseded keys as well as the current one"
    );

    // The superseded key is the founder's, not a fresh one: it must open what
    // was wrapped under that epoch before the joiner existed.
    let old_ref = founder_node
        .epoch_keyring()
        .records()
        .next()
        .unwrap()
        .rotation_ref;
    let founder_old = founder_node.epoch_keyring().key_for(&old_ref).unwrap().clone();
    let joiner_old = joiner_node
        .epoch_keyring()
        .key_for(&old_ref)
        .expect("the joiner should hold the superseded epoch under the same reference")
        .clone();
    assert_eq!(
        founder_old.fingerprint(),
        joiner_old.fingerprint(),
        "a delivered historical key must be the same key, not merely some key"
    );
}

#[tokio::test]
async fn current_epoch_forward_delivers_no_history() {
    // The conservative default, and the contrast that makes the previous test
    // mean something: under this policy nothing prior is delivered at all.
    let (mut founder_node, founder, mut joiner_node, joiner) =
        network_with_admitted_joiner(HistoryAccess::CurrentEpochForward).await;

    founder_node.rotate_epoch(&founder, Timestamp::from_millis(15)).unwrap();
    resync(&mut joiner_node, &mut founder_node, &founder).await;

    joiner_node.request_epoch_key(founder.id(), &joiner).unwrap();
    deliver_key(&mut founder_node, &founder, &mut joiner_node, 20)
        .await
        .expect("the joiner should be keyed in");

    assert_eq!(
        joiner_node.epoch_keyring().len(),
        1,
        "a current-epoch-forward joiner receives exactly the epoch it joined at"
    );
}

#[tokio::test]
async fn an_unadmitted_identity_cannot_borrow_a_members_standing() {
    // A signed request proves the named identity asked; it does not prove the
    // peer delivering it is that identity. Replaying a captured request from a
    // different connection must fail, or membership is transferable by anyone
    // who once observed a member ask for a key.
    let (mut founder_node, founder, mut joiner_node, joiner) =
        network_with_admitted_joiner(HistoryAccess::CurrentEpochForward).await;

    // A request validly signed by the admitted joiner, replayed by an outsider.
    let pending = GroupSession::prepare_join(&identity_label(&joiner.id())).unwrap();
    let captured =
        intranet_epoch::EpochKeyRequest::create(&joiner, pending.key_package().unwrap());

    let (mut outsider_node, outsider_addr) = node(4).await;
    founder_node.dial_candidates([outsider_addr]).unwrap();
    assert!(
        drive(&mut founder_node, &mut outsider_node, Duration::from_secs(20), |_, b| {
            !b.governance_log().is_empty()
        })
        .await,
        "the outsider should reach the founder"
    );

    outsider_node.send_epoch_request(founder.id(), captured);
    let outcome = deliver_key(&mut founder_node, &founder, &mut outsider_node, 20).await;
    assert!(
        outcome.is_err(),
        "a replayed request must not key in whoever delivered it"
    );
    assert!(!outsider_node.holds_epoch_key());

    // The legitimate holder is unaffected — the replay does not consume anything.
    joiner_node.request_epoch_key(founder.id(), &joiner).unwrap();
    deliver_key(&mut founder_node, &founder, &mut joiner_node, 20)
        .await
        .expect("the real joiner should still be keyed in");
    assert!(joiner_node.holds_epoch_key());
}

#[tokio::test]
async fn a_synced_rotation_commit_keeps_a_third_member_in_step() {
    // Why the commit lives in the log entry. When the founder admits a second
    // member, every existing member must apply that commit or derive a different
    // key from then on. The commit reaches them through ordinary log sync, and
    // `apply_pending_rotations` is what turns a synced entry into applied MLS
    // state.
    let (mut founder_node, founder, mut joiner_node, joiner) =
        network_with_admitted_joiner(HistoryAccess::CurrentEpochForward).await;

    joiner_node.request_epoch_key(founder.id(), &joiner).unwrap();
    deliver_key(&mut founder_node, &founder, &mut joiner_node, 20)
        .await
        .expect("the joiner should be keyed in");

    let before = joiner_node.epoch_keyring().current().unwrap().1.fingerprint();

    // A third member is admitted, advancing the epoch for everyone.
    let third = identity(5);
    let parent = founder_node.governance_log().canonical_chain().last().copied().unwrap();
    founder_node
        .append_entry(admit(&founder, &third, parent, 30))
        .unwrap();
    let (mut third_node, third_addr) = node(5).await;
    founder_node.dial_candidates([third_addr]).unwrap();
    assert!(
        drive(&mut founder_node, &mut third_node, Duration::from_secs(20), same_length).await,
        "the third node should sync the log"
    );
    third_node.request_epoch_key(founder.id(), &third).unwrap();
    deliver_key(&mut founder_node, &founder, &mut third_node, 40)
        .await
        .expect("the third member should be keyed in");

    // The joiner learns of the rotation by ordinary sync, then applies it.
    resync(&mut joiner_node, &mut founder_node, &founder).await;
    let applied = joiner_node.apply_pending_rotations();
    assert!(
        !applied.is_empty(),
        "the joiner should apply the commit it synced, or it is now on a stale epoch"
    );

    let after = joiner_node.epoch_keyring().current().unwrap().1.fingerprint();
    assert_ne!(before, after, "applying the commit must advance the epoch");
    assert_eq!(
        after,
        founder_node.epoch_keyring().current().unwrap().1.fingerprint(),
        "all three members must land on the same epoch key"
    );
    assert_eq!(
        after,
        third_node.epoch_keyring().current().unwrap().1.fingerprint(),
        "including the member whose admission caused the rotation"
    );
}

/// A rotation reference that no node holds, for the negative case below.
fn absent() -> Hash {
    Hash::from_bytes([0xABu8; 32])
}

#[tokio::test]
async fn a_node_without_a_group_refuses_rather_than_pretending() {
    // A responder that never created or joined a group, asked by a requester who
    // *does* pass every other check. Fail-closed: it must say it holds no group
    // rather than inventing one.
    //
    // The requester has to be genuinely admitted for this to test anything. The
    // gate is deliberately evaluated before the group is consulted, so an
    // unadmitted requester is refused on `read-content` and never reaches the
    // check under test here.
    let responder = identity(6);
    let b_identity = identity(7);
    let (mut a_node, _) = node(6).await;
    let (mut b_node, b_addr) = node(7).await;

    let parent = a_node
        .append_entry(genesis(&responder, HistoryAccess::CurrentEpochForward))
        .unwrap();
    a_node
        .append_entry(admit(&responder, &b_identity, parent, 10))
        .unwrap();
    a_node.dial_candidates([b_addr]).unwrap();
    assert!(
        drive(&mut a_node, &mut b_node, Duration::from_secs(20), same_length).await,
        "the log should sync"
    );

    assert!(
        !a_node.holds_epoch_key(),
        "the responder was never keyed in, which is the case under test"
    );
    assert!(a_node.epoch_keyring().key_for(&absent()).is_none());

    b_node.request_epoch_key(responder.id(), &b_identity).unwrap();
    let outcome = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                _ = a_node.next_event() => {}
                event = b_node.next_event() => {
                    if let NodeEvent::EpochKeyUnavailable { reason, .. } = event {
                        return reason;
                    }
                }
            }
        }
    })
    .await;

    let reason = outcome.expect("a node with no group should refuse promptly");
    assert!(
        reason.contains("group"),
        "refusal should name the missing group, got: {reason}"
    );
}
