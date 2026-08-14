//! Revocation across nodes — Core Protocol Spec §3.1, §3.3, Harness §3.
//!
//! # Why this is the test that matters most
//!
//! Reference Test Harness Spec §3 calls the revocation round trip "the harness's
//! most important correctness test, since it's the actual, honest revocation
//! guarantee the whole encryption design exists to provide." Until MLS removal
//! was driven from a node, it could only be asserted in-process against one
//! group — which proves the library rekeys, not that a network does.
//!
//! # Both halves, and the floor underneath them
//!
//! The guarantee has two halves that fail independently (§5.5):
//!
//! - The revoked member cannot obtain any key wrapped for the first time after
//!   removal — the MLS rotation here.
//! - They cannot obtain new *ciphertext* either — the `read-content` serving
//!   gate, which converges rather than blocking instantly.
//!
//! And it has a floor that must be asserted just as deliberately: a revoked
//! member **can** still decrypt what they already held. No symmetric-key scheme
//! can un-know a key, and a test suite that asserted otherwise would be claiming
//! the impossible guarantee this project's own documents briefly made before a
//! review pass caught it.

use intranet_crypto::{Hash, Timestamp};
use intranet_governance::{
    Capability, EntryBody, GroupId, HistoryAccess, LogEntry, MembershipAction, NetworkPolicy,
    PointerId,
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

fn genesis(founder: &PerNetworkIdentity) -> LogEntry {
    let mut policy = NetworkPolicy::conservative_default();
    policy.history_access = HistoryAccess::CurrentEpochForward;
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
            action: MembershipAction::Add { via_invite: None },
        },
    )
}

fn remove(
    founder: &PerNetworkIdentity,
    target: &PerNetworkIdentity,
    parent: Hash,
    at: i64,
) -> LogEntry {
    LogEntry::create(
        founder,
        Some(parent),
        Timestamp::from_millis(at),
        EntryBody::MembershipChange {
            group: GroupId::everyone(),
            identity: target.id(),
            action: MembershipAction::Remove { cascade: None },
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

fn same_length(a: &MemberNode, b: &MemberNode) -> bool {
    a.governance_log().len() == b.governance_log().len()
}

async fn resync(puller: &mut MemberNode, other: &mut MemberNode, from: &PerNetworkIdentity) {
    puller.sync_with(from.peer_id());
    assert!(
        drive(puller, other, Duration::from_secs(20), same_length).await,
        "an explicit sync should converge the logs"
    );
}

/// Keys `joiner_node` into the network held by `founder_node`.
async fn key_in(
    founder_node: &mut MemberNode,
    founder: &PerNetworkIdentity,
    joiner_node: &mut MemberNode,
    joiner: &PerNetworkIdentity,
    at: i64,
) {
    joiner_node.request_epoch_key(founder.id(), joiner).unwrap();
    let mut answered = false;
    let delivered = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            tokio::select! {
                event = founder_node.next_event() => {
                    if let NodeEvent::EpochKeyRequested { request, .. } = event && !answered {
                        founder_node
                            .answer_epoch_key(request, founder, Timestamp::from_millis(at))
                            .expect("the founder should be able to answer");
                        answered = true;
                    }
                }
                event = joiner_node.next_event() => {
                    match event {
                        NodeEvent::EpochKeyDelivered { .. } => return true,
                        NodeEvent::EpochKeyUnavailable { reason, .. } => {
                            panic!("key delivery failed: {reason}")
                        }
                        _ => {}
                    }
                }
            }
        }
    })
    .await
    .unwrap_or(false);
    assert!(delivered, "the joiner should be keyed in");
}

/// The canonical tip, which is the only correct parent for a new entry.
///
/// Worth a helper rather than tracking a variable: every key delivery appends a
/// rotation, so a parent captured before one lands is stale, and an entry built
/// on it forks the log instead of extending it. That fork is invisible until
/// something replays the canonical branch and finds the entry missing.
fn tip(node: &MemberNode) -> Hash {
    node.governance_log()
        .canonical_chain()
        .last()
        .copied()
        .expect("the log has a genesis entry")
}

fn fingerprint(node: &MemberNode) -> Hash {
    node.epoch_keyring().current().unwrap().1.fingerprint()
}

#[tokio::test]
async fn a_revoked_member_loses_the_new_epoch_while_everyone_else_keeps_reading() {
    let founder = identity(1);
    let stayer = identity(2);
    let revoked = identity(3);

    let (mut founder_node, _) = node(1).await;
    let (mut stayer_node, stayer_addr) = node(2).await;
    let (mut revoked_node, revoked_addr) = node(3).await;

    // A network with three keyed-in members.
    let parent = founder_node.append_entry(genesis(&founder)).unwrap();
    founder_node.create_epoch_group(&founder).unwrap();
    let parent = founder_node
        .append_entry(admit(&founder, &stayer, parent, 10))
        .unwrap();
    founder_node
        .append_entry(admit(&founder, &revoked, parent, 11))
        .unwrap();

    founder_node.dial_candidates([stayer_addr]).unwrap();
    assert!(drive(&mut founder_node, &mut stayer_node, Duration::from_secs(20), same_length).await);
    key_in(&mut founder_node, &founder, &mut stayer_node, &stayer, 20).await;

    founder_node.dial_candidates([revoked_addr]).unwrap();
    assert!(drive(&mut founder_node, &mut revoked_node, Duration::from_secs(20), same_length).await);
    key_in(&mut founder_node, &founder, &mut revoked_node, &revoked, 21).await;

    // The stayer picks up the commit that admitted the third member.
    resync(&mut stayer_node, &mut founder_node, &founder).await;
    stayer_node.apply_pending_rotations();
    assert_eq!(
        fingerprint(&founder_node),
        fingerprint(&revoked_node),
        "all three should share an epoch before the revocation"
    );

    // Content published *before* the revocation, which the revoked member can
    // legitimately open and will keep being able to open forever.
    let pointer = PointerId::from_bytes([5u8; 32]);
    let old_dek = Dek::generate().unwrap();
    let before_key = founder_node.epoch_keyring().current().unwrap().1.clone();
    let wrapped_before = before_key.wrap(&pointer, &old_dek);
    let revoked_before = revoked_node.epoch_keyring().current().unwrap().1.clone();
    assert!(
        revoked_before.unwrap_dek(&pointer, &wrapped_before).is_ok(),
        "the member could read before removal, which is the premise of the test"
    );

    // Ordering is enforced, not assumed: rotating while the target is still a
    // member would mint a key they are still entitled to.
    let premature = founder_node.revoke_epoch_member(
        &revoked.id(),
        &founder,
        Timestamp::from_millis(29),
    );
    assert!(
        premature.is_err(),
        "rotating before the membership removal must be refused"
    );

    // Remove, then rotate. The parent is the *current* tip: the key deliveries
    // above each appended a rotation, so anything captured earlier would fork.
    founder_node
        .append_entry(remove(&founder, &revoked, tip(&founder_node), 30))
        .unwrap();
    let rotation = founder_node
        .revoke_epoch_member(&revoked.id(), &founder, Timestamp::from_millis(31))
        .expect("the rotation should be authorized")
        .expect("a keyed-in member has a leaf to remove");

    let after_key = founder_node.epoch_keyring().current().unwrap().1.clone();
    assert_ne!(
        before_key.fingerprint(),
        after_key.fingerprint(),
        "revocation must actually advance the epoch"
    );

    // The remaining member follows along by ordinary sync.
    resync(&mut stayer_node, &mut founder_node, &founder).await;
    let applied = stayer_node.apply_pending_rotations();
    assert!(
        applied.contains(&rotation),
        "the remaining member should apply the revocation commit"
    );
    assert_eq!(
        fingerprint(&stayer_node),
        fingerprint(&founder_node),
        "remaining members keep full access via the new epoch key"
    );

    // The revoked member sees the entry — the log is public to whoever can still
    // reach it — and cannot turn it into the new key.
    resync(&mut revoked_node, &mut founder_node, &founder).await;
    revoked_node.apply_pending_rotations();
    assert_ne!(
        fingerprint(&revoked_node),
        fingerprint(&founder_node),
        "a revoked member must not be able to derive the epoch that excluded them"
    );

    // Concretely: content wrapped after the removal does not open for them.
    let new_dek = Dek::generate().unwrap();
    let wrapped_after = after_key.wrap(&pointer, &new_dek);
    let revoked_now = revoked_node.epoch_keyring().current().unwrap().1.clone();
    assert!(
        revoked_now.unwrap_dek(&pointer, &wrapped_after).is_err(),
        "nothing wrapped after removal may be readable by the removed member"
    );
    assert!(
        after_key.unwrap_dek(&pointer, &wrapped_after).is_ok(),
        "while remaining members read it normally"
    );

    // The floor, asserted as deliberately as the guarantee: what they already
    // held, they still hold. Claiming otherwise would be claiming the
    // impossible.
    assert!(
        revoked_before.unwrap_dek(&pointer, &wrapped_before).is_ok(),
        "a revoked member keeps what they could already decrypt — no symmetric \
         scheme can un-know a key, and asserting otherwise would be dishonest"
    );
}

#[tokio::test]
async fn a_revoked_member_is_refused_new_ciphertext_as_well_as_new_keys() {
    // The other half of §5.5. Losing the key stops them reading *new* wrappings;
    // the serving gate stops them collecting the bytes at all. Either alone
    // leaves a gap, so both are asserted.
    let founder = identity(4);
    let revoked = identity(5);
    let (mut founder_node, _) = node(4).await;
    let (mut revoked_node, revoked_addr) = node(5).await;

    let parent = founder_node.append_entry(genesis(&founder)).unwrap();
    founder_node.create_epoch_group(&founder).unwrap();
    let parent = founder_node
        .append_entry(admit(&founder, &revoked, parent, 10))
        .unwrap();

    founder_node.dial_candidates([revoked_addr]).unwrap();
    assert!(drive(&mut founder_node, &mut revoked_node, Duration::from_secs(20), same_length).await);

    // While still a member, the node can fetch content bytes.
    let cid = founder_node.store_chunk(b"published content".to_vec());
    revoked_node.request_chunk(founder.id(), cid, &revoked);
    let served = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            tokio::select! {
                _ = founder_node.next_event() => {}
                event = revoked_node.next_event() => {
                    match event {
                        NodeEvent::ChunkReceived { .. } => return true,
                        NodeEvent::ChunkUnavailable { .. } => return false,
                        _ => {}
                    }
                }
            }
        }
    })
    .await
    .unwrap_or(false);
    assert!(served, "a current member holding read-content is served");

    // Remove them, and let their own replay converge on the removal.
    founder_node
        .append_entry(remove(&founder, &revoked, parent, 30))
        .unwrap();

    let other = founder_node.store_chunk(b"content published after removal".to_vec());
    revoked_node.request_chunk(founder.id(), other, &revoked);
    let refusal = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            tokio::select! {
                _ = founder_node.next_event() => {}
                event = revoked_node.next_event() => {
                    match event {
                        NodeEvent::ChunkUnavailable { reason, .. } => return Some(reason),
                        NodeEvent::ChunkReceived { .. } => return None,
                        _ => {}
                    }
                }
            }
        }
    })
    .await
    .expect("the serving node should answer");

    let reason = refusal.expect("a revoked member must not be served new ciphertext");
    assert!(
        reason.contains("read-content"),
        "refusal should name the gate, got: {reason}"
    );
}

#[tokio::test]
async fn revoking_a_member_who_was_never_keyed_in_needs_no_commit() {
    // Admitted to the network but never keyed in — no leaf, so nothing to
    // remove. Reported as "no rotation" rather than as an error, since there is
    // nothing wrong with the request and nothing for a caller to fix.
    let founder = identity(6);
    let ghost = identity(7);
    let (mut founder_node, _) = node(6).await;

    let parent = founder_node.append_entry(genesis(&founder)).unwrap();
    founder_node.create_epoch_group(&founder).unwrap();
    let parent = founder_node
        .append_entry(admit(&founder, &ghost, parent, 10))
        .unwrap();
    founder_node
        .append_entry(remove(&founder, &ghost, parent, 20))
        .unwrap();

    let before = founder_node.governance_log().len();
    let rotation = founder_node
        .revoke_epoch_member(&ghost.id(), &founder, Timestamp::from_millis(30))
        .expect("revoking a never-keyed member is not an error");
    assert!(rotation.is_none(), "there was no leaf to remove");
    assert_eq!(
        founder_node.governance_log().len(),
        before,
        "and therefore no rotation entry was appended"
    );
}
