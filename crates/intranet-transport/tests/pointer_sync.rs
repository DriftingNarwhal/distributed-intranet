//! Mutable pointer distribution — Storage Spec §2.2, §5.3, §5.4.
//!
//! # What was missing
//!
//! `MutablePointer` was a pure data type: publish, update, verify, and the
//! resolution rules including the same-version tie-break, all well covered in
//! one process. Nothing propagated a record or answered "what is the latest
//! version of this pointer", which three consuming specs need and none can work
//! without — an app manifest resolves through a pointer (App Hosting §4.5), a
//! live stream *is* a pointer whose `current_cid` advances (Real-Time §3.6), and
//! a search result is a pointer reference that has to resolve (Search §5).
//!
//! # The case that shapes the protocol
//!
//! Two publishers can each build on the same prior version and produce records
//! claiming the *identical* version. A digest keyed on version alone reports
//! those as agreeing, so neither side fetches the other and the disagreement is
//! permanent — the one failure a pointer sync exists to prevent. Carrying the
//! record hash makes it visible, and the existing lower-hash tie-break settles
//! it. `both_sides_of_a_same_version_fork_converge_on_the_lower_hash` is the
//! test that would fail against a version-only digest.

use intranet_crypto::{Hash, Timestamp};
use intranet_governance::{
    Capability, ContentType, EntryBody, GroupId, LogEntry, MembershipAction, ModerationAction,
    ModerationEntry, NetworkPolicy,
};
use intranet_identity::{MasterSeed, NetworkId, PerNetworkIdentity};
use intranet_storage::{Cid, Dek, DekWrapping, EpochKey, MutablePointer, new_pointer_id};
use intranet_transport::{MemberNode, NodeEvent};
use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;
use std::time::Duration;

const NETWORK: NetworkId = NetworkId::from_bytes([42u8; 32]);

fn identity(n: u8) -> PerNetworkIdentity {
    MasterSeed::from_entropy([n; 32]).identity_for(&NETWORK).unwrap()
}

fn text() -> ContentType {
    ContentType::new("text")
}

/// Genesis granting `everyone` both the read gate and the right to publish text.
fn genesis(founder: &PerNetworkIdentity) -> LogEntry {
    LogEntry::create(
        founder,
        None,
        Timestamp::from_millis(0),
        EntryBody::Genesis {
            network: NETWORK,
            policy: NetworkPolicy::conservative_default(),
            everyone_capabilities: [Capability::ReadContent, Capability::Publish(text())]
                .into_iter()
                .collect(),
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

fn cid(n: u8) -> Cid {
    Cid::from_hash(Hash::from_bytes([n; 32]))
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

/// Appends genesis plus an admission for each member, returning the tip.
///
/// Every node in a test needs the *same* log, since a pointer request is gated
/// on `read-content` and a node whose log does not admit the requester refuses
/// it — correctly, and confusingly if the test meant to exercise something else.
fn seed_log(node: &mut MemberNode, founder: &PerNetworkIdentity, members: &[u8]) -> Hash {
    let mut parent = node.append_entry(genesis(founder)).unwrap();
    for (n, seed) in members.iter().enumerate() {
        parent = node
            .append_entry(admit(founder, &identity(*seed), parent, 10 + n as i64))
            .unwrap();
    }
    parent
}

/// Two connected nodes sharing a log, both members able to publish text.
async fn pair() -> (MemberNode, PerNetworkIdentity, MemberNode, PerNetworkIdentity) {
    let founder = identity(1);
    let peer = identity(2);
    let (mut a, _) = node(1).await;
    let (mut b, b_addr) = node(2).await;

    // Seeds 3 and 6 join later in some tests; admitting them here keeps one
    // membership set across the whole file.
    seed_log(&mut a, &founder, &[2, 3, 6]);

    a.dial_candidates([b_addr]).unwrap();
    assert!(drive(&mut a, &mut b, Duration::from_secs(20), same_log).await);
    (a, founder, b, peer)
}

#[tokio::test]
async fn a_published_pointer_reaches_a_peer_with_its_wrapping() {
    let (mut a, founder, mut b, _) = pair().await;

    let state = a.governance_log().replay_canonical().unwrap();
    let pointer_id = new_pointer_id().unwrap();
    let dek = Dek::generate().unwrap();
    let pointer = MutablePointer::publish(
        &founder,
        pointer_id,
        text(),
        cid(7),
        dek.commitment(),
        &state,
    )
    .unwrap();
    assert!(a.accept_pointer(pointer.clone()));

    // A wrapping travels with it — without one a resolver has the address of
    // something it cannot open (§5.3).
    let epoch_key = EpochKey::from_bytes([3u8; 32]);
    let rotation = Hash::from_bytes([4u8; 32]);
    assert!(a.accept_wrapping(DekWrapping::create(
        &founder,
        pointer_id,
        &dek,
        &epoch_key,
        rotation,
    )));

    b.sync_pointers_with(founder.peer_id());
    assert!(
        drive(&mut a, &mut b, Duration::from_secs(20), |_, b| {
            b.pointer(&pointer_id).is_some()
        })
        .await,
        "the pointer should reach the peer"
    );

    let received = b.pointer(&pointer_id).unwrap();
    assert_eq!(received, &pointer, "the record must survive intact");
    assert!(received.verify().is_ok());

    // And the wrapping opens to the DEK the owner committed to — validated
    // against the commitment, not against who sent it.
    let wrapping = b
        .wrapping_under(&pointer_id, &rotation)
        .expect("the wrapping should travel with the record");
    let recovered = wrapping
        .unwrap(&epoch_key, &received.dek_commitment)
        .expect("the wrapping must open to the committed DEK");
    assert_eq!(recovered.commitment(), dek.commitment());
}

#[tokio::test]
async fn an_update_supersedes_and_a_stale_record_is_refused() {
    let (mut a, founder, mut b, _) = pair().await;
    let state = a.governance_log().replay_canonical().unwrap();

    let pointer_id = new_pointer_id().unwrap();
    let dek = Dek::generate().unwrap();
    let v0 = MutablePointer::publish(
        &founder,
        pointer_id,
        text(),
        cid(1),
        dek.commitment(),
        &state,
    )
    .unwrap();
    let v1 = v0.update(&founder, cid(2), &state).unwrap();

    assert!(a.accept_pointer(v1.clone()));
    b.sync_pointers_with(founder.peer_id());
    assert!(
        drive(&mut a, &mut b, Duration::from_secs(20), |_, b| {
            b.pointer(&pointer_id).is_some()
        })
        .await
    );
    assert_eq!(b.pointer(&pointer_id).unwrap().version, 1);

    // Replaying the older record must not roll the peer back. This is the check
    // that stops a stale record being presented as current.
    assert!(
        !b.accept_pointer(v0),
        "a lower version must be refused, not stored"
    );
    assert_eq!(b.pointer(&pointer_id).unwrap().version, 1);
    assert_eq!(b.pointer(&pointer_id).unwrap().current_cid, cid(2));
}

#[tokio::test]
async fn both_sides_of_a_same_version_fork_converge_on_the_lower_hash() {
    // The case a version-only digest cannot see. Two owners each publish version
    // 0 for *different* pointers built the same way — then each node is given
    // both competing records for one pointer id, in opposite orders, and must
    // land on the same winner.
    let (mut a, founder, mut b, peer) = pair().await;
    let state = a.governance_log().replay_canonical().unwrap();

    // Two records for the same pointer id at the same version, by different
    // owners — the concurrent-publish shape §2.2 describes.
    let pointer_id = new_pointer_id().unwrap();
    let dek = Dek::generate().unwrap();
    let from_founder = MutablePointer::publish(
        &founder,
        pointer_id,
        text(),
        cid(1),
        dek.commitment(),
        &state,
    )
    .unwrap();
    let from_peer = MutablePointer::publish(
        &peer,
        pointer_id,
        text(),
        cid(2),
        dek.commitment(),
        &state,
    )
    .unwrap();
    assert_eq!(from_founder.version, from_peer.version);
    assert_ne!(from_founder.record_hash(), from_peer.record_hash());

    let expected = MutablePointer::resolve(&from_founder, &from_peer).clone();

    // Delivered in opposite orders, which is the point: arrival order must not
    // decide the outcome.
    a.accept_pointer(from_founder.clone());
    a.accept_pointer(from_peer.clone());
    b.accept_pointer(from_peer.clone());
    b.accept_pointer(from_founder.clone());

    assert_eq!(
        a.pointer(&pointer_id).unwrap(),
        &expected,
        "the lower record hash wins regardless of arrival order"
    );
    assert_eq!(b.pointer(&pointer_id).unwrap(), &expected);

    // And over the wire: a node holding the losing record must adopt the winner
    // after a sync, which only happens because the digest carries a record hash.
    let (mut c, c_addr) = node(3).await;
    seed_log(&mut c, &founder, &[2, 3, 6]);
    let loser = if expected == from_founder {
        from_peer
    } else {
        from_founder
    };
    assert!(c.accept_pointer(loser.clone()));
    assert_eq!(c.pointer(&pointer_id).unwrap(), &loser);

    a.dial_candidates([c_addr]).unwrap();
    assert!(
        drive(&mut a, &mut c, Duration::from_secs(20), |_, c| {
            c.pointer(&pointer_id).is_some_and(|held| *held == expected)
        })
        .await,
        "a same-version disagreement must be visible in the digest and resolved"
    );
}

#[tokio::test]
async fn a_node_without_read_content_is_told_nothing_about_the_content_graph() {
    // §5.4 applied to pointers. The digest is a list of everything published,
    // which is the content graph itself — so gating it matters as much as
    // gating the records.
    let founder = identity(4);
    let (mut a, _) = node(4).await;
    let (mut outsider_node, outsider_addr) = node(5).await;

    // `everyone` holds publish rights but *not* read-content, so the outsider is
    // a valid identity that has simply not been admitted to anything.
    a.append_entry(LogEntry::create(
        &founder,
        None,
        Timestamp::from_millis(0),
        EntryBody::Genesis {
            network: NETWORK,
            policy: NetworkPolicy::conservative_default(),
            everyone_capabilities: [Capability::Publish(text())].into_iter().collect(),
        },
    ))
    .unwrap();

    let state = a.governance_log().replay_canonical().unwrap();
    let pointer_id = new_pointer_id().unwrap();
    let dek = Dek::generate().unwrap();
    a.accept_pointer(
        MutablePointer::publish(&founder, pointer_id, text(), cid(9), dek.commitment(), &state)
            .unwrap(),
    );

    a.dial_candidates([outsider_addr]).unwrap();
    assert!(drive(&mut a, &mut outsider_node, Duration::from_secs(20), same_log).await);

    outsider_node.sync_pointers_with(founder.peer_id());
    let refusal = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            tokio::select! {
                _ = a.next_event() => {}
                event = outsider_node.next_event() => {
                    match event {
                        NodeEvent::PointerSyncRefused { reason, .. } => return Some(reason),
                        NodeEvent::PointerDigest { offered, .. } => return None.filter(|_: &String| offered == 0),
                        _ => {}
                    }
                }
            }
        }
    })
    .await
    .expect("the serving node should answer");

    let reason = refusal.expect("a node without read-content must be refused");
    assert!(reason.contains("read-content"), "got: {reason}");
    assert!(
        outsider_node.pointer(&pointer_id).is_none(),
        "and must learn nothing about what exists"
    );
}

#[tokio::test]
async fn a_delisted_pointer_stops_being_served_and_stops_being_accepted() {
    // App Hosting §3.4 defines delisting as stopping content being "servable and
    // surfaced". A node that kept serving a delisted record would make
    // moderation effective only against whoever happened to be listening when it
    // was applied.
    let (mut a, founder, mut b, _) = pair().await;
    let state = a.governance_log().replay_canonical().unwrap();

    let pointer_id = new_pointer_id().unwrap();
    let dek = Dek::generate().unwrap();
    let pointer = MutablePointer::publish(
        &founder,
        pointer_id,
        text(),
        cid(5),
        dek.commitment(),
        &state,
    )
    .unwrap();
    assert!(a.accept_pointer(pointer.clone()));

    // Delist it.
    let tip = a.governance_log().canonical_chain().last().copied().unwrap();
    a.append_entry(LogEntry::create(
        &founder,
        Some(tip),
        Timestamp::from_millis(50),
        EntryBody::Moderation(ModerationEntry {
            action: ModerationAction::Delist,
            target_pointer_id: pointer_id,
        }),
    ))
    .unwrap();

    // A peer that has caught up refuses the record outright.
    b.sync_with(founder.peer_id());
    assert!(drive(&mut a, &mut b, Duration::from_secs(20), same_log).await);
    assert!(
        !b.accept_pointer(pointer.clone()),
        "a delisted pointer must not be stored"
    );
    assert!(b.pointer(&pointer_id).is_none());

    // And the serving node stops offering it, so a peer that never saw it does
    // not learn of it through the digest either.
    let (mut c, c_addr) = node(6).await;
    seed_log(&mut c, &founder, &[2, 3, 6]);
    a.dial_candidates([c_addr]).unwrap();
    assert!(drive(&mut a, &mut c, Duration::from_secs(20), same_log).await);
    c.sync_pointers_with(founder.peer_id());
    let offered = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            tokio::select! {
                _ = a.next_event() => {}
                event = c.next_event() => {
                    if let NodeEvent::PointerDigest { offered, .. } = event {
                        return offered;
                    }
                }
            }
        }
    })
    .await
    .expect("a digest should arrive");
    assert_eq!(offered, 0, "a delisted pointer must not appear in a digest");
}

#[tokio::test]
async fn a_pointer_whose_owner_may_not_publish_that_type_is_refused() {
    // §2.2's two gates, re-derived by the receiving node rather than trusted.
    // The publisher held publish:text when the record was made; the receiver
    // does not allow that type at all, and must refuse regardless.
    let founder = identity(7);
    let (mut a, _) = node(7).await;

    let state_owner = identity(8);
    let (mut publisher, _) = node(8).await;
    publisher.append_entry(genesis(&founder)).unwrap();
    let publisher_state = publisher.governance_log().replay_canonical().unwrap();
    let pointer_id = new_pointer_id().unwrap();
    let dek = Dek::generate().unwrap();
    let pointer = MutablePointer::publish(
        &founder,
        pointer_id,
        text(),
        cid(3),
        dek.commitment(),
        &publisher_state,
    )
    .unwrap();
    let _ = state_owner;

    // The receiving node's network excludes `text` from its allowlist entirely.
    let mut policy = NetworkPolicy::conservative_default();
    policy.content_type_allowlist.remove(&text());
    a.append_entry(LogEntry::create(
        &founder,
        None,
        Timestamp::from_millis(0),
        EntryBody::Genesis {
            network: NETWORK,
            policy,
            everyone_capabilities: [Capability::ReadContent].into_iter().collect(),
        },
    ))
    .unwrap();

    assert!(
        !a.accept_pointer(pointer),
        "a record whose type is not allowed here must be refused, however it was signed"
    );
    assert!(a.pointer(&pointer_id).is_none());
}

#[tokio::test]
async fn a_fresh_wrapping_replaces_a_stale_one_under_the_canonical_rotation() {
    // §5.3.1's cleanup, which is ordinary re-wrapping triggered by an extra
    // condition. Wrappings are keyed by rotation, so a fresh one under the
    // canonical rotation lands beside the stale one rather than fighting it, and
    // a resolver picks by rotation rather than by whoever published last.
    let (mut a, founder, _, _) = pair().await;
    let state = a.governance_log().replay_canonical().unwrap();

    let pointer_id = new_pointer_id().unwrap();
    let dek = Dek::generate().unwrap();
    a.accept_pointer(
        MutablePointer::publish(&founder, pointer_id, text(), cid(1), dek.commitment(), &state)
            .unwrap(),
    );

    let voided = Hash::from_bytes([1u8; 32]);
    let canonical = Hash::from_bytes([2u8; 32]);
    let old_key = EpochKey::from_bytes([10u8; 32]);
    let new_key = EpochKey::from_bytes([20u8; 32]);

    assert!(a.accept_wrapping(DekWrapping::create(
        &founder, pointer_id, &dek, &old_key, voided
    )));
    assert!(a.accept_wrapping(DekWrapping::create(
        &founder, pointer_id, &dek, &new_key, canonical
    )));

    assert_eq!(a.wrappings_for(&pointer_id).len(), 2);
    let stale = a.wrapping_under(&pointer_id, &voided).unwrap();
    assert!(stale.is_stale(&canonical), "the old one reports as stale");

    let fresh = a.wrapping_under(&pointer_id, &canonical).unwrap();
    assert!(!fresh.is_stale(&canonical));
    let commitment = a.pointer(&pointer_id).unwrap().dek_commitment;
    assert!(
        fresh.unwrap(&new_key, &commitment).is_ok(),
        "the canonical wrapping opens under the canonical epoch key"
    );

    // Re-wrapping under the same rotation is idempotent — determinism means two
    // members doing it independently produce byte-identical records, so this
    // converges rather than accumulating.
    assert!(a.accept_wrapping(DekWrapping::create(
        &founder, pointer_id, &dek, &new_key, canonical
    )));
    assert_eq!(a.wrappings_for(&pointer_id).len(), 2);
}
