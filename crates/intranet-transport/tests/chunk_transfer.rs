//! Chunk transfer between nodes — Storage Spec §4, §5.4.
//!
//! # The gap these close
//!
//! Everything about content addressing, chunking, encryption, source selection
//! and the serving gate was implemented and tested while no byte of content
//! could move between two nodes. `may_serve` was a pure function nobody called
//! from a network path; `select_sources` ranked candidates that could not then
//! be asked for anything. These are the first tests in which content actually
//! travels.

use intranet_crypto::Timestamp;
use intranet_governance::{
    Capability, EntryBody, GroupId, LogEntry, MembershipAction, NetworkPolicy,
};
use intranet_identity::{MasterSeed, NetworkId, PerNetworkIdentity};
use intranet_storage::Cid;
use intranet_transport::{MemberNode, NodeEvent};
use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;
use std::time::Duration;

const NETWORK: NetworkId = NetworkId::from_bytes([42u8; 32]);

fn identity(n: u8) -> PerNetworkIdentity {
    MasterSeed::from_entropy([n; 32]).identity_for(&NETWORK).unwrap()
}

/// Genesis granting `everyone` the `read-content` capability the gate checks.
fn genesis(founder: &PerNetworkIdentity, everyone_reads: bool) -> LogEntry {
    let everyone = if everyone_reads {
        vec![Capability::ReadContent]
    } else {
        vec![]
    };
    LogEntry::create(
        founder,
        None,
        Timestamp::from_millis(0),
        EntryBody::Genesis {
            network: NETWORK,
            policy: NetworkPolicy::conservative_default(),
            everyone_capabilities: everyone.into_iter().collect(),
        },
    )
}

fn admit(
    founder: &PerNetworkIdentity,
    parent: intranet_crypto::Hash,
    who: &PerNetworkIdentity,
    at: i64,
) -> LogEntry {
    LogEntry::create(
        founder,
        Some(parent),
        Timestamp::from_millis(at),
        EntryBody::MembershipChange {
            group: GroupId::everyone(),
            identity: who.id(),
            action: MembershipAction::Add { via_invite: None },
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

/// Drives two nodes until `done`, or the deadline passes.
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

/// Drives two nodes until the fetcher reports an outcome for `cid`.
async fn await_outcome(
    fetcher: &mut MemberNode,
    other: &mut MemberNode,
    cid: Cid,
) -> Option<NodeEvent> {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            tokio::select! {
                event = fetcher.next_event() => match event {
                    NodeEvent::ChunkReceived { cid: got, .. } if got == cid => return Some(event),
                    NodeEvent::ChunkUnavailable { cid: got, .. } if got == cid => {
                        return Some(event);
                    }
                    _ => {}
                },
                _ = other.next_event() => {}
            }
        }
    })
    .await
    .ok()
    .flatten()
}

/// Two connected nodes sharing a chain that admits both, with `read-content`.
async fn pair(everyone_reads: bool) -> (MemberNode, MemberNode) {
    let founder = identity(1);
    let joiner = identity(2);
    let (mut host, _) = node(1).await;
    let (mut guest, guest_addr) = node(2).await;

    let root = host.append_entry(genesis(&founder, everyone_reads)).unwrap();
    host.append_entry(admit(&founder, root, &joiner, 5)).unwrap();

    host.dial_candidates([guest_addr]).unwrap();
    assert!(
        drive(&mut host, &mut guest, Duration::from_secs(20), |a, b| {
            a.governance_log().len() == 2 && b.governance_log().len() == 2
        })
        .await,
        "both nodes should agree on governance before content moves"
    );

    (host, guest)
}

#[tokio::test]
async fn content_moves_between_nodes_and_verifies_on_arrival() {
    let (mut host, mut guest) = pair(true).await;
    let joiner = identity(2);

    let content = b"the quick brown fox jumps over the lazy dog".to_vec();
    let cid = host.store_chunk(content.clone());
    assert!(!guest.chunk_store().has(&cid));

    guest.request_chunk(identity(1).id(), cid, &joiner);

    let outcome = await_outcome(&mut guest, &mut host, cid).await;
    assert!(
        matches!(outcome, Some(NodeEvent::ChunkReceived { .. })),
        "the chunk should transfer, got {outcome:?}"
    );
    assert_eq!(guest.chunk_store().get(&cid), Some(content.as_slice()));
}

#[tokio::test]
async fn fetching_a_chunk_makes_the_fetcher_a_server_for_it() {
    // §4.2: swarm membership is automatic and needs no per-item opt-in. Person A
    // publishes, B fetches to view it, and B is thereby a candidate source for
    // C — without B doing anything to "start serving". Tested by actually
    // fetching from B afterwards, since a store containing the bytes proves only
    // half of it.
    let (mut host, mut guest) = pair(true).await;
    let founder = identity(1);
    let joiner = identity(2);

    let content = b"popular content".to_vec();
    let cid = host.store_chunk(content.clone());

    guest.request_chunk(founder.id(), cid, &joiner);
    assert!(matches!(
        await_outcome(&mut guest, &mut host, cid).await,
        Some(NodeEvent::ChunkReceived { .. })
    ));

    // The publisher drops its copy entirely — §4.5's "a publisher can go fully
    // offline after initial distribution and popular content remains servable".
    host.chunk_store_mut().remove(&cid);
    assert!(!host.chunk_store().has(&cid));

    // Now the original publisher fetches from the viewer.
    host.request_chunk(joiner.id(), cid, &founder);
    let outcome = await_outcome(&mut host, &mut guest, cid).await;
    assert!(
        matches!(outcome, Some(NodeEvent::ChunkReceived { .. })),
        "a node that merely viewed the content must be able to serve it back, \
         got {outcome:?}"
    );
    assert_eq!(host.chunk_store().get(&cid), Some(content.as_slice()));
}

#[tokio::test]
async fn a_requester_without_read_content_is_refused() {
    // §5.4's gate on a real network path. Under a genesis granting `everyone`
    // nothing, a member in good standing still holds no `read-content`, which is
    // exactly the waiting-room posture the gate exists for: a valid, non-revoked
    // identity that has not been admitted to anything must not receive
    // ciphertext or bandwidth.
    let (mut host, mut guest) = pair(false).await;
    let joiner = identity(2);

    let cid = host.store_chunk(b"members only".to_vec());
    guest.request_chunk(identity(1).id(), cid, &joiner);

    let outcome = await_outcome(&mut guest, &mut host, cid).await;
    let Some(NodeEvent::ChunkUnavailable {
        reason,
        counted_against_peer,
        ..
    }) = outcome
    else {
        panic!("expected a refusal, got {outcome:?}");
    };
    assert!(
        reason.contains("read-content"),
        "the refusal should say why: {reason}"
    );
    assert!(
        !counted_against_peer,
        "a node correctly enforcing the gate has not misbehaved and must not be \
         marked unreliable for it"
    );
    assert!(!guest.chunk_store().has(&cid));
}

#[tokio::test]
async fn a_chunk_nobody_holds_is_reported_as_not_held() {
    // Distinct from a refusal, and deliberately: "not held" is the ordinary
    // answer to a stale provider record, where a refusal is a judgement about
    // the requester. A requester that could not tell them apart would either
    // give up too early or retry a refusal against every holder in the swarm.
    let (mut host, mut guest) = pair(true).await;
    let joiner = identity(2);
    let cid = Cid::of(b"content nobody has");

    guest.request_chunk(identity(1).id(), cid, &joiner);

    let outcome = await_outcome(&mut guest, &mut host, cid).await;
    let Some(NodeEvent::ChunkUnavailable {
        reason,
        counted_against_peer,
        ..
    }) = outcome
    else {
        panic!("expected not-held, got {outcome:?}");
    };
    assert_eq!(reason, "not held");
    assert!(
        !counted_against_peer,
        "not holding a chunk is not a verification failure — counting it would make \
         every node that dropped a cached copy look unreliable"
    );
}

#[tokio::test]
async fn a_chunk_that_fails_verification_is_discarded_and_counted() {
    // §4.4 step 5 and Core Protocol Spec §4.6 together. A source serving bytes
    // that are not what their identifier says must have its copy discarded, and
    // that failure feeds this node's local reliability signal — the only kind of
    // failure that does.
    //
    // The dishonesty is constructed by storing bytes under a CID they do not
    // match, which the store refuses through its normal path, so the test
    // deliberately reaches past it.
    let (mut host, mut guest) = pair(true).await;
    let joiner = identity(2);

    let honest_cid = Cid::of(b"what the requester asked for");
    host.chunk_store_mut()
        .insert_unchecked(honest_cid, b"something else entirely".to_vec());

    let before = guest
        .reliability_observations()
        .for_peer(&identity(1).id())
        .total();
    guest.request_chunk(identity(1).id(), honest_cid, &joiner);

    let outcome = await_outcome(&mut guest, &mut host, honest_cid).await;
    let Some(NodeEvent::ChunkUnavailable {
        reason,
        counted_against_peer,
        ..
    }) = outcome
    else {
        panic!("expected a verification failure, got {outcome:?}");
    };
    assert!(reason.contains("verification"), "{reason}");
    assert!(
        counted_against_peer,
        "serving bytes that do not match their identifier is exactly the \
         verification failure §4.6 records"
    );
    assert!(
        !guest.chunk_store().has(&honest_cid),
        "a chunk that failed verification must not be stored, or this node would \
         go on to serve the corrupt copy itself"
    );

    let observations = guest.reliability_observations().for_peer(&identity(1).id());
    assert_eq!(observations.total(), before + 1);
    assert_eq!(
        observations.failure_rate(),
        Some(1.0),
        "the failure should be recorded against the source that served it"
    );
}

#[tokio::test]
async fn a_successful_fetch_records_a_verified_observation() {
    // The other half of the signal, without which `failure_rate` has no
    // denominator and a peer that served correctly a thousand times would look
    // identical to one that had never been asked.
    let (mut host, mut guest) = pair(true).await;
    let founder = identity(1);
    let joiner = identity(2);

    let cid = host.store_chunk(b"good content".to_vec());
    guest.request_chunk(founder.id(), cid, &joiner);
    assert!(matches!(
        await_outcome(&mut guest, &mut host, cid).await,
        Some(NodeEvent::ChunkReceived { .. })
    ));

    let observations = guest.reliability_observations().for_peer(&founder.id());
    assert_eq!(observations.total(), 1);
    assert_eq!(observations.failure_rate(), Some(0.0));
}

#[tokio::test]
async fn a_signed_request_replayed_by_a_different_peer_is_refused() {
    // A signed request proves the named identity *made* it. It does not prove
    // that whoever delivered it is that identity — anyone who captured it could
    // replay it. Binding the request to the connection is what closes that, and
    // it needs its own test because the refusal it produces is indistinguishable
    // from an ordinary capability refusal: without this, the gate test above
    // could be passing through this branch instead of the one it names.
    //
    // The borrowed identity is deliberately a full member holding `read-content`,
    // so the *only* reason to refuse is that it is not the peer on the wire.
    let founder = identity(1);
    let guest_identity = identity(2);
    let bystander = identity(3);

    let (mut host, _) = node(1).await;
    let (mut guest, guest_addr) = node(2).await;

    let root = host.append_entry(genesis(&founder, true)).unwrap();
    let next = host.append_entry(admit(&founder, root, &guest_identity, 5)).unwrap();
    host.append_entry(admit(&founder, next, &bystander, 6)).unwrap();

    host.dial_candidates([guest_addr]).unwrap();
    assert!(
        drive(&mut host, &mut guest, Duration::from_secs(20), |a, b| {
            a.governance_log().len() == 3 && b.governance_log().len() == 3
        })
        .await
    );

    let cid = host.store_chunk(b"members only".to_vec());

    // Sanity: the bystander genuinely holds read-content, so a refusal below
    // cannot be blamed on its standing.
    let state = host.governance_log().replay_canonical().unwrap();
    assert!(intranet_storage::may_serve(&bystander.id(), &state).is_ok());

    // The guest asks in the bystander's name, over the guest's own connection.
    guest.request_chunk(founder.id(), cid, &bystander);

    let outcome = await_outcome(&mut guest, &mut host, cid).await;
    assert!(
        matches!(outcome, Some(NodeEvent::ChunkUnavailable { .. })),
        "a request signed by one identity and delivered by another must be refused, \
         got {outcome:?}"
    );
    assert!(
        !guest.chunk_store().has(&cid),
        "no bytes should have been handed over"
    );
}
