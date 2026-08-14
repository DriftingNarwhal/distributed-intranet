//! Search postings propagating over the append-set primitive — Search Spec §3.
//!
//! # What this closes
//!
//! Tokenizing, posting construction, TF-IDF ranking and the local index were all
//! implemented and tested against postings that never left the machine that
//! built them. A search index whose entries cannot reach another node indexes
//! nothing anyone else can find, which is the entire point of §1's "no crawlers"
//! design: the index is built as a side effect of publishing and distributed by
//! the same DHT everything else uses.
//!
//! # The shape being exercised
//!
//! One posting object per publish, announced under every term it matched (§3.1's
//! efficiency note), carried by the generic append-set collection primitive
//! (Storage Spec §2.5) rather than by anything search-specific. A query
//! enumerates a term's collection, validates what comes back, and ranks locally.

use intranet_crypto::{Hash, Timestamp};
use intranet_governance::{
    Capability, EntryBody, GroupId, LogEntry, MembershipAction, ModerationAction, ModerationEntry,
    NetworkPolicy, PointerId,
};
use intranet_identity::{MasterSeed, NetworkId, PerNetworkIdentity};
use intranet_search::{
    ContentMetadata, IndexableContent, LocalIndex, Posting, decode_posting, encode_posting, search,
};
use intranet_storage::collection_id;
use intranet_transport::{MemberNode, NodeEvent};
use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;
use std::time::Duration;

const NETWORK: NetworkId = NetworkId::from_bytes([42u8; 32]);

fn identity(n: u8) -> PerNetworkIdentity {
    MasterSeed::from_entropy([n; 32]).identity_for(&NETWORK).unwrap()
}

fn genesis(founder: &PerNetworkIdentity) -> LogEntry {
    LogEntry::create(
        founder,
        None,
        Timestamp::from_millis(0),
        EntryBody::Genesis {
            network: NETWORK,
            policy: NetworkPolicy::conservative_default(),
            everyone_capabilities: [Capability::ReadContent].into_iter().collect(),
        },
    )
}

fn admit(
    founder: &PerNetworkIdentity,
    parent: Hash,
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

fn posting_for(
    publisher: &PerNetworkIdentity,
    pointer: PointerId,
    title: &str,
    description: &str,
) -> Posting {
    let metadata = ContentMetadata::new(title, description);
    let content = IndexableContent {
        pointer_id: pointer,
        metadata: &metadata,
        document: None,
    };
    Posting::build(publisher, &content, Timestamp::from_millis(1_000))
}

async fn node(seed: u8) -> (MemberNode, Multiaddr) {
    let identity = identity(seed);
    let mut node = MemberNode::new(&identity).unwrap();
    // Loopback confirms no external address, so Kademlia would stay a client and
    // answer every lookup with "nobody". See `set_dht_server_mode`.
    node.set_dht_server_mode(true);
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

async fn settle(a: &mut MemberNode, b: &mut MemberNode, how_long: Duration) {
    let _ = drive(a, b, how_long, |_, _| false).await;
}

/// A publisher and a searcher that agree on governance.
async fn pair() -> (MemberNode, MemberNode) {
    let founder = identity(1);
    let searcher = identity(2);
    let (mut publisher, _) = node(1).await;
    let (mut seeker, seeker_addr) = node(2).await;

    let root = publisher.append_entry(genesis(&founder)).unwrap();
    publisher
        .append_entry(admit(&founder, root, &searcher, 5))
        .unwrap();

    publisher.dial_candidates([seeker_addr]).unwrap();
    assert!(
        drive(&mut publisher, &mut seeker, Duration::from_secs(20), |a, b| {
            a.governance_log().len() == 2 && b.governance_log().len() == 2
        })
        .await
    );

    (publisher, seeker)
}

/// Announces a posting under every term it matched — §3.1.
fn announce(node: &mut MemberNode, posting: &Posting) {
    let payload = encode_posting(posting);
    let entry_id = posting.id();
    for collection in posting.announcements(&NETWORK) {
        node.publish_to_collection(collection, entry_id, payload.clone());
    }
}

/// Runs a full query for one term, returning the postings that survived
/// validation on the searching node.
async fn resolve_term(
    seeker: &mut MemberNode,
    other: &mut MemberNode,
    term: &str,
    requester: &PerNetworkIdentity,
) -> Vec<Posting> {
    let collection = collection_id(&NETWORK, term);
    seeker.enumerate_collection(collection);

    let mut postings = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(20), async {
        let mut asked = 0usize;
        let mut answered = 0usize;
        loop {
            tokio::select! {
                event = seeker.next_event() => match event {
                    NodeEvent::CollectionProviders { collection_id: got, providers }
                        if got == collection =>
                    {
                        if providers.is_empty() {
                            return;
                        }
                        asked = providers.len();
                        for peer in providers {
                            seeker.request_collection(peer, collection, requester);
                        }
                    }
                    NodeEvent::CollectionEnumerated { collection_id: got, payloads, .. }
                        if got == collection =>
                    {
                        for payload in payloads {
                            if let Ok(posting) = decode_posting(&payload) {
                                postings.push(posting);
                            }
                        }
                        answered += 1;
                        if answered >= asked {
                            return;
                        }
                    }
                    _ => {}
                },
                _ = other.next_event() => {}
            }
        }
    })
    .await;
    postings
}

#[tokio::test]
async fn a_query_finds_content_published_on_another_node() {
    // The whole point of §3: indexing happens as a side effect of publishing on
    // one node, and a search on a different node finds it, with no crawler and
    // no central index server.
    let (mut publisher, mut seeker) = pair().await;
    let founder = identity(1);
    let searcher = identity(2);

    let pointer = PointerId::from_bytes([7u8; 32]);
    let posting = posting_for(
        &founder,
        pointer,
        "Trail maps for the north ridge",
        "Printable topographic maps of the ridge",
    );
    announce(&mut publisher, &posting);
    settle(&mut publisher, &mut seeker, Duration::from_secs(3)).await;

    let found = resolve_term(&mut seeker, &mut publisher, "topographic", &searcher).await;
    assert_eq!(found.len(), 1, "the posting should be discoverable by term");
    assert_eq!(found[0].pointer_id, pointer);

    // A query is answered from a locally built index, ranked locally (§5).
    let state = seeker.governance_log().replay_canonical().unwrap();
    let mut index = LocalIndex::new(NETWORK);
    for posting in found {
        index.insert(posting, &state).unwrap();
    }
    let results = search(&index, "topographic maps");
    assert_eq!(results.results.len(), 1);
    assert_eq!(results.results[0].pointer_id, pointer);
}

#[tokio::test]
async fn a_term_nobody_published_under_returns_nothing() {
    // The negative case. Without it the test above would pass against a build
    // that returned every posting it held for any query.
    let (mut publisher, mut seeker) = pair().await;
    let founder = identity(1);
    let searcher = identity(2);

    announce(
        &mut publisher,
        &posting_for(
            &founder,
            PointerId::from_bytes([7u8; 32]),
            "Trail maps",
            "Topographic maps",
        ),
    );
    settle(&mut publisher, &mut seeker, Duration::from_secs(3)).await;

    let found = resolve_term(&mut seeker, &mut publisher, "kayaking", &searcher).await;
    assert!(
        found.is_empty(),
        "a term the content never matched should find nothing, got {found:?}"
    );
}

#[tokio::test]
async fn one_posting_is_reachable_under_every_term_it_matched() {
    // §3.1's efficiency note made observable: the object is built and signed
    // once, and it is the announcement that repeats per term. If this were
    // implemented the expensive way — one posting object per term — each lookup
    // would return a *different* object, so asserting the identifier is what
    // distinguishes the two shapes.
    let (mut publisher, mut seeker) = pair().await;
    let founder = identity(1);
    let searcher = identity(2);

    let posting = posting_for(
        &founder,
        PointerId::from_bytes([7u8; 32]),
        "Trail maps for the north ridge",
        "Printable topographic maps",
    );
    announce(&mut publisher, &posting);
    settle(&mut publisher, &mut seeker, Duration::from_secs(3)).await;

    for term in ["trail", "ridge", "topographic"] {
        let found = resolve_term(&mut seeker, &mut publisher, term, &searcher).await;
        assert_eq!(found.len(), 1, "'{term}' should find the posting");
        assert_eq!(
            found[0].id(),
            posting.id(),
            "'{term}' should return the same single posting object, not a per-term copy"
        );
    }
}

#[tokio::test]
async fn a_posting_for_delisted_content_is_refused_by_the_searcher() {
    // §3.1's third mandatory check, and the one that makes moderation actually
    // effective rather than cosmetic. The publisher is a current member in good
    // standing and its signature is valid, so the first two checks pass — only
    // the delisting check stops the index entry, and it has to be applied by the
    // node *relying* on the posting, since the announcing node has every reason
    // not to.
    let founder = identity(1);
    let searcher = identity(2);
    let (mut publisher, mut seeker) = pair().await;

    let pointer = PointerId::from_bytes([7u8; 32]);
    let posting = posting_for(&founder, pointer, "Trail maps", "Topographic maps");
    announce(&mut publisher, &posting);
    settle(&mut publisher, &mut seeker, Duration::from_secs(3)).await;

    let found = resolve_term(&mut seeker, &mut publisher, "topographic", &searcher).await;
    assert_eq!(found.len(), 1, "precondition: the posting is discoverable");

    // Delist the content it points at.
    let tip = *publisher.governance_log().canonical_chain().last().unwrap();
    publisher
        .append_entry(LogEntry::create(
            &founder,
            Some(tip),
            Timestamp::from_millis(50),
            EntryBody::Moderation(ModerationEntry {
                action: ModerationAction::Delist,
                target_pointer_id: pointer,
            }),
        ))
        .unwrap();
    let publisher_peer = publisher.peer_id();
    seeker.sync_with(publisher_peer);
    assert!(
        drive(&mut publisher, &mut seeker, Duration::from_secs(20), |_, b| {
            b.governance_log().len() == 3
        })
        .await,
        "the searcher needs the moderation entry"
    );

    // The posting still propagates — nothing withdraws it — but it must not
    // enter the index.
    let still_found = resolve_term(&mut seeker, &mut publisher, "topographic", &searcher).await;
    assert_eq!(
        still_found.len(),
        1,
        "the announcement is unchanged; delisting is enforced by the reader"
    );

    let state = seeker.governance_log().replay_canonical().unwrap();
    let mut index = LocalIndex::new(NETWORK);
    let rejected = index.insert(still_found[0].clone(), &state);
    assert!(
        rejected.is_err(),
        "a posting referencing delisted content must be refused"
    );
    assert!(index.is_empty());
}

