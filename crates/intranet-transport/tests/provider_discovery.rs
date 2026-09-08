//! Provider discovery over Kademlia — Storage Spec §4.4 step 1.
//!
//! # What the DHT is for here
//!
//! Chunk transfer already worked, but only between nodes that already knew who
//! to ask. §4.4 has a requester query the DHT for each chunk it lacks, getting
//! back both the holders and — as a side effect — the holder *count* that
//! rarest-first ordering depends on.
//!
//! # Why these tests force DHT server mode
//!
//! libp2p keeps Kademlia in client mode until a node has a confirmed external
//! address, which is correct: a node nobody can dial makes a poor DHT server. On
//! loopback nothing ever confirms one, so every node stays a client, nothing
//! answers queries, and every provider lookup returns "nobody" — which is
//! indistinguishable from content genuinely having no holders. In a real
//! deployment the publicly addressable nodes carry the records, which is why
//! `RelayNode` runs Kademlia as well (§5.5).

use intranet_crypto::Timestamp;
use intranet_governance::{
    Capability, EntryBody, GroupId, LogEntry, MembershipAction, NetworkPolicy,
};
use intranet_identity::{MasterSeed, NetworkId, PerNetworkIdentity, PerNetworkIdentityId};
use intranet_ledger::{BandwidthCap, CapabilityAdvertisement, ComputeClass};
use intranet_storage::Cid;
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

/// An advertisement offering upload capacity.
///
/// Required before a node can be fetched from at all: §4.3 reads throughput from
/// the capability ledger, and `select_sources` drops a peer advertising none on
/// the grounds that it has not volunteered to serve. So the DHT reporting a
/// holder is necessary but not sufficient — the ledger has to know it too, which
/// makes the layering governance, then ledger, then fetch.
fn advertisement(node: &PerNetworkIdentity, at: i64) -> CapabilityAdvertisement {
    CapabilityAdvertisement::create(
        node,
        1 << 30,
        BandwidthCap {
            up_bytes_per_sec: 1_000_000,
            down_bytes_per_sec: 8_000_000,
            active_window: None,
        },
        false,
        false,
        ComputeClass::Modest,
        Timestamp::from_millis(at),
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

/// Runs both nodes for `settle`, letting announcements publish.
async fn settle(a: &mut MemberNode, b: &mut MemberNode, settle: Duration) {
    let _ = drive(a, b, settle, |_, _| false).await;
}

/// Asks `seeker` who holds `cid`, driving both nodes until the DHT answers.
async fn providers_of(
    seeker: &mut MemberNode,
    other: &mut MemberNode,
    cid: Cid,
) -> Option<(Vec<PerNetworkIdentityId>, usize)> {
    seeker.find_providers(cid);
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            tokio::select! {
                event = seeker.next_event() => {
                    if let NodeEvent::ProvidersFound { cid: got, providers, holder_count } = event
                        && got == cid
                    {
                        return (providers, holder_count);
                    }
                }
                _ = other.next_event() => {}
            }
        }
    })
    .await
    .ok()
}

async fn pair() -> (MemberNode, MemberNode) {
    let founder = identity(1);
    let joiner = identity(2);
    let (mut host, _) = node(1).await;
    let (mut guest, guest_addr) = node(2).await;

    let root = host.append_entry(genesis(&founder)).unwrap();
    host.append_entry(admit(&founder, root, &joiner, 5)).unwrap();

    host.dial_candidates([guest_addr]).unwrap();
    assert!(
        drive(&mut host, &mut guest, Duration::from_secs(20), |a, b| {
            a.governance_log().len() == 2 && b.governance_log().len() == 2
        })
        .await
    );

    host.advertise(advertisement(&founder, 100)).unwrap();
    let host_peer = host.peer_id();
    guest.sync_ledger_with(host_peer);
    assert!(
        drive(&mut host, &mut guest, Duration::from_secs(20), |_, b| {
            b.capability_ledger().len() == 1
        })
        .await,
        "the guest needs the host's advertisement before it can rank it as a source"
    );

    (host, guest)
}

#[tokio::test]
async fn the_dht_reports_who_holds_a_chunk() {
    let (mut host, mut guest) = pair().await;

    let cid = host.store_chunk(b"findable content".to_vec());
    settle(&mut host, &mut guest, Duration::from_secs(3)).await;

    let (providers, holder_count) = providers_of(&mut guest, &mut host, cid)
        .await
        .expect("the DHT should answer");

    assert_eq!(providers, vec![identity(1).id()]);
    assert_eq!(
        holder_count, 1,
        "the holder count is what rarest-first ordering reads (§4.4 step 2)"
    );
}

#[tokio::test]
async fn a_chunk_nobody_holds_reports_no_providers() {
    // The negative case, and the one that keeps the test above honest: a lookup
    // that returned the same answer regardless of who was providing would pass
    // it just as well.
    let (mut host, mut guest) = pair().await;
    let cid = Cid::of(b"content that was never published");
    settle(&mut host, &mut guest, Duration::from_secs(2)).await;

    let (providers, holder_count) = providers_of(&mut guest, &mut host, cid)
        .await
        .expect("the DHT should answer even when the answer is nobody");

    assert!(providers.is_empty());
    assert_eq!(holder_count, 0);
}

#[tokio::test]
async fn fetching_a_chunk_makes_the_fetcher_discoverable_as_a_holder() {
    // §4.2's automatic swarm membership, completed. The chunk transfer tests
    // already showed a fetcher can *serve* what it fetched; this shows the DHT
    // knows to send anyone there. A holder nobody can discover is a holder in
    // principle only, and this is the difference between a swarm that spreads
    // load and one where every request still lands on the publisher.
    let (mut host, mut guest) = pair().await;
    let founder = identity(1);
    let joiner = identity(2);

    let cid = host.store_chunk(b"popular content".to_vec());
    settle(&mut host, &mut guest, Duration::from_secs(3)).await;

    guest.request_chunk(founder.id(), cid, &joiner);
    let received = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            tokio::select! {
                event = guest.next_event() => {
                    if matches!(event, NodeEvent::ChunkReceived { .. }) {
                        return true;
                    }
                }
                _ = host.next_event() => {}
            }
        }
    })
    .await
    .unwrap_or(false);
    assert!(received, "the guest should have fetched the chunk");

    settle(&mut host, &mut guest, Duration::from_secs(3)).await;

    let (providers, holder_count) = providers_of(&mut host, &mut guest, cid)
        .await
        .expect("the DHT should answer");

    assert!(
        providers.contains(&joiner.id()),
        "the fetcher should now be discoverable as a holder, found {providers:?}"
    );
    assert_eq!(
        holder_count, 2,
        "both the publisher and the viewer should count as holders"
    );
}

#[tokio::test]
async fn a_stale_provider_record_degrades_to_a_clean_not_held() {
    // Kademlia has no un-publish. `stop_providing` drops the local record and
    // stops republishing, but copies already pushed to other peers persist until
    // they expire, so a node that dropped a chunk keeps being *advertised* for a
    // while afterwards. That is the protocol working as designed, not a bug to
    // fix — but it means provider records are a hint, never a promise.
    //
    // What has to hold is that following a stale hint costs a requester one
    // round trip and nothing else: a clean `not held`, no bytes, and nothing
    // counted against a peer that has done nothing wrong. Without the explicit
    // NotHeld response this would be indistinguishable from a peer refusing or
    // failing, and ordinary record expiry would look like misbehaviour.
    let (mut host, mut guest) = pair().await;
    let founder = identity(1);
    let joiner = identity(2);

    let cid = host.store_chunk(b"transient content".to_vec());
    settle(&mut host, &mut guest, Duration::from_secs(3)).await;
    let (providers, _) = providers_of(&mut guest, &mut host, cid).await.unwrap();
    assert_eq!(providers.len(), 1, "precondition: the host is a holder");

    host.forget_chunk(&cid);
    assert!(
        !host.chunk_store().has(&cid),
        "the bytes should be gone locally, whatever the DHT still says"
    );
    settle(&mut host, &mut guest, Duration::from_secs(2)).await;

    // The record has not expired, so the host is still offered. Following it
    // must be harmless.
    let (providers, _) = providers_of(&mut guest, &mut host, cid).await.unwrap();
    assert!(
        providers.contains(&founder.id()),
        "this test is about a *stale* record; if it has already expired there is \
         nothing here to exercise"
    );

    guest.request_chunk(founder.id(), cid, &joiner);
    let outcome = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            tokio::select! {
                event = guest.next_event() => {
                    if let NodeEvent::ChunkUnavailable { cid: got, .. } = &event
                        && *got == cid
                    {
                        return Some(event);
                    }
                }
                _ = host.next_event() => {}
            }
        }
    })
    .await
    .ok()
    .flatten();

    let Some(NodeEvent::ChunkUnavailable {
        reason,
        counted_against_peer,
        ..
    }) = outcome
    else {
        panic!("expected a clean not-held, got {outcome:?}");
    };
    assert_eq!(reason, "not held");
    assert!(
        !counted_against_peer,
        "a peer that dropped a cached copy has not misbehaved — counting expiry \
         lag against it would penalise every node that ever frees space"
    );
    assert!(!guest.chunk_store().has(&cid));
}

/// Drives three nodes until `done`, or the deadline passes.
async fn drive3(
    a: &mut MemberNode,
    b: &mut MemberNode,
    c: &mut MemberNode,
    limit: Duration,
    done: impl Fn(&MemberNode) -> bool,
) -> bool {
    tokio::time::timeout(limit, async {
        loop {
            if done(a) {
                return true;
            }
            tokio::select! {
                _ = a.next_event() => {}
                _ = b.next_event() => {}
                _ = c.next_event() => {}
            }
        }
    })
    .await
    .unwrap_or(false)
}

#[tokio::test]
async fn an_object_is_fetched_from_several_holders_at_once() {
    // §4.4 end to end, and the first time every piece runs together: DHT lookup,
    // rarest-first ordering, per-chunk source selection, parallel requests,
    // verification on arrival, and the fetcher joining each chunk's swarm.
    //
    // The chunks are split across two publishers so the fetch genuinely has to
    // draw from more than one source. If both held everything, a build that
    // always asked the same peer would pass just as well.
    let founder = identity(1);
    let second = identity(2);
    let fetcher = identity(3);

    let (mut a, a_addr) = node(1).await;
    let (mut b, b_addr) = node(2).await;
    let (mut c, _) = node(3).await;

    let root = a.append_entry(genesis(&founder)).unwrap();
    let next = a.append_entry(admit(&founder, root, &second, 5)).unwrap();
    a.append_entry(admit(&founder, next, &fetcher, 6)).unwrap();

    c.dial_candidates([a_addr]).unwrap();
    c.dial_candidates([b_addr]).unwrap();
    assert!(
        drive3(&mut c, &mut a, &mut b, Duration::from_secs(25), |c| {
            c.governance_log().len() == 3
        })
        .await,
        "the fetcher should learn the chain"
    );
    assert!(
        drive3(&mut a, &mut b, &mut c, Duration::from_secs(25), |a| {
            a.governance_log().len() == 3
        })
        .await
    );
    assert!(
        drive3(&mut b, &mut a, &mut c, Duration::from_secs(25), |b| {
            b.governance_log().len() == 3
        })
        .await
    );

    // Both publishers must advertise upload capacity, or source selection drops
    // them as not having volunteered to serve. The ledger sync that runs on
    // connect has already happened by now, so the fetcher is asked to sync
    // again — advertising is not a push (§4.5 is pull-based like everything
    // else), so a peer learns about it on its next sync.
    a.advertise(advertisement(&founder, 100)).unwrap();
    b.advertise(advertisement(&second, 100)).unwrap();
    let (a_peer, b_peer) = (a.peer_id(), b.peer_id());
    c.sync_ledger_with(a_peer);
    c.sync_ledger_with(b_peer);
    assert!(
        drive3(&mut c, &mut a, &mut b, Duration::from_secs(25), |c| {
            c.capability_ledger().len() == 2
        })
        .await,
        "the fetcher needs both advertisements before it can rank sources"
    );

    // Six chunks, split between the two publishers.
    let contents: Vec<Vec<u8>> = (0..6u8).map(|i| vec![i; 64]).collect();
    let mut cids = Vec::new();
    for (i, bytes) in contents.iter().enumerate() {
        let cid = if i % 2 == 0 {
            a.store_chunk(bytes.clone())
        } else {
            b.store_chunk(bytes.clone())
        };
        cids.push(cid);
    }
    let _ = drive3(&mut a, &mut b, &mut c, Duration::from_secs(4), |_| false).await;

    c.fetch_chunks(cids.clone(), &fetcher, 3);

    let mut completion = None;
    let finished = tokio::time::timeout(Duration::from_secs(40), async {
        loop {
            tokio::select! {
                event = c.next_event() => {
                    if let NodeEvent::FetchComplete { .. } = &event {
                        completion = Some(event);
                        return true;
                    }
                }
                _ = a.next_event() => {}
                _ = b.next_event() => {}
            }
        }
    })
    .await
    .unwrap_or(false);

    assert!(finished, "the fetch should complete");
    let Some(NodeEvent::FetchComplete {
        received,
        unavailable,
    }) = completion
    else {
        unreachable!()
    };
    assert!(
        unavailable.is_empty(),
        "every chunk had a holder, so none should be unavailable: {unavailable:?}"
    );
    assert_eq!(received.len(), 6, "all six chunks should arrive");

    for (cid, bytes) in cids.iter().zip(&contents) {
        assert_eq!(
            c.chunk_store().get(cid),
            Some(bytes.as_slice()),
            "chunk {} should have arrived intact",
            cid.short()
        );
    }

    // Both publishers should have been used: the chunks only exist on one each,
    // so a fetch that drew from a single source could not have completed. Made
    // explicit so the reason this passed is recorded rather than inferred.
    assert!(
        a.chunk_store().len() == 3 && b.chunk_store().len() == 3,
        "precondition: the content was genuinely split across two holders"
    );
}

#[tokio::test]
async fn a_fetch_completes_even_when_some_chunks_have_no_holder() {
    // A partial result is a real outcome. A fetch that hung waiting for content
    // nobody has would take an object missing one chunk and turn it into a
    // request that never returns.
    let (mut host, mut guest) = pair().await;
    let joiner = identity(2);

    let held = host.store_chunk(b"this one exists".to_vec());
    let missing = Cid::of(b"this one was never published");
    settle(&mut host, &mut guest, Duration::from_secs(3)).await;

    guest.fetch_chunks([held, missing], &joiner, 2);

    let completion = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            tokio::select! {
                event = guest.next_event() => {
                    if let NodeEvent::FetchComplete { .. } = &event {
                        return Some(event);
                    }
                }
                _ = host.next_event() => {}
            }
        }
    })
    .await
    .ok()
    .flatten();

    let Some(NodeEvent::FetchComplete {
        received,
        unavailable,
    }) = completion
    else {
        panic!("the fetch should complete, got {completion:?}");
    };
    assert_eq!(received, vec![held]);
    assert_eq!(unavailable, vec![missing]);
}

#[tokio::test]
async fn a_fetcher_finds_a_holder_it_was_never_told_about() {
    // **The property every other test here stops short of.** Each of them has
    // the fetcher connected to whoever holds the chunk — so the answer is
    // already in its routing table, and an implementation that merely asked
    // everyone it had a socket to would pass exactly as well. That is not
    // routing, and §4.4 step 1 is routing: the DHT exists so a node can find
    // content held by a peer it has never heard of.
    //
    // Forced by the topology rather than hoped for. The fetcher dials the middle
    // node and nothing else; the holder dials the middle node and nothing else;
    // the middle node holds no content of its own. So the only way the fetcher
    // can learn who has the chunk is by asking somebody who is not the holder.
    //
    // *Told about*, not *connected to*: the fetcher necessarily connects to the
    // holder in order to take the bytes, and the claim is about how it came to
    // know there was anybody to connect to. A name promising it never connected
    // would be false by the last assertion.
    //
    // Note what mDNS could and could not do to this on a loopback run: it
    // discovers *peers* and never auto-dials (§5.1), and it carries no provider
    // records at all. Knowing an address is not knowing who holds a chunk, so a
    // pass here cannot come from LAN discovery — which is why this needs a
    // topology rather than a container.
    let founder = identity(1);
    let holder_id = identity(2);
    let fetcher_id = identity(3);

    let (mut middle, middle_addr) = node(1).await;
    let (mut holder, _) = node(2).await;
    let (mut fetcher, _) = node(3).await;

    let root = middle.append_entry(genesis(&founder)).unwrap();
    let next = middle
        .append_entry(admit(&founder, root, &holder_id, 5))
        .unwrap();
    middle
        .append_entry(admit(&founder, next, &fetcher_id, 6))
        .unwrap();

    // Both dial the middle and neither dials the other. This is the whole test:
    // everything below is only meaningful because of these two lines.
    holder.dial_candidates([middle_addr.clone()]).unwrap();
    fetcher.dial_candidates([middle_addr]).unwrap();

    // Driven once per node because the predicate only sees the first, which is
    // what the existing three-node test does for the same reason.
    assert!(
        drive3(
            &mut fetcher,
            &mut middle,
            &mut holder,
            Duration::from_secs(25),
            |f| f.governance_log().len() == 3
        )
        .await,
        "the fetcher should learn the chain, through the middle node"
    );
    assert!(
        drive3(
            &mut holder,
            &mut middle,
            &mut fetcher,
            Duration::from_secs(25),
            |h| h.governance_log().len() == 3
        )
        .await,
        "and so should the holder"
    );
    assert!(
        drive3(
            &mut middle,
            &mut holder,
            &mut fetcher,
            Duration::from_secs(25),
            |m| m.governance_log().len() == 3
        )
        .await
    );

    // The holder must advertise upload capacity or source selection drops it as
    // not having volunteered (§4.3), and the fetcher has to have heard that.
    holder.advertise(advertisement(&holder_id, 100)).unwrap();
    let holder_peer = holder.peer_id();
    let middle_peer = middle.peer_id();
    middle.sync_ledger_with(holder_peer);
    fetcher.sync_ledger_with(middle_peer);
    assert!(
        drive3(
            &mut fetcher,
            &mut middle,
            &mut holder,
            Duration::from_secs(25),
            |f| f.capability_ledger().len() == 1
        )
        .await,
        "the fetcher needs the holder's advertisement, which also reaches it second-hand"
    );

    let content = b"held by somebody the fetcher has never spoken to".to_vec();
    let cid = holder.store_chunk(content.clone());
    let _ = drive3(
        &mut middle,
        &mut holder,
        &mut fetcher,
        Duration::from_secs(4),
        |_| false,
    )
    .await;

    // The precondition, asserted rather than assumed: the middle node must not
    // hold the chunk, or this would be the one-hop case again wearing three
    // nodes.
    assert!(
        middle.chunk_store().get(&cid).is_none(),
        "the middle node must not hold the content it is routing to"
    );

    fetcher.find_providers(cid);
    let found = tokio::time::timeout(Duration::from_secs(25), async {
        loop {
            tokio::select! {
                event = fetcher.next_event() => {
                    if let NodeEvent::ProvidersFound { cid: got, providers, .. } = event
                        && got == cid
                    {
                        return providers;
                    }
                }
                _ = middle.next_event() => {}
                _ = holder.next_event() => {}
            }
        }
    })
    .await
    .expect("the lookup should answer");

    assert!(
        found.contains(&holder_id.id()),
        "the DHT should name a holder the fetcher was never given an address for, got {found:?}"
    );

    // And the answer has to be usable, not merely correct: finding a holder is
    // worth nothing if the bytes cannot then be got from it.
    fetcher.fetch_chunks(vec![cid], &fetcher_id, 1);
    let arrived = tokio::time::timeout(Duration::from_secs(40), async {
        loop {
            tokio::select! {
                event = fetcher.next_event() => {
                    if let NodeEvent::FetchComplete { .. } = event {
                        return true;
                    }
                }
                _ = middle.next_event() => {}
                _ = holder.next_event() => {}
            }
        }
    })
    .await
    .unwrap_or(false);

    assert!(arrived, "the fetch should complete");
    assert_eq!(
        fetcher.chunk_store().get(&cid),
        Some(content.as_slice()),
        "the content should arrive intact from a peer discovered through another"
    );
}
