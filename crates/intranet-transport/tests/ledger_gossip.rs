//! Capability ledger propagation over libp2p — Core Protocol Spec §4.2, §4.5.
//!
//! # What these exist to prove
//!
//! HRW replica placement (Storage Spec §3.3) and live-stream first-tier
//! assignment (Real-Time Spec §3.3) are deterministic functions over the
//! capability ledger, and both were fully implemented and tested while no node
//! could ever receive an advertisement from another. Their determinism was
//! therefore true of inputs that only ever existed locally.
//!
//! The last test here is the point of the whole layer: two independent nodes
//! computing the *same replica set*, from ledgers each built by gossip rather
//! than by being handed the same fixture.
//!
//! # A determinism caveat worth stating plainly
//!
//! `placement::rank` is deterministic given a candidate set. The candidate set
//! is each node's own cache, which depends on what has propagated and on each
//! node's local staleness judgment — so two nodes agree on placement once their
//! ledgers agree, not before. That is the design working as specified (§4.5
//! calls staleness tolerance local tuning, and Storage §3.4's repair loop exists
//! to correct drift), but it is a weaker claim than "any node can independently
//! recompute the identical replica set" reads as on its own.

use intranet_crypto::Timestamp;
use intranet_governance::{
    Capability, EntryBody, GroupId, LogEntry, MembershipAction, NetworkPolicy,
};
use intranet_identity::{MasterSeed, NetworkId, PerNetworkIdentity};
use intranet_ledger::{
    BandwidthCap, CapabilityAdvertisement, ComputeClass, WeightField, placement,
};
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

/// Admits `who` to `everyone`, which is what makes their advertisement valid.
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

fn advertisement(node: &PerNetworkIdentity, storage: u64, at: i64) -> CapabilityAdvertisement {
    CapabilityAdvertisement::create(
        node,
        storage,
        BandwidthCap {
            up_bytes_per_sec: 1_000_000,
            down_bytes_per_sec: 8_000_000,
            active_window: None,
        },
        true,
        false,
        ComputeClass::Modest,
        Timestamp::from_millis(at),
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

/// Two nodes sharing a governance chain that admits both, on one node only.
///
/// The joiner starts empty, so every test below exercises the real ordering:
/// governance must converge before any advertisement can be validated.
async fn network() -> (MemberNode, MemberNode, Multiaddr) {
    let founder = identity(1);
    let joiner = identity(2);
    let (mut host, _) = node(1).await;
    let (guest, guest_addr) = node(2).await;

    let root = host.append_entry(genesis(&founder)).unwrap();
    host.append_entry(admit(&founder, root, &joiner, 5)).unwrap();

    (host, guest, guest_addr)
}

#[tokio::test]
async fn an_advertisement_reaches_a_peer_that_agrees_it_is_a_member() {
    let (mut host, mut guest, guest_addr) = network().await;
    let founder = identity(1);

    host.advertise(advertisement(&founder, 8 << 30, 100)).unwrap();
    assert_eq!(host.capability_ledger().len(), 1);
    assert_eq!(guest.capability_ledger().len(), 0);

    host.dial_candidates([guest_addr]).unwrap();
    assert!(
        drive(&mut host, &mut guest, Duration::from_secs(20), |_, b| {
            b.capability_ledger().len() == 1
        })
        .await,
        "the advertisement should reach the peer"
    );

    let received = guest
        .capability_ledger()
        .get(&founder.id())
        .expect("the peer should hold the advertisement");
    assert_eq!(received.storage_offered, 8 << 30);
    assert!(received.relay_bootstrap_willing);
}

#[tokio::test]
async fn a_node_with_no_governance_replica_cannot_accept_an_advertisement() {
    // Fail closed, and the deterministic half of the ordering problem below. An
    // advertisement is only valid from a current member, so a node with no
    // replayable governance state has nothing to check membership against and
    // must refuse rather than accept on trust — otherwise the very first thing a
    // fresh node does is populate its placement inputs from unverified claims.
    let (mut fresh, _) = node(3).await;
    let founder = identity(1);

    assert!(fresh.governance_log().is_empty());
    assert!(
        fresh.advertise(advertisement(&founder, 8 << 30, 100)).is_err(),
        "a node that cannot replay its log must not accept advertisements"
    );
    assert_eq!(fresh.capability_ledger().len(), 0);
}

#[tokio::test]
async fn the_ledger_converges_whichever_sync_finishes_first() {
    // Governance sync and ledger sync both fire on connect with no ordering
    // between them, so a fresh peer may be offered advertisements before its log
    // can validate them. Whether that happens on any given run is a genuine race
    // — asserting it always fires would be asserting a scheduling detail — but
    // convergence must hold either way, which is what this pins.
    //
    // The recovery rule is what makes the losing interleaving self-correcting:
    // a governance sync that accepts anything triggers another ledger sync,
    // rather than the ledger staying empty until the next reconnect.
    let (mut host, mut guest, guest_addr) = network().await;
    let founder = identity(1);
    host.advertise(advertisement(&founder, 4 << 30, 100)).unwrap();

    host.dial_candidates([guest_addr]).unwrap();

    let mut rejections = 0;
    let converged = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if guest.capability_ledger().len() == 1 && guest.governance_log().len() == 2 {
                return true;
            }
            tokio::select! {
                _ = host.next_event() => {}
                event = guest.next_event() => {
                    if let NodeEvent::LedgerSynced { rejected, .. } = event {
                        rejections += rejected;
                    }
                }
            }
        }
    })
    .await
    .unwrap_or(false);

    assert!(
        converged,
        "both the log and the ledger must converge regardless of which sync won \
         the race ({rejections} advertisement(s) were rejected before the log caught up)"
    );
}

#[tokio::test]
async fn a_refreshed_advertisement_replaces_the_older_copy() {
    // §4.5's refresh-or-expire pattern. This is what the `(node, issued_at)`
    // digest buys: a digest carrying identity alone would tell a peer it had
    // heard of this node and nothing more, so the ledger would populate once and
    // then freeze, with placement running forever on first-contact capacity.
    let (mut host, mut guest, guest_addr) = network().await;
    let founder = identity(1);

    host.advertise(advertisement(&founder, 1 << 30, 100)).unwrap();
    host.dial_candidates([guest_addr]).unwrap();
    assert!(
        drive(&mut host, &mut guest, Duration::from_secs(20), |_, b| {
            b.capability_ledger().len() == 1
        })
        .await
    );
    assert_eq!(
        guest.capability_ledger().get(&founder.id()).unwrap().storage_offered,
        1 << 30
    );

    // The node re-announces with different capacity.
    host.advertise(advertisement(&founder, 64 << 30, 200)).unwrap();
    let peer = host.peer_id();
    guest.sync_ledger_with(peer);

    assert!(
        drive(&mut host, &mut guest, Duration::from_secs(20), |_, b| {
            b.capability_ledger()
                .get(&identity(1).id())
                .is_some_and(|a| a.storage_offered == 64 << 30)
        })
        .await,
        "a refreshed advertisement should replace the copy already held"
    );
}

#[tokio::test]
async fn an_older_advertisement_does_not_displace_a_newer_one() {
    // Replay protection, end to end. Without it a peer could re-serve a stale
    // advertisement and roll a node's declared capacity backwards — attracting
    // replicas to a node that has since withdrawn the offer, or removing one
    // that has just made it.
    let (mut host, mut guest, guest_addr) = network().await;
    let founder = identity(1);

    host.advertise(advertisement(&founder, 64 << 30, 200)).unwrap();
    host.dial_candidates([guest_addr]).unwrap();
    assert!(
        drive(&mut host, &mut guest, Duration::from_secs(20), |_, b| {
            b.capability_ledger().len() == 1
        })
        .await
    );

    // A genuinely older, genuinely signed advertisement — not a forgery.
    let stale = advertisement(&founder, 1, 100);
    assert!(stale.verify().is_ok());
    guest.advertise(stale).unwrap();

    assert_eq!(
        guest
            .capability_ledger()
            .get(&founder.id())
            .unwrap()
            .storage_offered,
        64 << 30,
        "an older advertisement must be discarded even though it verifies"
    );
}

#[tokio::test]
async fn two_nodes_compute_the_same_replica_set_from_gossiped_ledgers() {
    // The payoff, and the reason the ledger had to be wired before storage.
    // Placement is a pure function over the ledger, so its determinism is only
    // worth anything once two nodes can actually arrive at the same ledger
    // without being handed one. Each node here builds its view by gossip.
    let founder = identity(1);
    let joiner = identity(2);
    let (mut host, mut guest, guest_addr) = network().await;

    // Several advertisers with different declared capacity, so the ranking has
    // something to distinguish. Both are members of the chain the host holds.
    host.advertise(advertisement(&founder, 8 << 30, 100)).unwrap();

    host.dial_candidates([guest_addr]).unwrap();
    assert!(
        drive(&mut host, &mut guest, Duration::from_secs(20), |a, b| {
            a.governance_log().len() == b.governance_log().len()
                && a.capability_ledger().len() == b.capability_ledger().len()
                && b.capability_ledger().len() == 1
        })
        .await,
        "both nodes should converge on the same ledger"
    );

    // The guest can now advertise too, and the host must learn it.
    guest.advertise(advertisement(&joiner, 2 << 30, 150)).unwrap();
    let guest_peer = guest.peer_id();
    host.sync_ledger_with(guest_peer);
    assert!(
        drive(&mut host, &mut guest, Duration::from_secs(20), |a, b| {
            a.capability_ledger().len() == 2 && b.capability_ledger().len() == 2
        })
        .await,
        "the host should learn the guest's advertisement"
    );

    for key in [b"content-a".as_slice(), b"content-b", b"content-c"] {
        let from_host: Vec<_> = placement::select(
            key,
            host.capability_ledger().entries(),
            WeightField::StorageOffered,
            2,
        );
        let from_guest: Vec<_> = placement::select(
            key,
            guest.capability_ledger().entries(),
            WeightField::StorageOffered,
            2,
        );
        assert_eq!(
            from_host, from_guest,
            "two nodes holding the same gossiped ledger must place replicas identically — \
             this is the property HRW was chosen for, and it had no cross-node coverage \
             until advertisements could actually propagate"
        );
        assert_eq!(from_host.len(), 2, "both advertisers should be eligible");
    }
}
