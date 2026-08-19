//! A node built without peer discovery — Core Protocol Spec §5.1.1.
//!
//! # What this is for
//!
//! The behaviour set a node runs should follow what its network *is*. Kademlia
//! and mDNS answer "who else is out there, and who holds this content", and a
//! pairwise network has no work in that question: two members, and the one that
//! matters is known by construction.
//!
//! It matters because a client runs **one node per network** — the libp2p
//! keypair derives from the per-network identity, so sharing a swarm would share
//! a peer id and correlate identities Core §1.2 keeps unlinkable — and a direct
//! message *is* a network. A user with thirty conversations otherwise runs
//! thirty routing tables and thirty mDNS multicasters for networks that need
//! neither.
//!
//! # What these tests are actually pinning
//!
//! That turning discovery off costs *only* discovery. A node without it must
//! still connect, sync governance, and move content — otherwise the mode is not
//! a leaner node, it is a broken one, and nobody could safely use it.

use intranet_crypto::Timestamp;
use intranet_governance::{
    Capability, EntryBody, GroupId, LogEntry, MembershipAction, NetworkPolicy,
};
use intranet_identity::{MasterSeed, NetworkId, PerNetworkIdentity};
use intranet_storage::Cid;
use intranet_transport::{Discovery, MemberNode, NodeEvent};
use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;
use std::time::Duration;

const NETWORK: NetworkId = NetworkId::from_bytes([42u8; 32]);

fn identity(n: u8) -> PerNetworkIdentity {
    MasterSeed::from_entropy([n; 32])
        .identity_for(&NETWORK)
        .unwrap()
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

fn admit(founder: &PerNetworkIdentity, parent: intranet_crypto::Hash, who: &PerNetworkIdentity) -> LogEntry {
    LogEntry::create(
        founder,
        Some(parent),
        Timestamp::from_millis(5),
        EntryBody::MembershipChange {
            group: GroupId::everyone(),
            identity: who.id(),
            action: MembershipAction::Add { via_invite: None },
        },
    )
}

async fn node(seed: u8, discovery: Discovery) -> (MemberNode, Multiaddr) {
    let identity = identity(seed);
    let mut node = MemberNode::with_discovery(&identity, discovery).unwrap();
    node.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();

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
    .expect("a node without discovery still listens");

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

#[tokio::test]
async fn two_nodes_without_discovery_still_reach_each_other_and_agree() {
    // The load-bearing test. A pairwise network is exactly the case this mode
    // exists for, so if two nodes without discovery cannot connect and converge,
    // the mode is useless however much overhead it saves.
    let founder = identity(1);
    let joiner = identity(2);
    let (mut host, _) = node(1, Discovery::Off).await;
    let (mut guest, guest_addr) = node(2, Discovery::Off).await;

    let root = host.append_entry(genesis(&founder)).unwrap();
    host.append_entry(admit(&founder, root, &joiner)).unwrap();

    // Dialled by address, which is how a pairwise network always works: the peer
    // is known, so there was never a discovery step to lose.
    host.dial_candidates([guest_addr]).unwrap();
    assert!(
        drive(&mut host, &mut guest, Duration::from_secs(20), |a, b| {
            a.governance_log().len() == 2 && b.governance_log().len() == 2
        })
        .await,
        "governance must converge without Kademlia or mDNS"
    );
}

#[tokio::test]
async fn discovery_operations_report_absence_rather_than_pretending() {
    // A provider query on a node with no DHT has no query to run. Returning
    // `None` says so; returning a query id that silently never resolves would be
    // indistinguishable from content that genuinely has no holders — the exact
    // confusion `set_dht_server_mode` exists to prevent elsewhere.
    let (mut lean, _) = node(3, Discovery::Off).await;
    assert!(lean.find_providers(Cid::of(b"anything")).is_none());
    assert!(
        lean.enumerate_collection(intranet_crypto::hash_bytes(b"a-collection"))
            .is_none()
    );

    // And the same calls on a full node do produce a query.
    let (mut full, _) = node(4, Discovery::Full).await;
    assert!(full.find_providers(Cid::of(b"anything")).is_some());
}

#[tokio::test]
async fn announcing_content_without_discovery_is_a_no_op_rather_than_an_error() {
    // Storing and serving content must not depend on being able to announce it.
    // A peer that already knows who holds what asks directly, which is the only
    // way a pairwise network ever worked.
    let (mut lean, _) = node(5, Discovery::Off).await;
    let cid = lean.store_chunk(b"content".to_vec());
    lean.announce_chunk(cid);
    assert_eq!(
        lean.chunk_store().get(&cid).map(<[u8]>::to_vec),
        Some(b"content".to_vec()),
        "the chunk is held and servable whether or not it could be announced"
    );
    lean.set_dht_server_mode(true);
}
