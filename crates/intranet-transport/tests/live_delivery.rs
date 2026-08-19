//! Live delivery over gossipsub — Core §5.1, Chat Application Spec §6.1.
//!
//! # What these are careful about
//!
//! The transport carries these payloads and validates none of them, which is the
//! design rather than a shortcut: it does not know what a payload means, and a
//! half-check would be worse than none because a caller would read it as the
//! check having been done. So these tests pin what the transport *does* promise
//! — the payload arrives byte-identical, on the topic it was published to, only
//! to nodes that subscribed — and pin equally hard that it promises nothing
//! about who sent it.

use intranet_crypto::Timestamp;
use intranet_governance::{
    Capability, EntryBody, GroupId, LogEntry, MembershipAction, NetworkPolicy,
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

async fn node(seed: u8) -> (MemberNode, Multiaddr) {
    let identity = identity(seed);
    let mut node = MemberNode::new(&identity).unwrap();
    node.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap()).unwrap();
    node.set_dht_server_mode(true);

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
    .expect("listens");

    (node, address.with(Protocol::P2p(identity.peer_id())))
}

/// Two connected members, agreeing on governance.
async fn pair() -> (MemberNode, MemberNode) {
    let founder = identity(1);
    let peer = identity(2);
    let (mut a, _) = node(1).await;
    let (mut b, b_addr) = node(2).await;

    let root = a.append_entry(genesis(&founder)).unwrap();
    a.append_entry(admit(&founder, root, &peer)).unwrap();
    a.dial_candidates([b_addr]).unwrap();

    let connected = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            tokio::select! {
                event = a.next_event() => {
                    if matches!(event, NodeEvent::Connected { .. }) { return true; }
                }
                _ = b.next_event() => {}
            }
        }
    })
    .await
    .unwrap_or(false);
    assert!(connected, "the pair must connect before anything is published");

    (a, b)
}

/// Waits for a live payload on `reader`, driving both nodes.
async fn await_live(
    reader: &mut MemberNode,
    other: &mut MemberNode,
    within: Duration,
) -> Option<(String, Vec<u8>)> {
    tokio::time::timeout(within, async {
        loop {
            tokio::select! {
                event = reader.next_event() => {
                    if let NodeEvent::LiveReceived { topic, payload, .. } = event {
                        return (topic, payload);
                    }
                }
                _ = other.next_event() => {}
            }
        }
    })
    .await
    .ok()
}

/// Publishes until a subscriber's mesh has formed, or gives up.
///
/// Gossipsub needs a moment after subscribing before a publisher has anybody to
/// publish *to*, and a single attempt races that. Retrying is what a real client
/// does too, since §6.1 makes a failed publish unremarkable.
async fn publish_until_delivered(
    sender: &mut MemberNode,
    reader: &mut MemberNode,
    topic: &str,
    payload: &[u8],
) -> Option<(String, Vec<u8>)> {
    for _ in 0..40 {
        let _ = sender.publish_live(topic, payload.to_vec());
        if let Some(got) = await_live(reader, sender, Duration::from_millis(500)).await {
            return Some(got);
        }
    }
    None
}

#[tokio::test]
async fn a_payload_reaches_a_subscriber_byte_identical() {
    let (mut a, mut b) = pair().await;
    let topic = "intranet.test.live.v1";
    b.subscribe_live(topic).unwrap();
    a.subscribe_live(topic).unwrap();

    // Deliberately not a valid anything: the transport carries opaque bytes and
    // must not acquire an opinion about their shape.
    let payload = b"\x00\xff opaque bytes, meaning known only to the consumer".to_vec();

    let (got_topic, got) = publish_until_delivered(&mut a, &mut b, topic, &payload)
        .await
        .expect("a subscriber should receive what was published");

    assert_eq!(got_topic, topic, "delivered on the topic it was published to");
    assert_eq!(got, payload, "and byte-identical, with nothing added or framed");
}

#[tokio::test]
async fn a_node_that_did_not_subscribe_hears_nothing() {
    // Subscription is per topic and on demand precisely so a member of a
    // four-hundred-channel network carries a handful of meshes rather than four
    // hundred. A node receiving traffic for topics it never asked for would make
    // that saving imaginary.
    let (mut a, mut b) = pair().await;
    a.subscribe_live("intranet.test.subscribed.v1").unwrap();
    b.subscribe_live("intranet.test.subscribed.v1").unwrap();

    // Warm the mesh on a topic they share, so a silent result below cannot be
    // mistaken for the two never having connected at all.
    assert!(
        publish_until_delivered(&mut a, &mut b, "intranet.test.subscribed.v1", b"control")
            .await
            .is_some(),
        "precondition: delivery works on a topic both subscribed to"
    );

    let _ = a.publish_live("intranet.test.unsubscribed.v1", b"unheard".to_vec());
    let heard = await_live(&mut b, &mut a, Duration::from_secs(3)).await;
    assert!(
        heard.is_none_or(|(topic, _)| topic != "intranet.test.unsubscribed.v1"),
        "a node must not receive a topic it never subscribed to"
    );
}

#[tokio::test]
async fn unsubscribing_stops_delivery() {
    let (mut a, mut b) = pair().await;
    let topic = "intranet.test.leaving.v1";
    a.subscribe_live(topic).unwrap();
    b.subscribe_live(topic).unwrap();

    assert!(
        publish_until_delivered(&mut a, &mut b, topic, b"while subscribed")
            .await
            .is_some(),
        "precondition: delivery works while subscribed"
    );
    assert!(b.live_topics().iter().any(|held| held == topic));

    assert!(b.unsubscribe_live(topic), "unsubscribing reports the change");
    assert!(
        !b.live_topics().iter().any(|held| held == topic),
        "and the topic is no longer carried"
    );

    let _ = a.publish_live(topic, b"after leaving".to_vec());
    let heard = await_live(&mut b, &mut a, Duration::from_secs(3)).await;
    assert!(
        heard.is_none_or(|(_, payload)| payload != b"after leaving"),
        "a node that left a topic must stop receiving it"
    );
}

#[tokio::test]
async fn publishing_with_nobody_listening_is_not_a_failure_worth_reporting() {
    // §6.1: nothing may depend on this path. A quiet channel with no subscriber
    // is the ordinary state, not an error — a client that surfaced it would be
    // reporting a problem that does not exist, and the record reaches everybody
    // through the durable path regardless.
    let (mut a, _b) = pair().await;
    a.subscribe_live("intranet.test.lonely.v1").unwrap();

    // Whether this returns Ok or Err is not the point; that it does not panic
    // and leaves the node usable is.
    let _ = a.publish_live("intranet.test.lonely.v1", b"into the void".to_vec());
    assert!(a.live_topics().iter().any(|t| t == "intranet.test.lonely.v1"));
}
