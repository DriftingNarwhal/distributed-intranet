//! A relayed circuit carries the DCUtR negotiation and nothing else — Core
//! Protocol Spec §5.2.
//!
//! # Why the deadline was not enough
//!
//! `circuit_deadline.rs` proves an un-upgraded circuit is *closed*. Until then it
//! is open, and every protocol a node speaks would use it: libp2p hands a
//! request or a gossip message to whatever connection a peer has, and a peer
//! reachable only through a relay has exactly one. So for up to the deadline,
//! and again after every redial, the circuit carried direct messages, live
//! gossip, the join handshake and sync — §5.2's "no protocol or application
//! payload of any kind", broken by default rather than by any caller.
//!
//! Found by ko-ls running two installations across the NAT matrix: a pair whose
//! punch failed exchanged every message over the relay, delivered in bursts as
//! the circuit was closed and redialled.
//!
//! # What this pins
//!
//! The same shape as `circuit_deadline.rs` — the target has no direct address,
//! so the circuit is its only connection and no upgrade can happen — with the
//! deadline raised well past the test, so the circuit is open throughout. Over
//! it, a direct message must not be delivered, and live gossip must not arrive.

use intranet_identity::{MasterSeed, NetworkId, PerNetworkIdentity};
use intranet_transport::{ConnectionTier, MemberNode, NodeEvent, RelayNode};
use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;
use std::time::Duration;

const NETWORK: NetworkId = NetworkId::from_bytes([42u8; 32]);
const TOPIC: &str = "intranet.test.circuit.v1";

fn identity(n: u8) -> PerNetworkIdentity {
    MasterSeed::from_entropy([n; 32])
        .identity_for(&NETWORK)
        .unwrap()
}

fn has_tcp(address: &Multiaddr) -> bool {
    address.iter().any(|part| matches!(part, Protocol::Tcp(_)))
}

fn is_loopback(address: &Multiaddr) -> bool {
    address.iter().any(|part| match part {
        Protocol::Ip4(ip) => ip.is_loopback(),
        Protocol::Ip6(ip) => ip.is_loopback(),
        _ => false,
    })
}

async fn start_relay() -> (Multiaddr, RelayNode) {
    let relay_identity = identity(1);
    let mut relay = RelayNode::new(&relay_identity).unwrap();
    relay
        .listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap())
        .unwrap();
    let addr = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let NodeEvent::Listening(address) = relay.next_event().await
                && has_tcp(&address)
                && !is_loopback(&address)
            {
                return address;
            }
        }
    })
    .await
    .expect("relay should listen on a routable address");
    (addr.with(Protocol::P2p(relay_identity.peer_id())), relay)
}

#[tokio::test]
async fn nothing_but_the_negotiation_crosses_a_circuit() {
    let (relay_addr, mut relay) = start_relay().await;

    let target_identity = identity(6);
    let dialer_identity = identity(7);
    let target_peer = target_identity.peer_id();

    let mut target = MemberNode::new(&target_identity).unwrap();
    let mut dialer = MemberNode::new(&dialer_identity).unwrap();
    dialer
        .listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap())
        .unwrap();
    // Open for the whole test: what is under test is what the circuit carries
    // while it exists, not that it is eventually closed.
    dialer.set_circuit_upgrade_deadline(Duration::from_secs(120));
    target.set_circuit_upgrade_deadline(Duration::from_secs(120));
    target.handle_direct("test", "note");
    target.subscribe_live(TOPIC).unwrap();
    dialer.subscribe_live(TOPIC).unwrap();

    target.reserve_via_relay(relay_addr.clone()).await.unwrap();
    dialer.reserve_via_relay(relay_addr.clone()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut granted = false;
        while !granted {
            tokio::select! {
                event = target.next_event() => {
                    if let NodeEvent::Listening(address) = event
                        && address.iter().any(|p| matches!(p, Protocol::P2pCircuit))
                    {
                        granted = true;
                    }
                }
                _ = dialer.next_event() => {}
                _ = relay.next_event() => {}
            }
        }
    })
    .await
    .expect("the target's reservation should be granted");

    let circuit: Multiaddr = format!("{relay_addr}/p2p-circuit/p2p/{target_peer}")
        .parse()
        .unwrap();
    dialer.dial_candidates(vec![circuit]).unwrap();

    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let event = tokio::select! {
                event = dialer.next_event() => event,
                _ = target.next_event() => continue,
                _ = relay.next_event() => continue,
            };
            if let NodeEvent::Connected { peer, tier, .. } = event
                && peer == target_peer
            {
                assert_eq!(tier, ConnectionTier::Relayed);
                return;
            }
        }
    })
    .await
    .expect("the circuit should open, or this asserts nothing");

    // Let DCUtR's own attempts finish first. Each is a dial to the target that
    // fails, and a failed dial also fails any request waiting on that peer — so
    // a send made while they run would fail promptly with or without the rule
    // under test, and the timing below would prove nothing.
    let settle = tokio::time::sleep(Duration::from_secs(10));
    tokio::pin!(settle);
    loop {
        tokio::select! {
            () = &mut settle => break,
            _ = dialer.next_event() => {}
            _ = target.next_event() => {}
            _ = relay.next_event() => {}
        }
    }

    let sent = tokio::time::Instant::now();
    dialer
        .send_direct(
            target_identity.id(),
            &dialer_identity,
            "test",
            "note",
            b"over a relay".to_vec(),
        )
        .unwrap();

    // Long enough for a gossip mesh to form and a request to round-trip many
    // times over on loopback; publishing is repeated because a mesh that has
    // not formed yet would otherwise make an absence prove nothing.
    let mut send_failed = None;
    let mut publish = tokio::time::interval(Duration::from_millis(500));
    let watch = tokio::time::sleep(Duration::from_secs(8));
    tokio::pin!(watch);
    loop {
        tokio::select! {
            () = &mut watch => break,
            _ = publish.tick() => {
                let _ = dialer.publish_live(TOPIC, b"live over a relay".to_vec());
            }
            event = target.next_event() => match event {
                NodeEvent::DirectReceived { .. } => {
                    panic!("a direct message crossed the circuit, which \u{a7}5.2 forbids")
                }
                NodeEvent::LiveReceived { .. } => {
                    panic!("live gossip crossed the circuit, which \u{a7}5.2 forbids")
                }
                _ => {}
            },
            event = dialer.next_event() => {
                if let NodeEvent::DirectFailed { .. } = event {
                    send_failed.get_or_insert(sent.elapsed());
                }
                if let NodeEvent::DirectDelivered { .. } = event {
                    panic!("a direct message was acknowledged over the circuit")
                }
            }
            _ = relay.next_event() => {}
        }
    }

    // **Promptly, and that is the point of asserting a time.** Left to libp2p a
    // request to a peer with only a circuit is neither sent nor failed: the
    // swarm declines the dial as already connected, request-response ignores
    // that refusal, and the request waits until some later dial fails or a
    // punch lands. A failure that turned up seconds later would be that later
    // dial — DCUtR's, here — and would pass for the wrong reason.
    let failed_after = send_failed.expect(
        "a send with no permitted path must fail, so a caller can retry once one exists \
         rather than wait on an answer that cannot come",
    );
    assert!(
        failed_after < Duration::from_secs(1),
        "the send failed only after {failed_after:?}, which is some later dial failing \
         rather than the send being refused"
    );
    assert_eq!(
        dialer.tier_for(&target_peer),
        Some(ConnectionTier::Relayed),
        "the circuit must still have been open, or the absences above prove nothing"
    );
}

/// The other half: once the punch lands, everything flows — over the new
/// direct connection, which is announced to each protocol as the peer's first.
///
/// That word matters. A protocol is told how many *other* connections a peer
/// has, and gossipsub sends its subscriptions only on the first. Counted with
/// the circuit included, the direct connection would be the second, nobody's
/// subscriptions would be exchanged, and live delivery would silently never
/// start between two members who had punched successfully.
#[tokio::test]
async fn after_a_punch_everything_flows() {
    let (relay_addr, mut relay) = start_relay().await;

    let target_identity = identity(8);
    let dialer_identity = identity(9);
    let target_peer = target_identity.peer_id();

    let mut target = MemberNode::new(&target_identity).unwrap();
    let mut dialer = MemberNode::new(&dialer_identity).unwrap();
    // Both dialable, so the punch succeeds on loopback.
    target
        .listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap())
        .unwrap();
    dialer
        .listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap())
        .unwrap();
    target.handle_direct("test", "note");
    target.subscribe_live(TOPIC).unwrap();
    dialer.subscribe_live(TOPIC).unwrap();

    target.reserve_via_relay(relay_addr.clone()).await.unwrap();
    dialer.reserve_via_relay(relay_addr.clone()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut granted = false;
        while !granted {
            tokio::select! {
                event = target.next_event() => {
                    if let NodeEvent::Listening(address) = event
                        && address.iter().any(|p| matches!(p, Protocol::P2pCircuit))
                    {
                        granted = true;
                    }
                }
                _ = dialer.next_event() => {}
                _ = relay.next_event() => {}
            }
        }
    })
    .await
    .expect("the target's reservation should be granted");

    let circuit = relay_addr
        .with(Protocol::P2pCircuit)
        .with(Protocol::P2p(target_peer));
    dialer.dial_candidates([circuit]).unwrap();

    tokio::time::timeout(Duration::from_secs(25), async {
        loop {
            let event = tokio::select! {
                event = dialer.next_event() => event,
                _ = target.next_event() => continue,
                _ = relay.next_event() => continue,
            };
            if let NodeEvent::Connected { peer, tier, .. } = event
                && peer == target_peer
                && tier == ConnectionTier::HolePunched
            {
                return;
            }
        }
    })
    .await
    .expect("the punch should land on loopback, or this asserts nothing");

    dialer
        .send_direct(
            target_identity.id(),
            &dialer_identity,
            "test",
            "note",
            b"direct now".to_vec(),
        )
        .unwrap();

    let (mut direct, mut live) = (false, false);
    let mut publish = tokio::time::interval(Duration::from_millis(300));
    tokio::time::timeout(Duration::from_secs(15), async {
        while !(direct && live) {
            tokio::select! {
                _ = publish.tick() => {
                    let _ = dialer.publish_live(TOPIC, b"live now".to_vec());
                }
                event = target.next_event() => match event {
                    NodeEvent::DirectReceived { .. } => direct = true,
                    NodeEvent::LiveReceived { .. } => live = true,
                    _ => {}
                },
                _ = dialer.next_event() => {}
                _ = relay.next_event() => {}
            }
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "after the upgrade, direct delivered: {direct}, live delivered: {live} \u{2014} \
             both must flow once a permitted connection exists"
        )
    });
}
