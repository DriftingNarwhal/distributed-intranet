//! A live relay enforces its limits — Core Protocol Spec §5.3, Harness §2.5.
//!
//! # Why this is a named test rather than an incidental one
//!
//! The defect this guards against was found in real prior relay code: a rate
//! limiter that computed a decision and never enforced it. Unit tests over
//! `RelayGuard` cannot catch that, because they exercise the model rather than
//! the relay — the limits were fully unit-tested while a running relay enforced
//! nothing at all.
//!
//! So this drives an actual `RelayNode` and asserts that a reservation past the
//! ceiling is **refused**, not merely logged.

use intranet_identity::{MasterSeed, NetworkId, PerNetworkIdentity};
use intranet_transport::{MemberNode, NodeEvent, RelayLimits, RelayNode};
use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;
use std::time::Duration;

const NETWORK: NetworkId = NetworkId::from_bytes([42u8; 32]);

fn identity(n: u8) -> PerNetworkIdentity {
    MasterSeed::from_entropy([n; 32]).identity_for(&NETWORK).unwrap()
}

fn is_loopback(address: &Multiaddr) -> bool {
    address.iter().any(|part| match part {
        Protocol::Ip4(ip) => ip.is_loopback(),
        Protocol::Ip6(ip) => ip.is_loopback(),
        _ => false,
    })
}

/// Starts a relay on a routable interface with the given limits.
async fn start_relay(limits: RelayLimits) -> (Multiaddr, RelayNode) {
    let relay_identity = identity(1);
    let mut relay = RelayNode::with_limits(&relay_identity, limits).unwrap();
    relay
        .listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap())
        .unwrap();

    let addr = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let NodeEvent::Listening(address) = relay.next_event().await
                && address.iter().any(|p| matches!(p, Protocol::Tcp(_)))
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
async fn a_live_relay_refuses_reservations_past_its_ceiling() {
    // One reservation total, so the second member must be turned away.
    let limits = RelayLimits {
        max_reservations: 1,
        ..RelayLimits::default()
    };
    let (relay_addr, mut relay) = start_relay(limits).await;

    let mut first = MemberNode::new(&identity(2)).unwrap();
    let mut second = MemberNode::new(&identity(3)).unwrap();
    for node in [&mut first, &mut second] {
        node.listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap()).unwrap();
    }

    first.reserve_via_relay(relay_addr.clone()).await.unwrap();
    second.reserve_via_relay(relay_addr.clone()).await.unwrap();

    let mut granted = 0usize;
    let mut denied = 0usize;

    let _ = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            tokio::select! {
                event = relay.next_event() => match event {
                    NodeEvent::ReservationGranted { .. } => {
                        granted += 1;
                    }
                    NodeEvent::ReservationDenied { .. } => {
                        denied += 1;
                        return;
                    }
                    _ => {}
                },
                _ = first.next_event() => {}
                _ = second.next_event() => {}
            }
        }
    })
    .await;

    assert_eq!(
        granted, 1,
        "exactly one reservation should have been granted under a ceiling of 1"
    );
    assert_eq!(
        denied, 1,
        "the second reservation must be genuinely refused, not merely logged — \
         this is the defect class §2.5 names, a limiter that decides and does nothing"
    );
    assert_eq!(relay.reservation_count(), 1);
}

#[tokio::test]
async fn a_relay_grants_within_its_ceiling() {
    // The control: with room, the same two members both get reservations, so
    // the test above is measuring the limit rather than a broken relay.
    let (relay_addr, mut relay) = start_relay(RelayLimits::default()).await;

    let mut first = MemberNode::new(&identity(2)).unwrap();
    let mut second = MemberNode::new(&identity(3)).unwrap();
    for node in [&mut first, &mut second] {
        node.listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap()).unwrap();
    }

    first.reserve_via_relay(relay_addr.clone()).await.unwrap();
    second.reserve_via_relay(relay_addr.clone()).await.unwrap();

    let mut granted = 0usize;
    let _ = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            tokio::select! {
                event = relay.next_event() => {
                    if let NodeEvent::ReservationGranted { .. } = event {
                        granted += 1;
                        if granted == 2 {
                            return;
                        }
                    }
                }
                _ = first.next_event() => {}
                _ = second.next_event() => {}
            }
        }
    })
    .await;

    assert_eq!(granted, 2, "both members should reserve when there is room");
    assert_eq!(relay.reservation_count(), 2);
}

#[tokio::test]
async fn configured_limits_reach_the_running_relay() {
    // Guards the wiring itself: a relay built with specific limits should report
    // them, so a future refactor cannot silently drop the configuration on the
    // floor and leave the ceilings back at libp2p's defaults.
    let limits = RelayLimits {
        max_reservations: 7,
        max_circuits: 3,
        ..RelayLimits::default()
    };
    let (_, relay) = start_relay(limits).await;

    assert_eq!(relay.limits().max_reservations, 7);
    assert_eq!(relay.limits().max_circuits, 3);
    assert_eq!(relay.reservation_count(), 0);
}
