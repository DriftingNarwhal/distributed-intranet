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

fn is_circuit(address: &Multiaddr) -> bool {
    address.iter().any(|part| matches!(part, Protocol::P2pCircuit))
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

/// Opens a relayed connection to a target and reports what happened to it.
///
/// Returns `(established, closed_without_upgrade)`.
///
/// The target deliberately does **not** listen on a direct address. Both peers
/// need a reservation for a circuit dial to work at all, and on loopback that is
/// everything DCUtR needs to upgrade — after which the relayed connection closes
/// because it was replaced, not because the relay cut it off. Those two are
/// indistinguishable from the outside, so a test that allowed the upgrade would
/// claim enforcement it never observed. With no direct address to punch to, the
/// circuit is the only path and its fate is attributable to the relay.
async fn circuit_lifetime(limits: RelayLimits, hold: Duration) -> (bool, bool) {
    let (relay_addr, mut relay) = start_relay(limits).await;

    let target_identity = identity(2);
    let target_peer = target_identity.peer_id();
    let mut target = MemberNode::new(&target_identity).unwrap();
    let mut dialer = MemberNode::new(&identity(3)).unwrap();
    dialer.listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap()).unwrap();

    target.reserve_via_relay(relay_addr.clone()).await.unwrap();
    dialer.reserve_via_relay(relay_addr.clone()).await.unwrap();

    // Every swarm must be driven together here. `await_reservation` polls only
    // its own node, so waiting on the members one at a time leaves the relay
    // unpolled and it never gets to grant anything — the reservations simply
    // time out and the whole test reduces to "nothing connected", which is a
    // green byte-ceiling test that has observed no ceiling at all.
    let mut target_ready = false;
    let mut dialer_ready = false;
    let granted = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            tokio::select! {
                event = target.next_event() => {
                    if let NodeEvent::Listening(address) = event && is_circuit(&address) {
                        target_ready = true;
                    }
                }
                event = dialer.next_event() => {
                    if let NodeEvent::Listening(address) = event && is_circuit(&address) {
                        dialer_ready = true;
                    }
                }
                _ = relay.next_event() => {}
            }
            if target_ready && dialer_ready {
                return;
            }
        }
    })
    .await;
    assert!(granted.is_ok(), "both peers should hold a reservation before the dial");

    let circuit = relay_addr
        .with(Protocol::P2pCircuit)
        .with(Protocol::P2p(target_peer));
    dialer.dial_candidates([circuit]).unwrap();

    let mut established = false;
    let mut upgraded = false;
    let mut closed = false;
    let _ = tokio::time::timeout(hold, async {
        loop {
            tokio::select! {
                event = dialer.next_event() => match event {
                    NodeEvent::Connected { peer, tier, .. } if peer == target_peer => {
                        established = true;
                        if !tier.relay_in_data_path() {
                            upgraded = true;
                        }
                    }
                    NodeEvent::Disconnected { peer }
                        if peer == target_peer && established && !upgraded =>
                    {
                        closed = true;
                        return;
                    }
                    _ => {}
                },
                _ = target.next_event() => {}
                _ = relay.next_event() => {}
            }
        }
    })
    .await;

    assert!(
        !upgraded,
        "the target has no direct address, so no hole punch should be possible — an \
         upgrade here means these tests cannot attribute a closed circuit to the relay"
    );
    (established, closed)
}

#[tokio::test]
async fn a_live_relay_cuts_a_circuit_off_at_its_duration_ceiling() {
    // The circuit ceilings had exactly the coverage the reservation cap had
    // before `a_live_relay_refuses_reservations_past_its_ceiling` was written:
    // thorough unit tests over `RelayGuard`, and nothing driving a real relay.
    // `conformance.rs` asserts the model closes a circuit and that the numbers
    // survive on the struct — neither would notice a running relay enforcing
    // none of it.
    //
    // This matters more than an ordinary limit. §5.2 says tier 3 is a
    // correctness guarantee and not a path to live on, and §5.3's ceilings are
    // the whole mechanism behind that sentence. Unenforced, tier 3 silently
    // becomes the thing the spec says it must not be.
    let limits = RelayLimits {
        max_circuit_duration_millis: 3_000,
        ..RelayLimits::default()
    };
    let (established, closed) = circuit_lifetime(limits, Duration::from_secs(25)).await;

    assert!(established, "the circuit should open before it is timed out");
    assert!(
        closed,
        "a circuit with a 3s lifetime must be closed by the relay — if it survives, \
         max_circuit_duration is configured and mapped but never enforced, and circuits \
         are held indefinitely against §5.3"
    );
}

#[tokio::test]
async fn a_circuit_within_its_ceilings_stays_open() {
    // The control, without which the test above is not attributable: the same
    // setup under default limits keeps the circuit up, so what that test
    // observes is the ceiling rather than a relay that drops every circuit.
    let (established, closed) =
        circuit_lifetime(RelayLimits::default(), Duration::from_secs(12)).await;

    assert!(established, "a relayed connection should establish under default limits");
    assert!(
        !closed,
        "a circuit well inside its ceilings must not be cut off — if this closes, the \
         test above proves nothing about the limits"
    );
}

#[tokio::test]
async fn a_live_relay_cuts_a_circuit_off_at_its_byte_ceiling() {
    // The companion ceiling. A 128-byte budget is smaller than the Noise
    // handshake, so an enforcing relay either cuts the circuit before it
    // finishes establishing or immediately after — both are enforcement, and
    // which one happens is a libp2p accounting detail not worth pinning.
    //
    // What makes this attributable is `a_circuit_within_its_ceilings_stays_open`
    // above: identical setup, default budget, connection established and held.
    // Without that control this assertion would also pass against a relay that
    // simply never worked.
    let limits = RelayLimits {
        max_circuit_bytes: 128,
        ..RelayLimits::default()
    };
    let (established, closed) = circuit_lifetime(limits, Duration::from_secs(20)).await;

    assert!(
        !established || closed,
        "a circuit given a 128-byte budget must be cut off — a connection that both \
         establishes and survives means the running relay is enforcing no byte ceiling \
         at all, which is what lets tier 3 become a path peers can live on"
    );
}
