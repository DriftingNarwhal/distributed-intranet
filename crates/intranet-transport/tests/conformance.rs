//! Transport conformance tests — Core Protocol Spec §5, Reference Test Harness Spec §2.
//!
//! The NAT-topology scenarios (§2.3) need the Docker environment and live in
//! `harness/`. What runs here is everything provable in-process: relay resource
//! enforcement (§2.5), transport-layer unlinkability, and a real two-node
//! connection asserting the tier it succeeded at.

use intranet_crypto::{Timestamp, hash_bytes};
use intranet_identity::{MasterSeed, NetworkId, PerNetworkIdentity};
use intranet_transport::{
    AddressFamily, ConnectionTier, MemberNode, NodeEvent, RelayGuard, RelayLimits, RelayNode,
    Requester, TransportHandle, relay_limits::RelayDenied,
};

const NETWORK: NetworkId = NetworkId::from_bytes([42u8; 32]);

fn identity(n: u8) -> PerNetworkIdentity {
    MasterSeed::from_entropy([n; 32]).identity_for(&NETWORK).unwrap()
}

fn at(millis: i64) -> Timestamp {
    Timestamp::from_millis(millis)
}

// ---------------------------------------------------------------------------
// Relay resource limits (§5.3, Harness §2.5)
// ---------------------------------------------------------------------------

#[test]
fn regenerating_a_transport_handle_does_not_reset_the_limit() {
    // The named regression: a peer ID is free to regenerate, so a peer-ID-keyed
    // limit is not protection. Here one identity presents four *different*
    // transport handles and still hits its per-identity ceiling, because the
    // handle is not part of the key.
    let mut guard = RelayGuard::new(RelayLimits {
        max_reservations_per_identity: 2,
        ..RelayLimits::default()
    });
    let requester = Requester::Admitted(identity(1).id());

    assert!(guard.try_reserve(requester.clone(), TransportHandle(1), at(0)).is_ok());
    assert!(guard.try_reserve(requester.clone(), TransportHandle(2), at(0)).is_ok());

    // A fresh handle each time — as a client cycling peer IDs would produce.
    for handle in 3..10 {
        assert!(
            matches!(
                guard.try_reserve(requester.clone(), TransportHandle(handle), at(0)),
                Err(RelayDenied::IdentityCeiling { .. })
            ),
            "handle {handle} must not bypass a limit keyed on identity"
        );
    }
    assert_eq!(guard.reservation_count(), 2);
}

#[test]
fn distinct_identities_are_metered_separately() {
    let mut guard = RelayGuard::new(RelayLimits {
        max_reservations_per_identity: 1,
        ..RelayLimits::default()
    });

    assert!(
        guard
            .try_reserve(Requester::Admitted(identity(1).id()), TransportHandle(1), at(0))
            .is_ok()
    );
    assert!(
        guard
            .try_reserve(Requester::Admitted(identity(2).id()), TransportHandle(2), at(0))
            .is_ok(),
        "one identity's ceiling must not deny an unrelated identity"
    );
}

#[test]
fn the_global_reservation_ceiling_is_enforced() {
    let mut guard = RelayGuard::new(RelayLimits {
        max_reservations: 3,
        max_reservations_per_identity: 10,
        ..RelayLimits::default()
    });

    for i in 0..3 {
        assert!(
            guard
                .try_reserve(Requester::Admitted(identity(i).id()), TransportHandle(i as u64), at(0))
                .is_ok()
        );
    }
    assert!(matches!(
        guard.try_reserve(Requester::Admitted(identity(9).id()), TransportHandle(9), at(0)),
        Err(RelayDenied::ReservationCeiling { limit: 3 })
    ));
}

#[test]
fn many_pre_admission_identities_off_one_invite_are_caught_per_invite() {
    // The gap the per-identity argument leaves open: under a bearer invite an
    // attacker mints waiting-room identities freely, each technically distinct,
    // none having paid the admission cost the per-identity limit relies on. The
    // invite is the scarce resource, so it is what gets metered.
    let mut guard = RelayGuard::new(RelayLimits {
        max_reservations_per_identity: 4,
        max_reservations_per_invite: 3,
        ..RelayLimits::default()
    });
    let invite = hash_bytes(b"one-bearer-invite");

    for i in 0..3 {
        let requester = Requester::PreAdmission {
            identity: identity(i).id(),
            invite,
        };
        assert!(
            guard.try_reserve(requester, TransportHandle(i as u64), at(0)).is_ok(),
            "genuine joiners under one invite must still get through"
        );
    }

    for i in 3..12 {
        let requester = Requester::PreAdmission {
            identity: identity(i).id(),
            invite,
        };
        assert!(
            matches!(
                guard.try_reserve(requester, TransportHandle(i as u64), at(0)),
                Err(RelayDenied::InviteCeiling { .. })
            ),
            "freshly-minted identity {i} must not buy another reservation"
        );
    }
    assert_eq!(guard.reservations_for_invite(&invite), 3);
}

#[test]
fn pre_admission_metering_is_per_invite_not_global() {
    let mut guard = RelayGuard::new(RelayLimits {
        max_reservations_per_invite: 1,
        ..RelayLimits::default()
    });

    assert!(
        guard
            .try_reserve(
                Requester::PreAdmission {
                    identity: identity(1).id(),
                    invite: hash_bytes(b"invite-a"),
                },
                TransportHandle(1),
                at(0)
            )
            .is_ok()
    );
    assert!(
        guard
            .try_reserve(
                Requester::PreAdmission {
                    identity: identity(2).id(),
                    invite: hash_bytes(b"invite-b"),
                },
                TransportHandle(2),
                at(0)
            )
            .is_ok(),
        "a separately-issued invite is a separate scarce resource"
    );
}

#[test]
fn an_admitted_identity_is_not_subject_to_invite_metering() {
    let mut guard = RelayGuard::new(RelayLimits {
        max_reservations_per_invite: 1,
        max_reservations_per_identity: 4,
        ..RelayLimits::default()
    });

    // Once admission is complete, the identity itself is the costly thing
    // again, so the tight per-invite ceiling must not apply to it.
    let admitted = identity(1).id();
    let requester = Requester::Admitted(admitted);
    for handle in 0..4 {
        assert!(
            guard.try_reserve(requester.clone(), TransportHandle(handle), at(0)).is_ok(),
            "an admitted identity is metered per-identity, not per-invite"
        );
    }
    assert_eq!(guard.reservations_for(&admitted), 4);
}

#[test]
fn a_circuit_cannot_be_opened_without_a_reservation() {
    // Structural enforcement: there is no way to reach a circuit except through
    // a reservation this guard issued.
    let mut guard = RelayGuard::new(RelayLimits::default());
    let reservation = guard
        .try_reserve(Requester::Admitted(identity(1).id()), TransportHandle(1), at(0))
        .unwrap();

    assert!(guard.open_circuit(reservation, at(0)).is_ok());

    guard.release(reservation);
    assert!(matches!(
        guard.open_circuit(reservation, at(0)),
        Err(RelayDenied::NoReservation)
    ));
}

#[test]
fn releasing_a_reservation_closes_its_circuits() {
    let mut guard = RelayGuard::new(RelayLimits::default());
    let reservation = guard
        .try_reserve(Requester::Admitted(identity(1).id()), TransportHandle(1), at(0))
        .unwrap();
    guard.open_circuit(reservation, at(0)).unwrap();
    guard.open_circuit(reservation, at(0)).unwrap();
    assert_eq!(guard.circuit_count(), 2);

    guard.release(reservation);
    assert_eq!(
        guard.circuit_count(),
        0,
        "circuits must not outlive the reservation that authorized them"
    );
}

#[test]
fn the_byte_ceiling_actually_closes_the_circuit() {
    // Not "reports that a threshold was passed" — closes it. A caller that
    // ignores the return value still cannot keep using the circuit.
    let mut guard = RelayGuard::new(RelayLimits {
        max_circuit_bytes: 1_000,
        ..RelayLimits::default()
    });
    let reservation = guard
        .try_reserve(Requester::Admitted(identity(1).id()), TransportHandle(1), at(0))
        .unwrap();
    let circuit = guard.open_circuit(reservation, at(0)).unwrap();

    assert_eq!(guard.record_bytes(circuit, 900).unwrap(), None);
    assert_eq!(guard.circuit_count(), 1);

    let closure = guard.record_bytes(circuit, 200).unwrap();
    assert!(closure.is_some(), "exceeding the ceiling must close the circuit");
    assert_eq!(guard.circuit_count(), 0);
    assert!(
        matches!(guard.record_bytes(circuit, 1), Err(RelayDenied::NoCircuit)),
        "a closed circuit must be genuinely gone, not merely flagged"
    );
}

#[test]
fn circuits_are_expired_at_their_maximum_duration() {
    let mut guard = RelayGuard::new(RelayLimits {
        max_circuit_duration_millis: 120_000,
        ..RelayLimits::default()
    });
    let reservation = guard
        .try_reserve(Requester::Admitted(identity(1).id()), TransportHandle(1), at(0))
        .unwrap();
    let circuit = guard.open_circuit(reservation, at(0)).unwrap();

    assert!(guard.expire(at(120_000)).is_empty(), "not yet past the limit");
    assert_eq!(guard.circuit_count(), 1);

    let expired = guard.expire(at(120_001));
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].0, circuit);
    assert_eq!(guard.circuit_count(), 0);
}

#[test]
fn the_circuit_ceiling_is_enforced() {
    let mut guard = RelayGuard::new(RelayLimits {
        max_circuits: 2,
        ..RelayLimits::default()
    });
    let reservation = guard
        .try_reserve(Requester::Admitted(identity(1).id()), TransportHandle(1), at(0))
        .unwrap();

    guard.open_circuit(reservation, at(0)).unwrap();
    guard.open_circuit(reservation, at(0)).unwrap();
    assert!(matches!(
        guard.open_circuit(reservation, at(0)),
        Err(RelayDenied::CircuitCeiling { limit: 2 })
    ));
}

#[test]
fn default_limits_match_the_spec_baselines() {
    let limits = RelayLimits::default();
    assert_eq!(limits.max_reservations, 128);
    assert_eq!(limits.max_reservations_per_identity, 4);
    assert_eq!(limits.max_circuits, 32);
    // Lowered from 120s/8MB on 2026-08-22 along with §5.3 itself. Those came
    // from an implementation predating §5.2's prohibition and were loose enough
    // that a client relaying a whole conversation never met a ceiling — so the
    // rule held only by clients choosing to obey it. A circuit now lives for a
    // negotiation.
    assert_eq!(limits.max_circuit_duration_millis, 60_000);
    assert_eq!(limits.max_circuit_bytes, 256 * 1024);
}

// ---------------------------------------------------------------------------
// Transport-layer unlinkability (§1.2)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_node_presents_a_different_peer_id_in_each_network() {
    // Key-level unlinkability is void if the transport reuses one fingerprint,
    // so this is a hard requirement rather than a nicety.
    let seed = MasterSeed::from_entropy([7u8; 32]);
    let here = seed.identity_for(&NetworkId::from_bytes([1u8; 32])).unwrap();
    let there = seed.identity_for(&NetworkId::from_bytes([2u8; 32])).unwrap();

    let here_node = MemberNode::new(&here).unwrap();
    let there_node = MemberNode::new(&there).unwrap();

    assert_ne!(here_node.peer_id(), there_node.peer_id());
    assert_eq!(
        here_node.peer_id(),
        here.peer_id(),
        "the swarm's PeerId must be the identity's PeerId, not a separate one"
    );
}

#[tokio::test]
async fn the_same_identity_always_yields_the_same_peer_id() {
    let a = MemberNode::new(&identity(3)).unwrap();
    let b = MemberNode::new(&identity(3)).unwrap();
    assert_eq!(a.peer_id(), b.peer_id());
}

// ---------------------------------------------------------------------------
// Real connections (§5.2 tier 1; tiers 2 and 3 need the Docker environment)
// ---------------------------------------------------------------------------

/// Collects a node's listen addresses, driving its event loop until it has some.
async fn listen_addresses(node: &mut MemberNode) -> Vec<libp2p::Multiaddr> {
    let mut addresses = Vec::new();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(std::time::Duration::from_millis(300), node.next_event()).await {
            Ok(NodeEvent::Listening(address)) => addresses.push(address),
            Ok(_) => {}
            Err(_) if !addresses.is_empty() => break,
            Err(_) => {}
        }
    }
    addresses
}

#[tokio::test]
async fn two_nodes_connect_directly_and_the_tier_is_recorded() {
    let mut listener = MemberNode::new(&identity(1)).unwrap();
    let mut dialer = MemberNode::new(&identity(2)).unwrap();
    let listener_peer = listener.peer_id();
    let dialer_peer = dialer.peer_id();

    // Loopback only: this test is about tier classification, not NAT traversal.
    listener
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    listener
        .listen_on("/ip6/::1/tcp/0".parse().unwrap())
        .unwrap();

    let addresses = listen_addresses(&mut listener).await;
    assert!(!addresses.is_empty(), "listener must report listen addresses");

    dialer.dial_candidates(addresses).unwrap();

    let connected = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = dialer.next_event() => {
                    if let NodeEvent::Connected { peer, tier, .. } = event
                        && peer == listener_peer
                    {
                        return tier;
                    }
                }
                event = listener.next_event() => {
                    if let NodeEvent::Connected { peer, .. } = event {
                        assert_eq!(peer, dialer_peer);
                    }
                }
            }
        }
    })
    .await
    .expect("nodes should connect over loopback");

    // Tier 1, and specifically not the relay fallback — the distinction the
    // harness exists to catch, since a relayed connection also "works".
    assert!(
        matches!(connected, ConnectionTier::Direct(_)),
        "expected a direct connection, got {}",
        connected.label()
    );
    assert!(!connected.relay_in_data_path());
    assert_eq!(dialer.tier_for(&listener_peer), Some(connected));
}

#[tokio::test]
async fn ipv6_is_attempted_before_ipv4() {
    // §5.2 tier 1 ordering. Both loopback families are offered; the dialer must
    // reach the peer over IPv6.
    let mut listener = MemberNode::new(&identity(4)).unwrap();
    let mut dialer = MemberNode::new(&identity(5)).unwrap();
    let listener_peer = listener.peer_id();

    listener
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    listener
        .listen_on("/ip6/::1/tcp/0".parse().unwrap())
        .unwrap();

    let addresses = listen_addresses(&mut listener).await;
    let has_v6 = addresses
        .iter()
        .any(|a| intranet_transport::dial::family_of(a) == Some(AddressFamily::Ipv6));
    if !has_v6 {
        eprintln!("skipping: no IPv6 loopback listener available in this environment");
        return;
    }

    dialer.dial_candidates(addresses).unwrap();

    let tier = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = dialer.next_event() => {
                    if let NodeEvent::Connected { peer, tier, .. } = event
                        && peer == listener_peer
                    {
                        return tier;
                    }
                }
                _ = listener.next_event() => {}
            }
        }
    })
    .await
    .expect("nodes should connect");

    assert_eq!(
        tier,
        ConnectionTier::Direct(AddressFamily::Ipv6),
        "IPv6 must be preferred when both families are available"
    );
}

#[tokio::test]
async fn a_relay_node_listens_and_reports_a_verifiable_peer_id() {
    // §5.4: a relay should expose its peer ID out-of-band so a client adding it
    // as a bootstrap candidate can confirm it is reaching the intended relay
    // rather than an impersonator.
    let relay_identity = identity(6);
    let mut relay = RelayNode::new(&relay_identity).unwrap();

    assert_eq!(relay.peer_id(), relay_identity.peer_id());

    relay
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();

    let listening = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let NodeEvent::Listening(address) = relay.next_event().await {
                return address;
            }
        }
    })
    .await
    .expect("relay should begin listening");

    assert!(listening.to_string().contains("/tcp/"));
}
