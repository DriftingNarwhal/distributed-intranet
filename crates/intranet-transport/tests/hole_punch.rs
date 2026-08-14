//! DCUtR upgrade over a relay — Core Protocol Spec §5.2 tier 2.
//!
//! # What this isolates
//!
//! In the NAT environment the traversal itself works — a real direct connection
//! is made — but DCUtR reports the upgrade as failed and the connection is torn
//! down. That is a different failure from "the packets cannot get through", and
//! separating the two needs an environment where traversal is guaranteed.
//!
//! Loopback is that environment: both peers are trivially dialable, so anything
//! that fails here is the upgrade path itself rather than connectivity.

use intranet_identity::{MasterSeed, NetworkId, PerNetworkIdentity};
use intranet_transport::{ConnectionTier, MemberNode, NodeEvent, RelayNode};
use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;
use std::time::Duration;

const NETWORK: NetworkId = NetworkId::from_bytes([42u8; 32]);

fn identity(n: u8) -> PerNetworkIdentity {
    MasterSeed::from_entropy([n; 32]).identity_for(&NETWORK).unwrap()
}

fn has_tcp(address: &Multiaddr) -> bool {
    address
        .iter()
        .any(|part| matches!(part, Protocol::Tcp(_)))
}

/// Whether an address is loopback.
fn is_loopback(address: &Multiaddr) -> bool {
    address.iter().any(|part| match part {
        Protocol::Ip4(ip) => ip.is_loopback(),
        Protocol::Ip6(ip) => ip.is_loopback(),
        _ => false,
    })
}

/// Brings up a relay and returns its dialable address.
///
/// Binds a wildcard and takes a **non-loopback** address deliberately.
/// `RelayNode` refuses to advertise loopback as an external address — correct in
/// production, since a relay telling a remote peer to dial 127.0.0.1 is useless
/// — but it means a loopback-only relay hands back reservations with no
/// addresses in them and no client can accept one. Using a routable interface
/// keeps the test faithful to how a relay is actually reached.
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

/// Drives every node, reporting what the dialer observes about the target.
///
/// Returns the tier finally attributed to the target peer, plus whether DCUtR
/// reported a successful upgrade.
async fn attempt_hole_punch() -> (Option<ConnectionTier>, bool, Vec<String>) {
    // Tracks the tier carried by the *connection event* itself, separately from
    // DCUtR's later verdict, so the two can be asserted independently.
    let (relay_addr, mut relay) = start_relay().await;

    let target_identity = identity(2);
    let dialer_identity = identity(3);
    let target_peer = target_identity.peer_id();

    let mut target = MemberNode::new(&target_identity).unwrap();
    let mut dialer = MemberNode::new(&dialer_identity).unwrap();

    // Wildcard binds, as a real node uses — and as the scenarios do.
    target
        .listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap())
        .unwrap();
    dialer
        .listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap())
        .unwrap();

    // Both sides need a reservation: a punch is negotiated between two peers,
    // so both must be reachable through the relay.
    target.reserve_via_relay(relay_addr.clone()).await.unwrap();
    dialer.reserve_via_relay(relay_addr.clone()).await.unwrap();

    // Give the reservations a moment to be granted before dialling the circuit.
    let settle = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < settle {
        tokio::select! {
            _ = relay.next_event() => {}
            _ = target.next_event() => {}
            _ = dialer.next_event() => {}
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    }

    let circuit = relay_addr
        .with(Protocol::P2pCircuit)
        .with(Protocol::P2p(target_peer));
    dialer.dial_candidates([circuit]).unwrap();

    let mut log = Vec::new();
    let mut punched = false;
    let mut tier = None;
    let mut upgraded_on_connect = false;

    let _ = tokio::time::timeout(Duration::from_secs(25), async {
        loop {
            tokio::select! {
                event = dialer.next_event() => match event {
                    NodeEvent::Connected { peer, tier: t, .. } if peer == target_peer => {
                        log.push(format!("dialer connected tier={}", t.label()));
                        tier = Some(t);
                        if t == ConnectionTier::HolePunched {
                            upgraded_on_connect = true;
                        }
                    }
                    NodeEvent::HolePunchSucceeded { peer } if peer == target_peer => {
                        log.push("dialer hole-punch succeeded".into());
                        punched = true;
                        tier = Some(ConnectionTier::HolePunched);
                        return;
                    }
                    NodeEvent::HolePunchFailed { peer } if peer == target_peer => {
                        log.push("dialer hole-punch FAILED".into());
                        return;
                    }
                    NodeEvent::Disconnected { peer } if peer == target_peer => {
                        log.push("dialer disconnected from target".into());
                    }
                    _ => {}
                },
                event = target.next_event() => match event {
                    NodeEvent::HolePunchSucceeded { .. } => {
                        log.push("target hole-punch succeeded".into());
                    }
                    NodeEvent::HolePunchFailed { .. } => {
                        log.push("target hole-punch FAILED".into());
                    }
                    _ => {}
                },
                _ = relay.next_event() => {}
            }
        }
    })
    .await;

    if upgraded_on_connect {
        log.push("upgrade attributed on the connection itself".into());
    }
    (tier, punched, log)
}

#[tokio::test]
async fn dcutr_upgrades_a_relayed_connection_on_loopback() {
    let (tier, punched, log) = attempt_hole_punch().await;

    for line in &log {
        println!("  {line}");
    }

    assert!(
        punched,
        "DCUtR should upgrade a relayed connection to direct when both peers are \
         trivially dialable. Observed tier: {tier:?}. Event log above. If this fails on \
         loopback the problem is the upgrade path itself, not NAT traversal."
    );
    assert_eq!(tier, Some(ConnectionTier::HolePunched));
    assert!(
        log.iter().any(|line| line == "upgrade attributed on the connection itself"),
        "the upgrade must be attributed when the direct connection replaces the relayed \
         one, not only when DCUtR later reports its own dial succeeded — a caller that \
         settles on the first direct connection would otherwise record tier 1 for a \
         genuine tier 2 upgrade, which is exactly how a passing hole punch failed a \
         conformance check"
    );
}

#[tokio::test]
async fn a_direct_connection_with_no_relay_behind_it_is_not_called_an_upgrade() {
    // The negative half of the attribution rule, and the one that keeps tiers 1
    // and 3 honest: the relayed-to-direct transition is what marks an upgrade,
    // so a plain direct connection must stay tier 1 and a relayed connection
    // that never upgrades must stay tier 3 — which is what scenarios 4 and 5
    // assert. Without this, the rule could quietly turn every relayed
    // connection into a reported success.
    let mut listener = MemberNode::new(&identity(4)).unwrap();
    let mut dialer = MemberNode::new(&identity(5)).unwrap();
    let listener_peer = identity(4).peer_id();

    listener
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();

    let addr = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let NodeEvent::Listening(address) = listener.next_event().await
                && has_tcp(&address)
            {
                return address;
            }
        }
    })
    .await
    .expect("listener should listen");

    dialer.dial_candidates([addr]).unwrap();

    let tier = tokio::time::timeout(Duration::from_secs(10), async {
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
    .expect("the nodes should connect");

    assert!(
        matches!(tier, ConnectionTier::Direct(_)),
        "a direct connection with no relayed connection before it is tier 1, not an upgrade"
    );
}
