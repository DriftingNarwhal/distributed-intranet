//! Does the *reservation* connection reuse the listening port? — Core Protocol Spec §5.2.
//!
//! # Why this is a separate question
//!
//! `port_reuse.rs` establishes that ordinary outbound dials originate from the
//! listening port. The connection that matters for hole-punching is not an
//! ordinary dial though: it is opened as a side effect of *listening* on a
//! circuit address to obtain a relay reservation.
//!
//! That connection is the one a relay observes, and its observed address is what
//! DCUtR hands to the remote peer to dial. If this particular connection uses an
//! ephemeral source port while everything else reuses the listener, the observed
//! address points at a port with nothing behind it and a hole punch cannot
//! succeed — while every other form of connectivity keeps working, which is
//! precisely the shape of the failure the NAT scenarios show.
//!
//! Runs on loopback, so there is no NAT involved and nothing else to blame.

use intranet_identity::{MasterSeed, NetworkId, PerNetworkIdentity};
use intranet_transport::{MemberNode, NodeEvent, RelayNode};
use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;
use std::time::Duration;

const NETWORK: NetworkId = NetworkId::from_bytes([42u8; 32]);

fn identity(n: u8) -> PerNetworkIdentity {
    MasterSeed::from_entropy([n; 32]).identity_for(&NETWORK).unwrap()
}

fn tcp_port(address: &Multiaddr) -> Option<u16> {
    address.iter().find_map(|part| match part {
        Protocol::Tcp(port) => Some(port),
        _ => None,
    })
}

#[tokio::test]
async fn the_reservation_connection_reuses_the_listening_port() {
    let relay_identity = identity(1);
    let mut relay = RelayNode::new(&relay_identity).unwrap();
    relay
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();

    let relay_addr = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let NodeEvent::Listening(address) = relay.next_event().await
                && tcp_port(&address).is_some()
            {
                return address;
            }
        }
    })
    .await
    .expect("relay should listen");

    let mut member = MemberNode::new(&identity(2)).unwrap();
    member
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();

    let member_listen_port = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let NodeEvent::Listening(address) = member.next_event().await
                && let Some(port) = tcp_port(&address)
            {
                return port;
            }
        }
    })
    .await
    .expect("member should listen");

    // Obtain a reservation exactly as the harness does: listen on the circuit.
    let circuit = relay_addr
        .clone()
        .with(Protocol::P2p(relay_identity.peer_id()))
        .with(Protocol::P2pCircuit);
    member.listen_on(circuit).unwrap();

    // The relay sees the member arrive; the remote address carries its source port.
    let observed = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = relay.next_event() => {
                    if let NodeEvent::Connected { address, .. } = event
                        && let Some(port) = tcp_port(&address)
                    {
                        return port;
                    }
                }
                _ = member.next_event() => {}
            }
        }
    })
    .await
    .expect("the member should connect to the relay to reserve");

    assert_eq!(
        observed, member_listen_port,
        "the connection a relay observes must originate from the member's listening port \
         ({member_listen_port}), but it came from {observed}. The relay's observed address is \
         what DCUtR hands to the remote peer to dial, so an ephemeral source port here makes \
         hole-punching impossible while leaving every other tier working."
    );
}
