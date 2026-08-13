//! Does an outbound dial originate from the listening port? — Core Protocol Spec §5.2.
//!
//! # Why this test exists
//!
//! Hole-punching (tier 2) rests on one property that nothing else needs: a
//! node's *outbound* connection must originate from the same port it *listens*
//! on. Only then does its NAT create a mapping `external:X -> node:listen_port`,
//! so that the address a relay observes is one the peer can actually dial back
//! into. If outbound dials use an ephemeral source port, the observed external
//! address maps to a port with no listener behind it, and a hole punch gets
//! `ConnectionRefused` no matter how the NAT is configured.
//!
//! The NAT scenarios found exactly that symptom, with two candidate causes: the
//! NAT emulation, or libp2p not reusing the port. This test separates them
//! without needing Docker — it runs on loopback, where there is no NAT to blame.
//! If the source port matches the listen port here, port reuse works and the
//! fault is in the emulation. If it does not, no amount of NAT tuning will help.

use intranet_identity::{MasterSeed, NetworkId, PerNetworkIdentity};
use intranet_transport::{MemberNode, NodeEvent};
use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;
use std::time::Duration;

const NETWORK: NetworkId = NetworkId::from_bytes([42u8; 32]);

fn identity(n: u8) -> PerNetworkIdentity {
    MasterSeed::from_entropy([n; 32]).identity_for(&NETWORK).unwrap()
}

/// The TCP port component of a multiaddr, if it has one.
fn tcp_port(address: &Multiaddr) -> Option<u16> {
    address.iter().find_map(|part| match part {
        Protocol::Tcp(port) => Some(port),
        _ => None,
    })
}

/// Drives a node until it reports a loopback TCP listen address.
async fn first_tcp_listen_addr(node: &mut MemberNode) -> Multiaddr {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let NodeEvent::Listening(address) = node.next_event().await
                && tcp_port(&address).is_some()
            {
                return address;
            }
        }
    })
    .await
    .expect("node should report a listen address")
}

#[tokio::test]
async fn an_outbound_dial_originates_from_the_listening_port() {
    let mut listener = MemberNode::new(&identity(1)).unwrap();
    let mut dialer = MemberNode::new(&identity(2)).unwrap();

    listener
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    dialer
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();

    let listener_addr = first_tcp_listen_addr(&mut listener).await;
    let dialer_addr = first_tcp_listen_addr(&mut dialer).await;
    let dialer_listen_port = tcp_port(&dialer_addr).expect("dialer listens on TCP");

    dialer.dial_candidates([listener_addr]).unwrap();

    // On the listening side, the remote address of an inbound connection carries
    // the dialer's *source* port — which is the whole question.
    let observed = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = listener.next_event() => {
                    if let NodeEvent::Connected { address, .. } = event {
                        return address;
                    }
                }
                _ = dialer.next_event() => {}
            }
        }
    })
    .await
    .expect("the nodes should connect over loopback");

    let source_port = tcp_port(&observed).expect("an inbound TCP connection has a source port");

    assert_eq!(
        source_port, dialer_listen_port,
        "outbound dials must originate from the listening port ({dialer_listen_port}), but this \
         one came from {source_port}. Without port reuse a NAT maps the observed external address \
         to a port with no listener behind it, so hole-punching cannot work regardless of how the \
         NAT is configured."
    );
}

#[tokio::test]
async fn port_reuse_survives_dialling_two_different_peers() {
    // A hole punch happens while the relay connection is still open, so the
    // property has to hold for a *second* concurrent dial rather than only the
    // first. If the second falls back to an ephemeral port, the address the
    // relay observed stops corresponding to anything dialable at exactly the
    // moment DCUtR needs it.
    let mut first = MemberNode::new(&identity(1)).unwrap();
    let mut second = MemberNode::new(&identity(3)).unwrap();
    let mut dialer = MemberNode::new(&identity(2)).unwrap();

    for node in [&mut first, &mut second, &mut dialer] {
        node.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();
    }

    let first_addr = first_tcp_listen_addr(&mut first).await;
    let second_addr = first_tcp_listen_addr(&mut second).await;
    let dialer_port = tcp_port(&first_tcp_listen_addr(&mut dialer).await).unwrap();

    dialer.dial_candidates([first_addr]).unwrap();
    dialer.dial_candidates([second_addr]).unwrap();

    let mut observed_ports = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), async {
        while observed_ports.len() < 2 {
            tokio::select! {
                event = first.next_event() => {
                    if let NodeEvent::Connected { address, .. } = event
                        && let Some(port) = tcp_port(&address)
                    {
                        observed_ports.push(port);
                    }
                }
                event = second.next_event() => {
                    if let NodeEvent::Connected { address, .. } = event
                        && let Some(port) = tcp_port(&address)
                    {
                        observed_ports.push(port);
                    }
                }
                _ = dialer.next_event() => {}
            }
        }
    })
    .await;

    assert_eq!(observed_ports.len(), 2, "both peers should have been reached");
    for port in observed_ports {
        assert_eq!(
            port, dialer_port,
            "every concurrent outbound dial must reuse the listening port"
        );
    }
}
