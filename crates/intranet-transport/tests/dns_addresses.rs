//! Can a node dial an address written as a **name**? — Core Protocol Spec §5.1.
//!
//! # Why this exists
//!
//! It could not, and nothing said so. `SwarmBuilder` composes a transport out of
//! what it is asked for, and name resolution is one of those things: without
//! `.with_dns()` a `/dns4/…` address is simply unsupported, and the failure is
//! the quietest kind available. `listen_on` for a circuit succeeds, because
//! registering a listener does not resolve anything. The dial that follows is
//! refused inside the swarm. No call returns an error, no relay sees a
//! connection, and the node reports only that no reservation arrived.
//!
//! That cost a real deployment an evening: a correctly configured relay, a
//! correct multiaddress, a matching peer id, and an empty log at the far end.
//! Every address in this project had been an `/ip4/` literal until then, so
//! nothing had ever asked the transport to resolve a name.
//!
//! §5.1 constrains families and transports and says nothing about how an address
//! is *written*, so a name has always been a legitimate way to name a relay —
//! and a deployed one is normally the only way, since its address is a hostname
//! whose IP the operator does not control.
//!
//! # What this asserts, and what it deliberately does not
//!
//! That a name is **dialable**: `localhost` resolves without a network, so this
//! needs no DNS server and cannot flake on one. It does not assert that any
//! particular public name resolves, which would be a test of the internet.

use intranet_identity::{MasterSeed, NetworkId, PerNetworkIdentity};
use intranet_transport::{MemberNode, NodeEvent};
use libp2p::Multiaddr;
use std::time::Duration;

const NETWORK: NetworkId = NetworkId::from_bytes([42u8; 32]);

fn identity(n: u8) -> PerNetworkIdentity {
    MasterSeed::from_entropy([n; 32]).identity_for(&NETWORK).unwrap()
}

/// A node dials a peer named by hostname rather than by literal address.
#[tokio::test]
async fn a_peer_named_by_hostname_can_be_dialled() {
    let mut listener = MemberNode::new(&identity(1)).unwrap();
    let listener_peer = listener.peer_id();
    listener
        .listen_on("/ip4/127.0.0.1/tcp/0".parse::<Multiaddr>().unwrap())
        .unwrap();

    // The port it actually bound, since the request asked for any.
    let mut port = None;
    while port.is_none() {
        if let NodeEvent::Listening(address) = listener.next_event().await {
            port = address.iter().find_map(|part| match part {
                libp2p::multiaddr::Protocol::Tcp(port) => Some(port),
                _ => None,
            });
        }
    }
    let port = port.expect("the listener reports a port");

    // The same endpoint, written as a name. Identical in every other respect,
    // so a failure here is about resolution and nothing else.
    let by_name: Multiaddr = format!("/dns4/localhost/tcp/{port}/p2p/{listener_peer}")
        .parse()
        .unwrap();

    let mut dialer = MemberNode::new(&identity(2)).unwrap();
    dialer
        .dial_candidates([by_name.clone()])
        .unwrap_or_else(|err| {
            panic!("dialling {by_name} was refused before it left this node: {err}")
        });

    let connected = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            // Driven on both sides: a dial completes only if the far end is
            // being polled to accept it.
            tokio::select! {
                event = dialer.next_event() => {
                    if let NodeEvent::Connected { peer, .. } = event {
                        if peer == listener_peer {
                            return true;
                        }
                    }
                }
                _ = listener.next_event() => {}
            }
        }
    })
    .await;

    assert!(
        connected.is_ok(),
        "a peer named /dns4/localhost was never reached. Without `.with_dns()` on \
         the swarm the transport reports the address unsupported and no call \
         returns an error — which is how a deployed relay addressed by hostname \
         goes unreached in silence"
    );
}
