//! Reserving immediately after a wildcard bind — Core Protocol Spec §5.2.
//!
//! # The gap this covers
//!
//! `port_reuse.rs` and `reservation_port.rs` bind *concrete* addresses. That
//! registers the listening port synchronously, so a dial issued straight
//! afterwards can reuse it — and those tests pass. A wildcard bind
//! (`0.0.0.0`) does not: libp2p watches for interfaces and registers each
//! address as it is discovered, asynchronously. A reservation dial issued
//! before that lands finds nothing to reuse and falls back to an ephemeral
//! port.
//!
//! The observed address a relay reports then points at a port with no listener
//! behind it, which is fatal for hole-punching and invisible everywhere else.
//! This is a property of the transport layer, not of the harness: any deployment
//! binding a wildcard address and then reserving hits it.
//!
//! Both orderings are exercised below so the difference is attributable rather
//! than merely observed.

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

/// Starts a relay and returns its address and identity.
async fn start_relay() -> (Multiaddr, PerNetworkIdentity, RelayNode) {
    let relay_identity = identity(1);
    let mut relay = RelayNode::new(&relay_identity).unwrap();
    relay
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();

    let addr = tokio::time::timeout(Duration::from_secs(5), async {
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

    (addr, relay_identity, relay)
}

/// How the member obtains its reservation.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reserve {
    /// Listen on the circuit immediately, as a naive caller would.
    Immediately,
    /// Drain listen addresses by hand first.
    AfterSettlingManually,
    /// Use the API that encodes the ordering requirement.
    ViaHelper,
}

/// The source port a relay observes for a member that reserved through it.
async fn observed_source_port(listen_on: &str, how: Reserve) -> (u16, u16) {
    let (relay_addr, relay_identity, mut relay) = start_relay().await;

    let mut member = MemberNode::new(&identity(2)).unwrap();
    member.listen_on(listen_on.parse().unwrap()).unwrap();

    let mut listen_port = None;
    if how == Reserve::AfterSettlingManually {
        listen_port = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let NodeEvent::Listening(address) = member.next_event().await
                    && let Some(port) = tcp_port(&address)
                {
                    return port;
                }
            }
        })
        .await
        .ok();
    }

    let relay_full = relay_addr.with(Protocol::P2p(relay_identity.peer_id()));
    match how {
        Reserve::ViaHelper => member.reserve_via_relay(relay_full).await.unwrap(),
        _ => member
            .listen_on(relay_full.with(Protocol::P2pCircuit))
            .unwrap(),
    }

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
                event = member.next_event() => {
                    if let NodeEvent::Listening(address) = event
                        && listen_port.is_none()
                        && let Some(port) = tcp_port(&address)
                        && !address.iter().any(|p| matches!(p, Protocol::P2pCircuit))
                    {
                        listen_port = Some(port);
                    }
                }
            }
        }
    })
    .await
    .expect("the member should reach the relay");

    (listen_port.expect("a listen port should have been reported"), observed)
}

#[tokio::test]
async fn a_concrete_bind_reuses_the_port_even_when_reserving_immediately() {
    // The control: binding a concrete address registers synchronously, so the
    // ordering does not matter and reuse happens regardless.
    let (listen, observed) = observed_source_port("/ip4/127.0.0.1/tcp/0", Reserve::Immediately).await;
    assert_eq!(
        listen, observed,
        "a concrete bind should reuse its port without needing to settle first"
    );
}

#[tokio::test]
async fn a_wildcard_bind_reuses_the_port_once_listeners_have_settled() {
    // The fix: draining listen addresses before reserving gives the transport
    // time to register them, after which reuse behaves as it does for a
    // concrete bind.
    let (listen, observed) =
        observed_source_port("/ip4/0.0.0.0/tcp/0", Reserve::AfterSettlingManually).await;
    assert_eq!(
        listen, observed,
        "once listen addresses are reported, a wildcard bind must reuse its port too — \
         otherwise the address a relay observes points at a port with no listener behind it \
         and hole-punching cannot work"
    );
}

#[tokio::test]
async fn a_wildcard_bind_reserving_immediately_loses_port_reuse() {
    // The bug, pinned. Reserving in the same breath as a wildcard bind finds
    // nothing registered to reuse and falls back to an ephemeral source port —
    // after which the address a relay observes has no listener behind it.
    //
    // Asserted rather than merely probed so that if libp2p ever registers
    // wildcard binds synchronously, this fails and tells us the workaround is
    // no longer needed, instead of quietly becoming dead weight.
    let (listen, observed) = observed_source_port("/ip4/0.0.0.0/tcp/0", Reserve::Immediately).await;
    assert_ne!(
        listen, observed,
        "expected the known wildcard ordering bug to reproduce; if this now passes, \
         libp2p registers wildcard listeners synchronously and reserve_via_relay's \
         wait is no longer necessary"
    );
}

#[tokio::test]
async fn reserve_via_relay_restores_port_reuse_for_a_wildcard_bind() {
    // The fix. Same naive call site as the failing case above — bind and
    // reserve back to back — but through the API that owns the ordering
    // requirement, so a caller cannot get it wrong.
    let (listen, observed) = observed_source_port("/ip4/0.0.0.0/tcp/0", Reserve::ViaHelper).await;
    assert_eq!(
        listen, observed,
        "reserve_via_relay must wait for listeners to register so the relay observes a \
         dialable address"
    );
}

/// Same as `observed_source_port`, but the relay sits on a routable interface.
///
/// libp2p only reuses a listening port when the listener's loopback-ness matches
/// the remote's (`local_dial_addr`). A wildcard bind reports 127.0.0.1 before the
/// routable interface, so waiting for *any* listener can proceed while only a
/// loopback one is registered — which matches nothing when the relay is routable.
async fn observed_source_port_routable_relay(how: Reserve) -> (u16, u16) {
    let relay_identity = identity(1);
    let mut relay = RelayNode::new(&relay_identity).unwrap();
    relay.listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap()).unwrap();

    let relay_addr = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let NodeEvent::Listening(address) = relay.next_event().await
                && tcp_port(&address).is_some()
                && !address.iter().any(|p| matches!(p, Protocol::Ip4(ip) if ip.is_loopback()))
            {
                return address;
            }
        }
    })
    .await
    .expect("relay should listen on a routable address");

    let mut member = MemberNode::new(&identity(2)).unwrap();
    member.listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap()).unwrap();

    let relay_full = relay_addr.with(Protocol::P2p(relay_identity.peer_id()));
    match how {
        Reserve::ViaHelper => member.reserve_via_relay(relay_full).await.unwrap(),
        _ => member.listen_on(relay_full.with(Protocol::P2pCircuit)).unwrap(),
    }

    let mut routable_listen = None;
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
                event = member.next_event() => {
                    if let NodeEvent::Listening(address) = event
                        && !address.iter().any(|p| matches!(p, Protocol::Ip4(ip) if ip.is_loopback()))
                        && !address.iter().any(|p| matches!(p, Protocol::P2pCircuit))
                        && let Some(port) = tcp_port(&address)
                    {
                        routable_listen = Some(port);
                    }
                }
            }
        }
    })
    .await
    .expect("the member should reach the relay");

    (routable_listen.expect("a routable listen port"), observed)
}

#[tokio::test]
async fn diagnostic_wildcard_with_routable_relay() {
    let (listen, observed) = observed_source_port_routable_relay(Reserve::ViaHelper).await;
    println!("ROUTABLE-RELAY listen_port={listen} observed_source_port={observed} reused={}",
        listen == observed);
}

#[tokio::test]
async fn reserve_via_relay_waits_for_a_listener_of_the_relays_family() {
    // A dual-stack node listens on both families, and they do not arrive
    // together. libp2p pairs a listener with a dial only when the family *and*
    // loopback-ness both match, so waiting on an IPv6 listener while dialling an
    // IPv4 relay would register nothing usable and lose port reuse silently.
    //
    // This matters more as IPv6 deployment grows: dual-stack is precisely the
    // case where both are live at once and the race stops being theoretical.
    let relay_identity = identity(1);
    let mut relay = RelayNode::new(&relay_identity).unwrap();
    relay.listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap()).unwrap();

    let relay_addr = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let NodeEvent::Listening(address) = relay.next_event().await
                && tcp_port(&address).is_some()
                && !address.iter().any(|p| matches!(p, Protocol::Ip4(ip) if ip.is_loopback()))
            {
                return address;
            }
        }
    })
    .await
    .expect("relay should listen on a routable IPv4 address");

    // Bind IPv6 first, so the naive wait would be satisfied by the wrong family.
    let mut member = MemberNode::new(&identity(2)).unwrap();
    member.listen_on("/ip6/::/tcp/0".parse().unwrap()).unwrap();
    member.listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap()).unwrap();

    let relay_full = relay_addr.with(Protocol::P2p(relay_identity.peer_id()));
    member.reserve_via_relay(relay_full).await.unwrap();

    let mut ipv4_listen = None;
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
                event = member.next_event() => {
                    if let NodeEvent::Listening(address) = event
                        && address.iter().any(|p| matches!(p, Protocol::Ip4(ip) if !ip.is_loopback()))
                        && let Some(port) = tcp_port(&address)
                    {
                        ipv4_listen = Some(port);
                    }
                }
            }
        }
    })
    .await
    .expect("the member should reach the relay");

    assert_eq!(
        ipv4_listen.expect("a routable IPv4 listen port"),
        observed,
        "reserving toward an IPv4 relay must reuse the IPv4 listener, not be satisfied \
         by an IPv6 one that cannot serve the dial"
    );
}
