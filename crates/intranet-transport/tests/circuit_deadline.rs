//! A circuit that never upgrades is closed on a deadline — Core Protocol Spec §5.2.
//!
//! # The gap this covers, and why it survived a passing NAT matrix
//!
//! §5.2 says a relayed circuit carries the DCUtR negotiation and nothing else,
//! and must be closed when the upgrade fails. The obvious implementation of that
//! sentence is to act on the failure event — and it is not enough. DCUtR reports
//! a failure only when its own direct dial fails in a way it observes; when the
//! dial fails at the transport level, which is the ordinary outcome behind a
//! symmetric NAT, the attempt is abandoned and **nothing is emitted at all**.
//!
//! So a node that waits to be told holds the circuit open forever, carrying
//! whatever it sends next. That is the failure §5.2 exists to prevent, and it
//! looks exactly like success — the harness's scenarios 4 and 6 observed relayed
//! connections surviving indefinitely with `HolePunchFailed` never emitted once
//! across a whole matrix run.
//!
//! # What this test does about it
//!
//! Loopback cannot reproduce a failed punch: both peers are trivially dialable,
//! so the upgrade succeeds and there is no stuck circuit to observe. Rather than
//! simulate a NAT here — the NAT matrix already does that, at a cost this suite
//! is not for — the target is given **no direct listen address at all**. Its only
//! reachable address is the circuit, so there is nothing for a direct dial to
//! reach and no upgrade is possible, which is the same shape as a punch that
//! cannot land and is deterministic rather than timing-dependent.
//!
//! The deadline is lowered so this costs a couple of seconds instead of
//! twenty-five. What is under test is that a bound is enforced at all, not its
//! default value, which §5.2 deliberately leaves to the deployment.

use intranet_identity::{MasterSeed, NetworkId, PerNetworkIdentity};
use intranet_transport::{ConnectionTier, MemberNode, NodeEvent, RelayNode};
use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;
use std::time::Duration;

const NETWORK: NetworkId = NetworkId::from_bytes([42u8; 32]);

/// Short enough to keep the test quick, long enough that the relayed connection
/// is genuinely established first — a deadline that expired during setup would
/// pass for the wrong reason.
const DEADLINE: Duration = Duration::from_secs(3);

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
async fn a_circuit_that_never_upgrades_is_closed_on_the_deadline() {
    let (relay_addr, mut relay) = start_relay().await;

    let target_identity = identity(2);
    let dialer_identity = identity(3);
    let target_peer = target_identity.peer_id();

    let mut target = MemberNode::new(&target_identity).unwrap();
    let mut dialer = MemberNode::new(&dialer_identity).unwrap();

    // Deliberately no `listen_on` for the target: the circuit is its only
    // address, so no direct dial can reach it and no upgrade can occur.
    dialer
        .listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap())
        .unwrap();
    dialer.set_circuit_upgrade_deadline(DEADLINE);

    target.reserve_via_relay(relay_addr.clone()).await.unwrap();
    dialer.reserve_via_relay(relay_addr.clone()).await.unwrap();

    // Reserving only *asks*. The grant arrives as an event, and it arrives only
    // if the relay is being polled — `await_reservation` drives one node, so
    // waiting on each in turn leaves the relay unpolled and nothing is ever
    // granted. The circuit dial then fails with a cancelled oneshot, which reads
    // like a transport fault and is really this.
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

    // Every node is polled together. Driving only the dialer leaves the relay
    // unpolled, so no circuit is ever carried and the test would observe the
    // absence of a connection it never made — passing while asserting nothing.
    let observed = tokio::time::timeout(DEADLINE * 4, async {
        let mut saw_relayed = false;
        loop {
            let event = tokio::select! {
                event = dialer.next_event() => event,
                _ = target.next_event() => continue,
                _ = relay.next_event() => continue,
            };
            match event {
                NodeEvent::Connected { peer, tier, .. } if peer == target_peer => {
                    assert_eq!(
                        tier,
                        ConnectionTier::Relayed,
                        "the target is reachable only through the circuit"
                    );
                    saw_relayed = true;
                }
                // The point of the test: reported without dcutr having said
                // anything, because dcutr never will.
                NodeEvent::HolePunchFailed { peer } if peer == target_peer => {
                    return (saw_relayed, true);
                }
                NodeEvent::Disconnected { peer } if peer == target_peer && saw_relayed => {
                    return (saw_relayed, false);
                }
                _ => {}
            }
        }
    })
    .await;

    let (saw_relayed, reported) = observed.expect(
        "the circuit was still open well past the deadline \u{2014} \u{a7}5.2 requires it be closed \
         without waiting for a failure event that never arrives",
    );

    assert!(
        saw_relayed,
        "the relayed connection must be established first, or this asserts nothing"
    );
    assert!(
        reported,
        "closing the circuit must be reported, not silent: a caller that is told \
         nothing cannot tell a peer it can no longer reach from one it never could"
    );
    assert_eq!(
        dialer.tier_for(&target_peer),
        None,
        "the peer must be forgotten once its circuit is closed, so nothing goes on \
         treating a relayed connection as a usable path"
    );
}
