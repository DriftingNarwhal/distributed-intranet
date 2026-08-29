//! The tiered connection sequence — Core Protocol Spec §5.2.
//!
//! A node attempts each tier only after the previous one fails:
//!
//! 1. **Direct dial, IPv6 before IPv4.** The ordering is practical, not
//!    cosmetic: two peers that both have globally-routable IPv6 typically have
//!    no NAT problem to solve at all, since IPv6 largely lacks the address
//!    translation layer that makes IPv4 traversal hard. Trying it first
//!    sidesteps hole-punching and relaying entirely.
//! 2. **DCUtR hole-punch**, negotiated peer-to-peer through a relay used only as
//!    a rendezvous point. On success the relay leaves the data path completely.
//! 3. **Persistent relay circuit**, the final fallback for symmetric NAT and
//!    CGNAT. The only tier where a relay stays in the ongoing data path.
//!
//! # Why the tier is recorded, not just the fact of connecting
//!
//! A bug that silently forces every connection through tier 3 still *works* —
//! and defeats the entire point of tiers 1 and 2. The harness asserts which tier
//! succeeded (§2.4), so the tier has to be an observable outcome rather than an
//! implementation detail, which is what [`ConnectionTier`] exists for.

use libp2p::{Multiaddr, multiaddr::Protocol};

/// Which IP family a direct connection used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AddressFamily {
    /// IPv6, preferred.
    Ipv6,
    /// IPv4.
    Ipv4,
}

/// How a connection was actually established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConnectionTier {
    /// Tier 1 — direct dial succeeded.
    Direct(AddressFamily),
    /// Tier 2 — a relayed connection was upgraded to direct via DCUtR.
    HolePunched,
    /// Tier 3 — traffic flows through a relay circuit for the session.
    Relayed,
}

impl ConnectionTier {
    /// Whether the relay is in the ongoing data path.
    ///
    /// True only for tier 3: tier 1 never involves a relay, and tier 2 involves
    /// one only transiently during negotiation.
    pub fn relay_in_data_path(&self) -> bool {
        matches!(self, Self::Relayed)
    }

    /// A short label for logs and harness assertions.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Direct(AddressFamily::Ipv6) => "direct-ipv6",
            Self::Direct(AddressFamily::Ipv4) => "direct-ipv4",
            Self::HolePunched => "hole-punched",
            Self::Relayed => "relayed",
        }
    }
}

/// Classifies an address by the tier a connection over it represents.
///
/// A circuit address is tier 3 regardless of its underlying IP family, which is
/// why the circuit check comes first: `/ip6/…/p2p-circuit/…` is a relayed
/// connection that merely happens to reach the relay over IPv6.
pub fn classify(address: &Multiaddr) -> ConnectionTier {
    if address
        .iter()
        .any(|protocol| matches!(protocol, Protocol::P2pCircuit))
    {
        return ConnectionTier::Relayed;
    }
    ConnectionTier::Direct(family_of(address).unwrap_or(AddressFamily::Ipv4))
}

/// The IP family an address uses, if it names one.
pub fn family_of(address: &Multiaddr) -> Option<AddressFamily> {
    address.iter().find_map(|protocol| match protocol {
        Protocol::Ip6(_) | Protocol::Dns6(_) => Some(AddressFamily::Ipv6),
        Protocol::Ip4(_) | Protocol::Dns4(_) => Some(AddressFamily::Ipv4),
        _ => None,
    })
}

/// Whether an address routes through a relay circuit.
pub fn is_circuit(address: &Multiaddr) -> bool {
    address
        .iter()
        .any(|protocol| matches!(protocol, Protocol::P2pCircuit))
}

/// Whether the address a dial actually *starts* with is one a stranger could
/// reach.
///
/// A dial begins at the first hop and no further. For a direct address that is
/// the whole address; for a circuit address it is the relay half, because a
/// circuit names two peers — the relay to go through, and the target beyond it
/// — and the target's address family says nothing about whether the relay
/// answers. So this reads up to `/p2p-circuit` and stops, which gives the right
/// answer for both shapes without the caller having to know which it holds.
///
/// # Why the hop is what matters, and why this changes an ordering
///
/// If the first hop names an address only reachable from inside some other
/// network, the dial cannot succeed for anyone the address was handed to.
///
/// That would be merely wasteful if it were independent, and it is not. Every
/// circuit address in an invite typically names the *same* relay peer, so the
/// attempts share a connection: once the relay-client behaviour has given up on
/// that peer, every later circuit request through it is cancelled without being
/// tried. A relay announcing its private container address alongside its public
/// one therefore does not merely add a dead address — it **poisons the live
/// one**, and the failure reads as `Response from behaviour was canceled`
/// against the address that would have worked.
///
/// Observed exactly that way: a relay announced `fd12::…` and `10.140.…`
/// beside its `/dns4/` proxy name, the two private hops were dialled first
/// because IPv6 sorts before IPv4, and the working address was tried last
/// against a relay the behaviour had already abandoned.
///
/// A name is treated as routable: `/dns4/` and `/dns6/` are how a hosted relay
/// is normally addressed, and resolution is the transport's business rather than
/// something to guess at from the text.
pub fn first_hop_is_routable(address: &Multiaddr) -> bool {
    for protocol in address.iter() {
        match protocol {
            // Everything before this names the relay; everything after names
            // the peer beyond it, whose address family says nothing about
            // whether the relay can be reached.
            Protocol::P2pCircuit => break,
            Protocol::Ip4(ip) => {
                // `is_global` is unstable, so the unroutable cases are named.
                // 100.64/10 is carrier-grade NAT, which Tailscale also uses —
                // reachable only inside that overlay.
                let cgnat = ip.octets()[0] == 100 && (64..128).contains(&ip.octets()[1]);
                return !(ip.is_private()
                    || ip.is_loopback()
                    || ip.is_link_local()
                    || ip.is_unspecified()
                    || cgnat);
            }
            Protocol::Ip6(ip) => {
                // `fc00::/7` is a unique local address and `fe80::/10` is link
                // local; neither has a stable predicate in `std`.
                let segments = ip.segments();
                let unique_local = segments[0] & 0xfe00 == 0xfc00;
                let link_local = segments[0] & 0xffc0 == 0xfe80;
                return !(unique_local
                    || link_local
                    || ip.is_loopback()
                    || ip.is_unspecified());
            }
            _ => {}
        }
    }
    // A name, or no IP at all: treated as routable rather than guessed at.
    true
}

/// Orders candidate addresses into the sequence §5.2 requires.
///
/// Direct IPv6 first, then direct IPv4, then circuit addresses last — so the
/// tiers are attempted in order simply by dialling the list in order, without
/// the dial loop needing tier logic of its own.
pub fn order_candidates(addresses: impl IntoIterator<Item = Multiaddr>) -> Vec<Multiaddr> {
    let mut candidates: Vec<Multiaddr> = addresses.into_iter().collect();
    candidates.sort_by_key(|address| {
        let circuit = u8::from(is_circuit(address));
        // Among circuits, a relay hop nobody outside its own network can reach
        // goes last. Not merely to save a failed dial: circuit attempts through
        // one relay peer share a connection, so a dead hop tried first cancels
        // the live one behind it (`first_hop_is_routable`). Zero for direct
        // addresses, which have no relay hop and are ordered by family alone.
        let unroutable = u8::from(circuit == 1 && !first_hop_is_routable(address));
        let family = match family_of(address) {
            Some(AddressFamily::Ipv6) => 0u8,
            Some(AddressFamily::Ipv4) => 1,
            None => 2,
        };
        // Circuit dominates: a circuit address is always attempted after every
        // direct one, whatever family it reaches the relay over.
        (circuit, unroutable, family)
    });
    candidates
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> Multiaddr {
        s.parse().expect("valid multiaddr")
    }

    #[test]
    fn a_relay_that_cannot_be_reached_is_tried_after_one_that_can() {
        // Taken from a real invite, in the order it carried them. A relay
        // deployed behind a proxy announced its private container addresses
        // beside its public name; those sort first by family, and because every
        // circuit here names the *same* relay peer, the dead hops cancelled the
        // live one behind them — the failure arrived as `Response from behaviour
        // was canceled` against the address that would have worked.
        let ordered = order_candidates([
            addr("/ip6/fd12:a6a1:7ec6:1::9867/udp/4001/quic-v1/p2p/12D3KooWAT1R2JjcZbnVUKLX8Xo1Qg5APTWMkpHarHY4Uo1YpGzT/p2p-circuit"),
            addr("/ip4/10.140.152.103/tcp/4001/p2p/12D3KooWAT1R2JjcZbnVUKLX8Xo1Qg5APTWMkpHarHY4Uo1YpGzT/p2p-circuit"),
            addr("/dns4/switchback.proxy.rlwy.net/tcp/55503/p2p/12D3KooWAT1R2JjcZbnVUKLX8Xo1Qg5APTWMkpHarHY4Uo1YpGzT/p2p-circuit"),
        ]);

        assert!(
            ordered[0].to_string().contains("switchback"),
            "the reachable relay must be dialled first, got {ordered:?}"
        );
    }

    #[test]
    fn a_relay_hop_is_judged_on_the_relay_and_not_on_the_peer_beyond_it() {
        // The half after `/p2p-circuit` is the target, whose address family says
        // nothing about whether the relay can be reached. Judging the whole
        // string would classify by whichever IP appeared first.
        assert!(first_hop_is_routable(&addr(
            "/dns4/relay.example/tcp/4001/p2p/12D3KooWAT1R2JjcZbnVUKLX8Xo1Qg5APTWMkpHarHY4Uo1YpGzT/p2p-circuit"
        )));
        assert!(!first_hop_is_routable(&addr(
            "/ip4/10.140.152.103/tcp/4001/p2p/12D3KooWAT1R2JjcZbnVUKLX8Xo1Qg5APTWMkpHarHY4Uo1YpGzT/p2p-circuit"
        )));
        // Tailscale's overlay, which is reachable only inside it.
        assert!(!first_hop_is_routable(&addr(
            "/ip4/100.101.152.117/tcp/4001/p2p/12D3KooWAT1R2JjcZbnVUKLX8Xo1Qg5APTWMkpHarHY4Uo1YpGzT/p2p-circuit"
        )));
        assert!(!first_hop_is_routable(&addr(
            "/ip6/fd7a:115c:a1e0::4b36/tcp/4001/p2p/12D3KooWAT1R2JjcZbnVUKLX8Xo1Qg5APTWMkpHarHY4Uo1YpGzT/p2p-circuit"
        )));
        assert!(first_hop_is_routable(&addr(
            "/ip6/2600:1700:a825:4800::3f/tcp/4001/p2p/12D3KooWAT1R2JjcZbnVUKLX8Xo1Qg5APTWMkpHarHY4Uo1YpGzT/p2p-circuit"
        )));
    }

    #[test]
    fn a_lan_relay_is_still_dialled_when_it_is_the_only_one() {
        // Ordering demotes an unreachable hop; it never drops one. A network
        // whose only relay is a member on the same LAN still reaches it, which
        // is the case this must not break.
        let only = addr("/ip4/192.168.1.5/tcp/4001/p2p/12D3KooWAT1R2JjcZbnVUKLX8Xo1Qg5APTWMkpHarHY4Uo1YpGzT/p2p-circuit");
        assert_eq!(order_candidates([only.clone()]), vec![only]);
    }

    #[test]
    fn ipv6_is_ordered_before_ipv4() {
        let ordered = order_candidates([
            addr("/ip4/10.0.0.1/tcp/4001"),
            addr("/ip6/::1/tcp/4001"),
            addr("/ip4/10.0.0.2/udp/4001/quic-v1"),
            addr("/ip6/2001:db8::1/udp/4001/quic-v1"),
        ]);

        let families: Vec<_> = ordered.iter().filter_map(family_of).collect();
        assert_eq!(
            families,
            vec![
                AddressFamily::Ipv6,
                AddressFamily::Ipv6,
                AddressFamily::Ipv4,
                AddressFamily::Ipv4
            ]
        );
    }

    #[test]
    fn circuit_addresses_are_always_attempted_last() {
        let ordered = order_candidates([
            addr("/ip6/2001:db8::1/tcp/4001/p2p-circuit"),
            addr("/ip4/10.0.0.1/tcp/4001"),
        ]);

        assert!(
            !is_circuit(&ordered[0]),
            "a direct IPv4 address must be tried before an IPv6 circuit"
        );
        assert!(is_circuit(&ordered[1]));
    }

    #[test]
    fn a_circuit_over_ipv6_is_still_tier_three() {
        // The trap this guards: classifying by IP family first would report a
        // relayed connection as a direct IPv6 one, and a bug that forced every
        // connection through a relay would look like a pass.
        assert_eq!(
            classify(&addr("/ip6/2001:db8::1/tcp/4001/p2p-circuit")),
            ConnectionTier::Relayed
        );
    }

    #[test]
    fn direct_addresses_classify_by_family() {
        assert_eq!(
            classify(&addr("/ip6/::1/tcp/4001")),
            ConnectionTier::Direct(AddressFamily::Ipv6)
        );
        assert_eq!(
            classify(&addr("/ip4/127.0.0.1/udp/4001/quic-v1")),
            ConnectionTier::Direct(AddressFamily::Ipv4)
        );
    }

    #[test]
    fn only_the_relayed_tier_keeps_a_relay_in_the_data_path() {
        assert!(!ConnectionTier::Direct(AddressFamily::Ipv6).relay_in_data_path());
        assert!(
            !ConnectionTier::HolePunched.relay_in_data_path(),
            "after a successful upgrade the relay drops out entirely"
        );
        assert!(ConnectionTier::Relayed.relay_in_data_path());
    }

    #[test]
    fn ordering_is_stable_and_deterministic() {
        let input = [
            addr("/ip4/10.0.0.1/tcp/4001"),
            addr("/ip6/::1/tcp/4001"),
            addr("/ip4/10.0.0.1/tcp/4002/p2p-circuit"),
        ];
        assert_eq!(
            order_candidates(input.clone()),
            order_candidates(input),
            "two nodes with the same candidate set must dial in the same order"
        );
    }
}
