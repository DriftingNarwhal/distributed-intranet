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

/// Orders candidate addresses into the sequence §5.2 requires.
///
/// Direct IPv6 first, then direct IPv4, then circuit addresses last — so the
/// tiers are attempted in order simply by dialling the list in order, without
/// the dial loop needing tier logic of its own.
pub fn order_candidates(addresses: impl IntoIterator<Item = Multiaddr>) -> Vec<Multiaddr> {
    let mut candidates: Vec<Multiaddr> = addresses.into_iter().collect();
    candidates.sort_by_key(|address| {
        let circuit = u8::from(is_circuit(address));
        let family = match family_of(address) {
            Some(AddressFamily::Ipv6) => 0u8,
            Some(AddressFamily::Ipv4) => 1,
            None => 2,
        };
        // Circuit dominates: a circuit address is always attempted after every
        // direct one, whatever family it reaches the relay over.
        (circuit, family)
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
