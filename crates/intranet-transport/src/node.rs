//! Member and relay nodes — Core Protocol Spec §5.1–5.5.

use crate::dial::{ConnectionTier, classify};
use crate::{RelayLimits, TransportError, behaviour::*};
use intranet_identity::PerNetworkIdentity;
use libp2p::{
    Multiaddr, PeerId, Swarm, SwarmBuilder, dcutr, identify, kad, mdns, ping, relay,
    swarm::SwarmEvent,
};
use std::collections::BTreeMap;

/// The protocol identifier exchanged during `identify`.
pub const PROTOCOL_VERSION: &str = "/intranet/0.1.0";

/// Dual-stack listen addresses covering TCP and QUIC over IPv4 and IPv6 (§5.1).
pub fn default_listen_addresses() -> Vec<Multiaddr> {
    [
        "/ip6/::/tcp/0",
        "/ip4/0.0.0.0/tcp/0",
        "/ip6/::/udp/0/quic-v1",
        "/ip4/0.0.0.0/udp/0/quic-v1",
    ]
    .into_iter()
    .map(|address| address.parse().expect("valid listen multiaddr"))
    .collect()
}

/// Something observable that happened on a node.
#[derive(Debug, Clone)]
pub enum NodeEvent {
    /// The node began listening on an address.
    Listening(Multiaddr),
    /// A connection was established, at a known tier.
    Connected {
        /// The remote peer.
        peer: PeerId,
        /// Which tier succeeded — the thing harness scenarios assert on.
        tier: ConnectionTier,
        /// The address the connection was established over.
        address: Multiaddr,
    },
    /// A connection closed.
    Disconnected {
        /// The remote peer.
        peer: PeerId,
    },
    /// A relayed connection was successfully upgraded to direct.
    HolePunchSucceeded {
        /// The remote peer.
        peer: PeerId,
    },
    /// A hole-punch attempt failed; the connection stays relayed.
    HolePunchFailed {
        /// The remote peer.
        peer: PeerId,
    },
    /// mDNS discovered peers on the local network.
    ///
    /// Carries addresses only. **These are never dialled automatically** — see
    /// [`MemberNode::next_event`].
    LocallyDiscovered {
        /// Discovered peers and their advertised addresses.
        peers: Vec<(PeerId, Multiaddr)>,
    },
    /// An address another peer reports seeing this node at.
    ///
    /// Surfaced because it is precisely what hole-punching depends on and what
    /// is otherwise impossible to observe. DCUtR advertises its own candidate
    /// set, fed from exactly these events, so the address carried here is the
    /// one a remote peer will be told to dial. If it does not correspond to a
    /// port this node listens on, tier 2 cannot succeed — and nothing else will
    /// report that, because every other tier keeps working.
    ExternalAddressCandidate {
        /// The address a peer observed for this node.
        address: Multiaddr,
    },
    /// An address confirmed as externally reachable.
    ///
    /// Distinct from a candidate: libp2p does not promote candidates on its own,
    /// since an address observed by one peer is not necessarily reachable by
    /// another. Confirmation normally comes from AutoNAT or from a node that
    /// knows its own reachability, as a relay does.
    ExternalAddressConfirmed {
        /// The confirmed address.
        address: Multiaddr,
    },
    /// An outbound dial failed.
    ///
    /// Carries the reason, because during a hole punch that reason is the whole
    /// diagnosis: refused, timed out and never left are three different faults
    /// with three different fixes.
    DialFailed {
        /// The peer dialled, if known.
        peer: Option<PeerId>,
        /// Why it failed.
        error: String,
    },
    /// A relay granted a reservation.
    ReservationGranted {
        /// The reserving peer.
        peer: PeerId,
    },
    /// A relay refused a reservation, typically for exceeding a limit.
    ///
    /// Observable on purpose: a refusal that only appears in a log is
    /// indistinguishable from a limiter that never ran.
    ReservationDenied {
        /// The refused peer.
        peer: PeerId,
    },
    /// A reservation ended.
    ReservationReleased {
        /// The peer whose reservation ended.
        peer: PeerId,
    },
}

/// How long a connection may sit idle before libp2p closes it.
///
/// libp2p defaults to 10 seconds, which is too short here for one specific
/// reason: a relayed connection awaiting a DCUtR upgrade carries no traffic, so
/// it is idle by definition and gets torn down mid-negotiation. That produced a
/// hole punch that appeared to land and then vanish, and made scenario outcomes
/// look nondeterministic when they were racing this timer.
///
/// **Flagged: the specs do not name a value.** Sixty seconds is comfortably
/// longer than an upgrade takes and still well inside the 120-second maximum
/// circuit duration a relay enforces (§5.3), so it cannot keep a circuit alive
/// past the relay's own ceiling.
const IDLE_CONNECTION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// How long to wait for listen addresses to register before reserving.
const LISTENER_SETTLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// A full member node.
pub struct MemberNode {
    swarm: Swarm<MemberBehaviour>,
    tiers: BTreeMap<PeerId, ConnectionTier>,
    discovered: BTreeMap<PeerId, Vec<Multiaddr>>,
    /// Events consumed while waiting internally, replayed to the caller.
    ///
    /// Without this, any method that drives the swarm on the caller's behalf
    /// would silently eat events they were waiting for.
    pending: std::collections::VecDeque<NodeEvent>,
    /// Non-circuit listen addresses seen so far.
    ///
    /// Tracked because their presence is what makes port reuse possible; see
    /// [`MemberNode::reserve_via_relay`].
    direct_listeners: std::collections::BTreeSet<Multiaddr>,
}

impl MemberNode {
    /// Builds a node whose transport identity is derived from `identity`.
    ///
    /// The PeerId therefore differs per network for free, which §1.2 requires:
    /// reusing one PeerId across networks would make a node's memberships
    /// trivially correlatable regardless of how carefully its identity keys were
    /// derived, voiding key-level unlinkability in practice.
    ///
    /// # Panics
    ///
    /// Must be called from within a Tokio runtime. The mDNS behaviour opens a
    /// netlink socket at construction time and panics without a reactor, so
    /// this is a hard requirement of the constructor rather than of the first
    /// `await` — a plain `#[test]` calling this will panic inside libp2p.
    pub fn new(identity: &PerNetworkIdentity) -> Result<Self, TransportError> {
        let keypair = crate::keypair_for(identity);

        let swarm = SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(
                libp2p::tcp::Config::default().nodelay(true),
                libp2p::noise::Config::new,
                libp2p::yamux::Config::default,
            )
            .map_err(|e| TransportError::Build(e.to_string()))?
            .with_quic()
            .with_relay_client(libp2p::noise::Config::new, libp2p::yamux::Config::default)
            .map_err(|e| TransportError::Build(e.to_string()))?
            .with_behaviour(|key, relay_client| {
                let peer = key.public().to_peer_id();
                MemberBehaviour {
                    kad: kad::Behaviour::new(peer, kad::store::MemoryStore::new(peer)),
                    mdns: mdns::tokio::Behaviour::new(mdns::Config::default(), peer)
                        .expect("mdns config is valid"),
                    identify: identify::Behaviour::new(identify::Config::new(
                        PROTOCOL_VERSION.into(),
                        key.public(),
                    )),
                    ping: ping::Behaviour::default(),
                    relay_client,
                    dcutr: dcutr::Behaviour::new(peer),
                }
            })
            .map_err(|e| TransportError::Build(e.to_string()))?
            .with_swarm_config(|config| {
                config.with_idle_connection_timeout(IDLE_CONNECTION_TIMEOUT)
            })
            .build();

        Ok(Self {
            swarm,
            tiers: BTreeMap::new(),
            discovered: BTreeMap::new(),
            pending: std::collections::VecDeque::new(),
            direct_listeners: std::collections::BTreeSet::new(),
        })
    }

    /// This node's PeerId for its network.
    pub fn peer_id(&self) -> PeerId {
        *self.swarm.local_peer_id()
    }

    /// Starts listening on an address.
    pub fn listen_on(&mut self, address: Multiaddr) -> Result<(), TransportError> {
        self.swarm
            .listen_on(address)
            .map(|_| ())
            .map_err(|e| TransportError::Listen(e.to_string()))
    }

    /// Starts listening on the dual-stack defaults.
    pub fn listen_default(&mut self) -> Result<(), TransportError> {
        for address in default_listen_addresses() {
            self.listen_on(address)?;
        }
        Ok(())
    }

    /// Dials candidate addresses in tier order (§5.2).
    ///
    /// Candidates are ordered IPv6-direct, IPv4-direct, then circuit, so simply
    /// dialling in order attempts the tiers in the sequence the spec requires.
    pub fn dial_candidates(
        &mut self,
        addresses: impl IntoIterator<Item = Multiaddr>,
    ) -> Result<(), TransportError> {
        for address in crate::dial::order_candidates(addresses) {
            self.swarm
                .dial(address)
                .map_err(|e| TransportError::Dial(e.to_string()))?;
        }
        Ok(())
    }

    /// The tier a currently-connected peer was reached at.
    pub fn tier_for(&self, peer: &PeerId) -> Option<ConnectionTier> {
        self.tiers.get(peer).copied()
    }

    /// Addresses learned from mDNS, which are cached but never auto-dialled.
    pub fn discovered_addresses(&self) -> &BTreeMap<PeerId, Vec<Multiaddr>> {
        &self.discovered
    }

    /// Adds a known address for a peer to the Kademlia routing table.
    pub fn add_address(&mut self, peer: &PeerId, address: Multiaddr) {
        self.swarm.behaviour_mut().kad.add_address(peer, address);
    }

    /// Drives the swarm until the next event.
    ///
    /// # mDNS never auto-dials
    ///
    /// §5.1 requires that LAN discovery inform address caching *only*: actual
    /// connections still flow through the invite and join authorization path, so
    /// LAN visibility never bypasses membership control. This loop therefore
    /// records discovered addresses and emits [`NodeEvent::LocallyDiscovered`],
    /// and deliberately does not call `dial` — nor add them to Kademlia, which
    /// would let routing dial them indirectly. Promoting a discovered peer to a
    /// dial is the caller's decision, made after authorization.
    pub async fn next_event(&mut self) -> NodeEvent {
        if let Some(buffered) = self.pending.pop_front() {
            return buffered;
        }
        self.next_swarm_event().await
    }

    /// Reserves a relay circuit slot, ensuring port reuse can actually happen.
    ///
    /// # Why this exists rather than calling `listen_on` directly
    ///
    /// Hole-punching needs the connection to the relay to originate from a port
    /// this node listens on, so that the address the relay observes is one a
    /// peer can dial back into. libp2p requests port reuse by default and the
    /// relay client's reservation dial does too — but reuse can only happen
    /// against a listener the transport has already *registered*.
    ///
    /// A concrete bind registers synchronously. A wildcard bind (`0.0.0.0`)
    /// does not: libp2p discovers interfaces asynchronously and registers each
    /// address as it arrives. Reserving in the same breath as binding therefore
    /// finds nothing to reuse and falls back to an ephemeral port — after which
    /// the observed address points at a port with no listener behind it, and the
    /// hole punch is refused.
    ///
    /// Nothing else surfaces that: tiers 1 and 3 keep working, and the relay
    /// still reports healthy. So the ordering requirement lives here, in the
    /// layer that owns it, rather than in each caller that would otherwise have
    /// to rediscover it.
    ///
    /// Events observed while waiting are buffered and replayed, so a caller
    /// loses nothing by using this instead of `listen_on`.
    pub async fn reserve_via_relay(&mut self, relay: Multiaddr) -> Result<(), TransportError> {
        // Waiting for *any* listener is not enough. libp2p reuses a listening
        // port only when its loopback-ness matches the remote's, so a wildcard
        // bind that reports 127.0.0.1 before its routable interface would
        // satisfy a naive wait while registering nothing the dial can use.
        let want_loopback = is_loopback(&relay);
        let usable = |listeners: &std::collections::BTreeSet<Multiaddr>| {
            listeners
                .iter()
                .any(|address| is_loopback(address) == want_loopback)
        };

        if !usable(&self.direct_listeners) {
            let deadline = tokio::time::Instant::now() + LISTENER_SETTLE_TIMEOUT;
            while !usable(&self.direct_listeners) {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    break;
                }
                match tokio::time::timeout(remaining, self.next_swarm_event()).await {
                    Ok(event) => self.pending.push_back(event),
                    Err(_) => break,
                }
            }
        }

        if self.direct_listeners.is_empty() {
            // Not fatal: a node with no listener can still reserve and be
            // reached over the circuit. It simply cannot be hole-punched, so
            // this warns rather than refusing and breaking tier 3 as well.
            tracing::warn!(
                "reserving a relay circuit with no direct listener registered;                  the observed address will not be dialable and tier 2 is unavailable"
            );
        }

        self.listen_on(relay.with(libp2p::multiaddr::Protocol::P2pCircuit))
    }

    /// Drives the swarm, bypassing the replay buffer.
    async fn next_swarm_event(&mut self) -> NodeEvent {
        loop {
            let event = futures::StreamExt::select_next_some(&mut self.swarm).await;
            match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    // Circuit addresses are not local sockets, so they are not
                    // what port reuse can bind against.
                    if !crate::dial::is_circuit(&address) {
                        self.direct_listeners.insert(address.clone());
                    }
                    return NodeEvent::Listening(address);
                }

                SwarmEvent::ConnectionEstablished {
                    peer_id, endpoint, ..
                } => {
                    let address = endpoint.get_remote_address().clone();
                    let tier = classify(&address);
                    // A hole-punched connection is first observed as a plain
                    // direct one; the dcutr event below is what distinguishes
                    // tier 2 from tier 1, so an existing HolePunched marking is
                    // never downgraded here.
                    let tier = match self.tiers.get(&peer_id) {
                        Some(ConnectionTier::HolePunched) if !tier.relay_in_data_path() => {
                            ConnectionTier::HolePunched
                        }
                        _ => tier,
                    };
                    self.tiers.insert(peer_id, tier);
                    return NodeEvent::Connected {
                        peer: peer_id,
                        tier,
                        address,
                    };
                }

                SwarmEvent::ConnectionClosed { peer_id, .. } => {
                    self.tiers.remove(&peer_id);
                    return NodeEvent::Disconnected { peer: peer_id };
                }

                SwarmEvent::Behaviour(MemberBehaviourEvent::Dcutr(dcutr::Event {
                    remote_peer_id,
                    result,
                })) => {
                    return match result {
                        Ok(_) => {
                            self.tiers.insert(remote_peer_id, ConnectionTier::HolePunched);
                            NodeEvent::HolePunchSucceeded {
                                peer: remote_peer_id,
                            }
                        }
                        Err(_) => NodeEvent::HolePunchFailed {
                            peer: remote_peer_id,
                        },
                    };
                }

                SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                    // The reason a hole punch failed lives here and nowhere
                    // else. Discarding it leaves "the punch failed" with no
                    // account of whether the SYN was refused, timed out, or
                    // never left — which is the difference between a NAT
                    // problem and a timing one.
                    return NodeEvent::DialFailed {
                        peer: peer_id,
                        error: error.to_string(),
                    };
                }

                SwarmEvent::NewExternalAddrCandidate { address } => {
                    return NodeEvent::ExternalAddressCandidate { address };
                }

                SwarmEvent::ExternalAddrConfirmed { address } => {
                    return NodeEvent::ExternalAddressConfirmed { address };
                }

                SwarmEvent::Behaviour(MemberBehaviourEvent::Mdns(mdns::Event::Discovered(
                    peers,
                ))) => {
                    for (peer, address) in &peers {
                        self.discovered
                            .entry(*peer)
                            .or_default()
                            .push(address.clone());
                    }
                    return NodeEvent::LocallyDiscovered { peers };
                }

                // Ping, identify, kad and the rest are protocol machinery this
                // layer has no opinion on. Skipping them rather than surfacing
                // an `Other` variant means a caller awaiting a connection is not
                // forced to loop past a flood of events it cannot act on.
                //
                // They are traced rather than dropped in silence. A relay bug
                // that broke tiers 2 and 3 was invisible from the outside
                // precisely because these events went nowhere, and was found
                // only by temporarily printing them.
                other => {
                    tracing::trace!(event = ?other, "unhandled swarm event");
                    continue;
                }
            }
        }
    }
}

/// Builds a libp2p relay configuration from this project's declared limits.
///
/// # What wiring these buys, and what it does not
///
/// Until now `RelayLimits` was enforced only by `RelayGuard` in unit tests,
/// while a live relay enforced nothing — which is precisely the class of defect
/// §5.3 exists to prevent, a limiter that computes a decision nothing acts on.
/// Mapping them onto libp2p's own ceilings makes a running relay reject
/// reservations and circuits past the limit, close over-long circuits, and cut
/// off circuits that exceed their byte budget.
///
/// libp2p keys its per-peer ceilings on PeerId. §5.3 warns that a peer-ID-keyed
/// limit is not real protection because a peer ID is free to regenerate — and
/// in a generic libp2p deployment that is exactly right. **Here the binding is
/// tighter**: a node's PeerId is derived from its per-network identity key
/// (§1.2), so it cannot be rotated without rotating that identity.
///
/// That is necessary but *not sufficient*, and the gap is worth naming: nothing
/// stops an attacker generating fresh keypairs that were never admitted to the
/// network. Making these limits meaningful therefore still requires refusing
/// service to identities that are not current members, and metering
/// pre-admission activity per-invite (§5.3) — neither of which a relay can do
/// until it learns which invite a connecting node used. See
/// [`relay_limits`](crate::relay_limits) for the model that expresses both.
fn relay_config(limits: &RelayLimits) -> relay::Config {
    relay::Config {
        max_reservations: limits.max_reservations as usize,
        max_reservations_per_peer: limits.max_reservations_per_identity as usize,
        max_circuits: limits.max_circuits as usize,
        max_circuits_per_peer: limits.max_reservations_per_identity as usize,
        max_circuit_duration: std::time::Duration::from_millis(
            limits.max_circuit_duration_millis.max(0) as u64,
        ),
        max_circuit_bytes: limits.max_circuit_bytes,
        ..relay::Config::default()
    }
}

/// A relay and bootstrap node — §5.2–5.5.
///
/// Deliberately stateless across restarts: its keypair and all routing and
/// reservation state are disposable, which keeps it cheap, interchangeable with
/// any other relay a network designates, and therefore reinforces the
/// takedown-resistance goal rather than becoming durable infrastructure.
///
/// Note the behaviour set carries **no dcutr**. Hole-punch negotiation is
/// client-side only, so a relay needs no dcutr support to facilitate it — a
/// point §5.2 confirms against a real working implementation.
pub struct RelayNode {
    swarm: Swarm<RelayBehaviour>,
    limits: RelayLimits,
    /// Reservations currently granted, by peer.
    ///
    /// Mirrors what libp2p is enforcing so the relay can report its own state —
    /// otherwise "is the limit working" is answerable only by observing clients
    /// fail, which is how an unenforced limiter goes unnoticed.
    reservations: std::collections::BTreeSet<PeerId>,
}

impl RelayNode {
    /// Builds a relay node with the default resource limits.
    pub fn new(identity: &PerNetworkIdentity) -> Result<Self, TransportError> {
        Self::with_limits(identity, RelayLimits::default())
    }

    /// Builds a relay node enforcing specific resource limits.
    pub fn with_limits(
        identity: &PerNetworkIdentity,
        limits: RelayLimits,
    ) -> Result<Self, TransportError> {
        let keypair = crate::keypair_for(identity);

        let swarm = SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(
                libp2p::tcp::Config::default().nodelay(true),
                libp2p::noise::Config::new,
                libp2p::yamux::Config::default,
            )
            .map_err(|e| TransportError::Build(e.to_string()))?
            .with_quic()
            .with_behaviour(|key| {
                let peer = key.public().to_peer_id();
                RelayBehaviour {
                    relay: relay::Behaviour::new(peer, relay_config(&limits)),
                    identify: identify::Behaviour::new(identify::Config::new(
                        PROTOCOL_VERSION.into(),
                        key.public(),
                    )),
                    ping: ping::Behaviour::default(),
                    kad: kad::Behaviour::new(peer, kad::store::MemoryStore::new(peer)),
                }
            })
            .map_err(|e| TransportError::Build(e.to_string()))?
            .build();

        Ok(Self {
            swarm,
            limits,
            reservations: std::collections::BTreeSet::new(),
        })
    }

    /// The limits this relay is enforcing.
    pub fn limits(&self) -> &RelayLimits {
        &self.limits
    }

    /// How many reservations are currently granted.
    pub fn reservation_count(&self) -> usize {
        self.reservations.len()
    }

    /// This relay's PeerId.
    ///
    /// §5.4 recommends exposing this over an out-of-band verifiable channel, so
    /// a client adding the relay as a bootstrap candidate can confirm it is
    /// reaching the relay it intends to rather than an impersonator.
    pub fn peer_id(&self) -> PeerId {
        *self.swarm.local_peer_id()
    }

    /// Starts listening on an address.
    pub fn listen_on(&mut self, address: Multiaddr) -> Result<(), TransportError> {
        self.swarm
            .listen_on(address)
            .map(|_| ())
            .map_err(|e| TransportError::Listen(e.to_string()))
    }

    /// Starts listening on the dual-stack defaults.
    pub fn listen_default(&mut self) -> Result<(), TransportError> {
        for address in default_listen_addresses() {
            self.listen_on(address)?;
        }
        Ok(())
    }

    /// Drives the swarm until the next event.
    pub async fn next_event(&mut self) -> NodeEvent {
        loop {
            let event = futures::StreamExt::select_next_some(&mut self.swarm).await;
            match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    // §5.2, §5.4: a relay is by definition reachable at a public
                    // address, so its listen addresses are its external ones.
                    //
                    // This is load-bearing, not bookkeeping. libp2p builds the
                    // addresses it hands back in a reservation from the swarm's
                    // *external* addresses and never infers them from listen
                    // addresses. Without this the relay still accepts every
                    // reservation but returns an empty address list, and clients
                    // reject it with `NoAddressesInReservation` — so tiers 2 and
                    // 3 fail while tier 1 keeps working and the relay's health
                    // check still reports ready.
                    if !is_loopback(&address) {
                        self.swarm.add_external_address(address.clone());
                    }
                    return NodeEvent::Listening(address);
                }
                SwarmEvent::ConnectionEstablished {
                    peer_id, endpoint, ..
                } => {
                    let address = endpoint.get_remote_address().clone();
                    return NodeEvent::Connected {
                        peer: peer_id,
                        tier: classify(&address),
                        address,
                    };
                }
                SwarmEvent::ConnectionClosed { peer_id, .. } => {
                    return NodeEvent::Disconnected { peer: peer_id };
                }
                SwarmEvent::ExternalAddrConfirmed { address } => {
                    return NodeEvent::ExternalAddressConfirmed { address };
                }

                SwarmEvent::Behaviour(RelayBehaviourEvent::Relay(
                    relay::Event::ReservationReqAccepted { src_peer_id, .. },
                )) => {
                    self.reservations.insert(src_peer_id);
                    return NodeEvent::ReservationGranted { peer: src_peer_id };
                }

                SwarmEvent::Behaviour(RelayBehaviourEvent::Relay(
                    relay::Event::ReservationReqDenied { src_peer_id, .. },
                )) => {
                    // Surfaced rather than logged, because "the limit is
                    // enforced" is only demonstrable if a refusal is observable.
                    return NodeEvent::ReservationDenied { peer: src_peer_id };
                }

                SwarmEvent::Behaviour(RelayBehaviourEvent::Relay(
                    relay::Event::ReservationClosed { src_peer_id },
                )) => {
                    self.reservations.remove(&src_peer_id);
                    return NodeEvent::ReservationReleased { peer: src_peer_id };
                }

                other => {
                    tracing::trace!(event = ?other, "unhandled relay swarm event");
                    continue;
                }
            }
        }
    }
}

/// Whether an address is loopback.
///
/// Used for two different decisions: whether a relay may advertise an address as
/// external, and whether a listener can serve a dial under libp2p's port-reuse
/// rule, which pairs listeners and remotes by loopback-ness.
fn is_loopback(address: &Multiaddr) -> bool {
    address.iter().any(|part| match part {
        libp2p::multiaddr::Protocol::Ip4(ip) => ip.is_loopback(),
        libp2p::multiaddr::Protocol::Ip6(ip) => ip.is_loopback(),
        _ => false,
    })
}
