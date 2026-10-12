//! Keeping protocols off relayed circuits — Core Protocol Spec §5.2.
//!
//! # The rule, and why it has to be structural
//!
//! §5.2: a relayed circuit carries the DCUtR negotiation and nothing else — "no
//! governance entries, no ledger, no epoch keys, no records, no pointers, no
//! segments, no live payloads" — and a joiner does not join through one. The
//! deadline in [`crate::node`] bounds how long a circuit lives; it says nothing
//! about what crosses it meanwhile, and libp2p's answer to that is *everything*:
//! a request or a gossip message goes to whatever connection a peer has, and a
//! peer reachable only through a relay has exactly one.
//!
//! So this is not a rule each caller can be asked to keep. ko-ls found it by
//! running two installations across the NAT matrix: a pair whose punch failed
//! exchanged every message over the relay, without any code choosing to. The
//! only place it can hold for every consumer is here, below them.
//!
//! # What this does
//!
//! [`DirectOnly`] wraps one protocol's behaviour. On a direct connection it is
//! invisible. On a relayed one the inner behaviour gets no handler — a dummy
//! stands in, which refuses every inbound stream — and **is never told the
//! connection exists**: its establishment and closure are withheld, and the
//! counts of other connections it is given leave circuits out. To the inner
//! behaviour, a peer reachable only by circuit is a peer it is not connected to,
//! which is exactly what §5.2 says that peer is.
//!
//! A protocol asked to reach such a peer asks the swarm to dial it. **That dial
//! is answered here, as failed, at once** — and so is one that the swarm makes
//! and that lands on a circuit, which it counts as a success. Left to the swarm it would be declined
//! as already connected, and request-response and Kademlia both ignore that
//! particular refusal: the request would sit pending, unanswered and unfailed,
//! until a punch landed and flushed every resend at once. Failing it lets a
//! caller retry once a permitted path exists, which is what the rest of this
//! stack already does. Gossipsub simply has no such peer in its mesh. When a
//! punch succeeds, the direct connection is announced as the peer's first, and
//! everything starts as it would for any new peer.
//!
//! The negotiation's own protocols — DCUtR, the relay client and identify — are
//! deliberately not wrapped: §5.3 budgets a circuit for "a DCUtR negotiation …
//! on top of Noise and identify", and DCUtR exchanges the addresses identify
//! learns. Ping is wrapped; §5.2 does not name it and the punch does not need it.

use std::collections::BTreeMap;
use std::task::{Context, Poll};

use either::Either;
use libp2p::core::transport::PortUse;
use libp2p::core::{Endpoint, Multiaddr};
use libp2p::swarm::behaviour::{ConnectionClosed, ConnectionEstablished, DialFailure};
use libp2p::swarm::{
    ConnectionDenied, ConnectionId, DialError, FromSwarm, NetworkBehaviour, NotifyHandler,
    THandler, THandlerInEvent, THandlerOutEvent, ToSwarm, dummy,
};
use libp2p::{PeerId, multiaddr::Protocol};

/// One protocol's behaviour, kept off relayed circuits.
pub struct DirectOnly<B> {
    inner: B,
    /// Circuits this behaviour was not given, and whose they are, so their
    /// closure is withheld too and a dial to a peer with only these is answered.
    relayed: BTreeMap<ConnectionId, PeerId>,
    /// Dials this behaviour asked for and the swarm has not yet settled. One
    /// that lands on a circuit is reported back to it as failed: the swarm
    /// counts it a success, and the behaviour, never told of the connection,
    /// would otherwise hold whatever it dialled for (module documentation).
    ///
    /// **Untested, stated.** The path was found by reading libp2p's sources:
    /// a peer with no connection, whose only answering address is a circuit.
    /// An in-process attempt to stage it failed the dial outright instead, so
    /// nothing here has watched this branch run.
    dialling: std::collections::BTreeSet<ConnectionId>,
    /// The connections it *was* given, per peer, oldest first: what an
    /// any-connection notification is routed to, and what its counts count.
    permitted: BTreeMap<PeerId, Vec<ConnectionId>>,
}

impl<B> DirectOnly<B> {
    /// Wraps `inner`.
    pub fn new(inner: B) -> Self {
        Self {
            inner,
            relayed: BTreeMap::new(),
            dialling: std::collections::BTreeSet::new(),
            permitted: BTreeMap::new(),
        }
    }

    fn permitted_for(&self, peer: &PeerId) -> usize {
        self.permitted.get(peer).map_or(0, Vec::len)
    }

    /// Whether `peer` is reachable only through a circuit just now.
    fn circuit_only(&self, peer: &PeerId) -> bool {
        self.permitted_for(peer) == 0 && self.relayed.values().any(|owner| owner == peer)
    }
}

/// Method calls reach the wrapped behaviour, so a caller writes
/// `behaviour.sync.send_request(..)` whether or not `sync` is wrapped.
impl<B> std::ops::Deref for DirectOnly<B> {
    type Target = B;

    fn deref(&self) -> &B {
        &self.inner
    }
}

impl<B> std::ops::DerefMut for DirectOnly<B> {
    fn deref_mut(&mut self) -> &mut B {
        &mut self.inner
    }
}

/// Whether an address routes through a relay circuit.
fn through_a_circuit(address: &Multiaddr) -> bool {
    address
        .iter()
        .any(|part| matches!(part, Protocol::P2pCircuit))
}

impl<B: NetworkBehaviour> NetworkBehaviour for DirectOnly<B> {
    type ConnectionHandler = Either<THandler<B>, dummy::ConnectionHandler>;
    type ToSwarm = B::ToSwarm;

    fn handle_pending_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        if through_a_circuit(local_addr) {
            return Ok(());
        }
        self.inner
            .handle_pending_inbound_connection(connection_id, local_addr, remote_addr)
    }

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        // The local address is the circuit listener's for an inbound circuit;
        // the remote one is a send-back address and names no circuit.
        if through_a_circuit(local_addr) {
            self.relayed.insert(connection_id, peer);
            return Ok(Either::Right(dummy::ConnectionHandler));
        }
        self.inner
            .handle_established_inbound_connection(connection_id, peer, local_addr, remote_addr)
            .map(Either::Left)
    }

    fn handle_pending_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        maybe_peer: Option<PeerId>,
        addresses: &[Multiaddr],
        effective_role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        self.inner.handle_pending_outbound_connection(
            connection_id,
            maybe_peer,
            addresses,
            effective_role,
        )
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        addr: &Multiaddr,
        role_override: Endpoint,
        port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        if through_a_circuit(addr) {
            self.relayed.insert(connection_id, peer);
            if self.dialling.remove(&connection_id) {
                self.inner
                    .on_swarm_event(FromSwarm::DialFailure(DialFailure {
                        peer_id: Some(peer),
                        error: &DialError::Aborted,
                        connection_id,
                    }));
            }
            return Ok(Either::Right(dummy::ConnectionHandler));
        }
        self.dialling.remove(&connection_id);
        self.inner
            .handle_established_outbound_connection(
                connection_id,
                peer,
                addr,
                role_override,
                port_use,
            )
            .map(Either::Left)
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::DialFailure(failure) if self.dialling.remove(&failure.connection_id) => {
                self.inner.on_swarm_event(FromSwarm::DialFailure(failure));
            }
            FromSwarm::ConnectionEstablished(established) => {
                if self.relayed.contains_key(&established.connection_id) {
                    return;
                }
                // Counted before this one is added: the inner behaviour is told
                // how many *other* permitted connections there are, so a direct
                // connection after a circuit is its first — which is what
                // decides, for one, whether gossipsub sends its subscriptions.
                let other_established = self.permitted_for(&established.peer_id);
                self.permitted
                    .entry(established.peer_id)
                    .or_default()
                    .push(established.connection_id);
                self.inner.on_swarm_event(FromSwarm::ConnectionEstablished(
                    ConnectionEstablished {
                        other_established,
                        ..established
                    },
                ));
            }
            FromSwarm::ConnectionClosed(closed) => {
                if self.relayed.remove(&closed.connection_id).is_some() {
                    return;
                }
                if let Some(connections) = self.permitted.get_mut(&closed.peer_id) {
                    connections.retain(|id| *id != closed.connection_id);
                    if connections.is_empty() {
                        self.permitted.remove(&closed.peer_id);
                    }
                }
                let remaining_established = self.permitted_for(&closed.peer_id);
                self.inner
                    .on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed {
                        remaining_established,
                        ..closed
                    }));
            }
            FromSwarm::AddressChange(change)
                if self.relayed.contains_key(&change.connection_id) => {}
            // A circuit another behaviour refused never establishes, so no
            // closure will come for it; its id is released here instead.
            FromSwarm::DialFailure(failure)
                if self.relayed.remove(&failure.connection_id).is_some() => {}
            FromSwarm::ListenFailure(failure)
                if self.relayed.remove(&failure.connection_id).is_some() => {}
            other => self.inner.on_swarm_event(other),
        }
    }

    fn on_connection_handler_event(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        match event {
            Either::Left(event) => {
                self.inner
                    .on_connection_handler_event(peer_id, connection_id, event);
            }
            Either::Right(never) => match never {},
        }
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        loop {
            let (peer_id, handler, event) = match self.inner.poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(ToSwarm::NotifyHandler {
                    peer_id,
                    handler,
                    event,
                }) => (peer_id, handler, event),
                // A dial to a peer this behaviour cannot reach, answered now
                // rather than declined by the swarm in a way the inner one
                // ignores (module documentation). It is told the dial failed,
                // which is true: no connection it may use was made.
                Poll::Ready(ToSwarm::Dial { opts })
                    if opts
                        .get_peer_id()
                        .is_some_and(|peer| self.circuit_only(&peer)) =>
                {
                    self.inner
                        .on_swarm_event(FromSwarm::DialFailure(DialFailure {
                            peer_id: opts.get_peer_id(),
                            error: &DialError::Aborted,
                            connection_id: opts.connection_id(),
                        }));
                    continue;
                }
                Poll::Ready(ToSwarm::Dial { opts }) => {
                    self.dialling.insert(opts.connection_id());
                    return Poll::Ready(ToSwarm::Dial { opts });
                }
                Poll::Ready(other) => return Poll::Ready(other.map_in(Either::Left)),
            };
            // A notification must reach a handler the inner behaviour owns. Any
            // connection to the peer might be a circuit, whose handler is the
            // dummy and would panic on it, so "any" is narrowed to a permitted
            // one. With none there is nobody to tell — as far as the inner
            // behaviour was ever told, it holds no connection to this peer — and
            // the notification is dropped, as libp2p drops one for a connection
            // that has closed.
            let target = match handler {
                NotifyHandler::One(connection) if !self.relayed.contains_key(&connection) => {
                    Some(connection)
                }
                NotifyHandler::One(_) => None,
                NotifyHandler::Any => self
                    .permitted
                    .get(&peer_id)
                    .and_then(|connections| connections.first().copied()),
            };
            if let Some(connection) = target {
                return Poll::Ready(ToSwarm::NotifyHandler {
                    peer_id,
                    handler: NotifyHandler::One(connection),
                    event: Either::Left(event),
                });
            }
        }
    }
}
