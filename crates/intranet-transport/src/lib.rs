//! Discovery and transport — Core Protocol Spec §5.
//!
//! Four things live here:
//!
//! - [`behaviour`] — the libp2p behaviour sets for member and relay nodes. The
//!   relay's set deliberately excludes dcutr, because hole-punch negotiation is
//!   client-side only.
//! - [`dial`] — the tiered connection sequence, and the [`ConnectionTier`] a
//!   connection is recorded as having succeeded at. The tier is an observable
//!   outcome rather than an internal detail, because a bug that silently forces
//!   every connection through the relay fallback still works and must fail the
//!   test suite rather than pass it.
//! - [`node`] — [`MemberNode`] and [`RelayNode`], whose PeerIds derive from the
//!   per-network identity so that transport-layer unlinkability holds.
//! - [`relay_limits`] — resource ceilings and rate limiting keyed on
//!   authenticated identity, never on a regenerable peer ID.
//!
//! # Bootstrap nodes are scaffolding, not dependency
//!
//! Nothing in this crate treats a relay as durable infrastructure. A relay holds
//! no state across restarts, and no other component may assume one is reachable
//! during steady-state operation (§5.5): a node caches peer addresses on first
//! join and reconnects without re-contacting a bootstrap node as long as any
//! previously-known peer is reachable.

pub mod behaviour;
pub mod dial;
pub mod node;
pub mod relay_limits;
pub mod sync;

/// Re-exported so a consumer that only drives nodes — a relay deployment, a
/// client embedding — needs no direct libp2p dependency of its own, and cannot
/// end up on a different version of it than this crate is built against.
pub use libp2p::{Multiaddr, PeerId};

pub use dial::{AddressFamily, ConnectionTier};
pub use node::{
    EpochRequestId, JoinRequestId, MemberNode, NodeEvent, RelayNode, default_listen_addresses,
};
pub use relay_limits::{
    CircuitClosure, CircuitId, RelayDenied, RelayGuard, RelayLimits, ReservationId, Requester,
    TransportHandle,
};

use intranet_identity::PerNetworkIdentity;

/// Errors produced by the transport layer.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// The swarm could not be constructed.
    #[error("could not build swarm: {0}")]
    Build(String),

    /// Listening on an address failed.
    #[error("could not listen: {0}")]
    Listen(String),

    /// Dialling failed.
    #[error("could not dial: {0}")]
    Dial(String),

    /// The identity's key material was not usable as a libp2p keypair.
    #[error("could not derive transport keypair: {0}")]
    Keypair(String),
}

/// Derives the libp2p keypair for a per-network identity.
///
/// This is the single point where identity meets transport, and it is why the
/// PeerId differs per network without any separate mechanism: the per-network
/// identity keypair *is* the transport keypair (§1.2).
pub(crate) fn keypair_for(identity: &PerNetworkIdentity) -> libp2p::identity::Keypair {
    let keypair = identity.transport_keypair();
    debug_assert_eq!(
        keypair.public().to_peer_id(),
        identity.peer_id(),
        "transport keypair must yield the identity's PeerId"
    );
    keypair
}
