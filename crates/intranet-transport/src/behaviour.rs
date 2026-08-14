//! libp2p behaviour sets — Core Protocol Spec §5.1.
//!
//! The `missing_docs` allow below is scoped to this module because
//! `#[derive(NetworkBehaviour)]` generates a sibling event enum whose variants
//! it does not document, and an attribute on the struct does not reach it.
//! Every item this module actually writes is documented.
#![allow(
    missing_docs,
    reason = "derive(NetworkBehaviour) emits an undocumented event enum"
)]

use crate::sync::{
    ChunkCodec, CollectionCodec, EpochCodec, LedgerCodec, MediaCodec, SignalCodec, SyncCodec,
};
use libp2p::{
    dcutr, identify, kad, mdns, ping, relay, request_response, swarm::NetworkBehaviour,
};

/// The behaviour set every full member node runs.
///
/// Carried forward from prior prototyping rather than relitigated: Kademlia for
/// WAN routing, mDNS for LAN discovery (address caching only, never auto-dial),
/// and identify plus ping for peer metadata and liveness. The relay *client* and
/// dcutr halves are what let this node be the connecting party in tiers 2 and 3.
#[derive(NetworkBehaviour)]
pub struct MemberBehaviour {
    /// WAN peer and content routing.
    pub kad: kad::Behaviour<kad::store::MemoryStore>,
    /// LAN peer discovery — informs address caching only.
    pub mdns: mdns::tokio::Behaviour,
    /// Peer metadata exchange.
    pub identify: identify::Behaviour,
    /// Liveness.
    pub ping: ping::Behaviour,
    /// Client half of circuit relay, for tiers 2 and 3.
    pub relay_client: relay::client::Behaviour,
    /// Hole-punch upgrade negotiation, for tier 2.
    pub dcutr: dcutr::Behaviour,
    /// Governance log sync — §2.7.
    ///
    /// Pull-based rather than a broadcast, for both a spec reason and a
    /// correctness one. §2.7 allows the log "no new storage or transport
    /// primitive beyond what's already specified in §5.1", and §5.1 names no
    /// pubsub. More importantly a broadcast has no history, so entries appended
    /// during a partition would be lost to the other side forever; pulling makes
    /// a heal indistinguishable from a reconnect. See [`crate::sync`].
    pub sync: request_response::Behaviour<SyncCodec>,
    /// Capability ledger gossip — §4.5.
    ///
    /// A separate protocol from the governance log rather than a second message
    /// type on the same one, because the two reconcile differently: the log by
    /// ancestry, the ledger by per-node freshness. Sharing a protocol would mean
    /// one version number covering two things that will not change together.
    pub ledger: request_response::Behaviour<LedgerCodec>,
    /// Epoch key delivery — §3.5.
    ///
    /// The one protocol here that moves key material, and therefore the one
    /// whose refusals matter as much as its successes: a waiting-room identity
    /// under explicit intake is a valid, non-revoked identity holding no
    /// capability, and it must come away with nothing (§2.4).
    pub epoch: request_response::Behaviour<EpochCodec>,
    /// Chunk transfer — Storage Spec §4.
    ///
    /// Its own protocol rather than a message on either of the others, because
    /// it moves bulk content rather than metadata: the size ceilings, the
    /// backpressure story (§4.5) and the authorization gate (§5.4) are all
    /// specific to it.
    pub chunk: request_response::Behaviour<ChunkCodec>,
    /// Append-set collection enumeration — Storage Spec §2.5.
    ///
    /// One primitive, several consumers: search postings (Search Spec §3.1) and
    /// the app name registry (App Hosting Spec §4.3–4.4) both build on it, which
    /// is why it carries opaque payloads rather than either consumer's type.
    pub collection: request_response::Behaviour<CollectionCodec>,
    /// Call signalling — Real-Time Spec §1.4.
    ///
    /// The session-scoped channel §1.4 says participants already need for the
    /// initial mesh and that renegotiation reuses rather than duplicating.
    pub signal: request_response::Behaviour<SignalCodec>,
    /// Call media — Real-Time Spec §2.2.
    ///
    /// Deliberately a separate protocol from signalling. A blind relay speaks
    /// this and not the other, which is what makes "architecturally incapable of
    /// decrypting" true rather than a promise: key envelopes travel on a channel
    /// the relay is never asked to carry.
    pub media: request_response::Behaviour<MediaCodec>,
}

/// The behaviour set a relay and bootstrap node runs.
///
/// **Deliberately excludes `dcutr`.** Hole-punch negotiation is client-side
/// only, so a relay needs no dcutr support to facilitate an upgrade — §5.2
/// confirms this against a real working relay whose behaviour set was exactly
/// relay + rendezvous + identify + ping + kad, with no dcutr feature. Including
/// it here would imply the relay participates in negotiation, which it does not.
///
/// It also excludes mDNS: a relay exists to solve cold start across the open
/// internet, and has no use for LAN discovery.
#[derive(NetworkBehaviour)]
pub struct RelayBehaviour {
    /// Server half of circuit relay.
    pub relay: relay::Behaviour,
    /// Peer metadata exchange.
    pub identify: identify::Behaviour,
    /// Liveness.
    pub ping: ping::Behaviour,
    /// Routing, so the relay can serve as a rendezvous point.
    pub kad: kad::Behaviour<kad::store::MemoryStore>,
}
