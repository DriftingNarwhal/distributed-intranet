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

use crate::direct_only::DirectOnly;
use crate::sync::{
    BallotCodec, ChunkCodec, CollectionCodec, DirectCodec, EpochCodec, JoinCodec, LedgerCodec,
    MediaCodec, PointerCodec, SignalCodec, SyncCodec,
};
use libp2p::{
    dcutr, gossipsub, identify, kad, mdns, ping, relay, request_response, swarm::NetworkBehaviour,
    swarm::behaviour::toggle::Toggle,
};

/// The behaviour set a member node runs.
///
/// **Every protocol is [`DirectOnly`] but the negotiation's own** — Core §5.2: a
/// relayed circuit carries the DCUtR negotiation and nothing else. Left bare are
/// DCUtR, the relay client and identify, which §5.3 budgets a circuit for ("on
/// top of Noise and identify"); mDNS opens no streams on a connection, so it has
/// nothing to keep off. A test below reads this struct and fails on anything
/// else left bare, because an unwrapped protocol runs over circuits silently.
///
/// Carried forward from prior prototyping rather than relitigated: Kademlia for
/// WAN routing, mDNS for LAN discovery (address caching only, never auto-dial),
/// and identify plus ping for peer metadata and liveness. The relay *client* and
/// dcutr halves are what let this node be the connecting party in tiers 2 and 3.
///
/// # Why the discovery halves are optional
///
/// Kademlia and mDNS answer one question — *who else is out there, and who has
/// this content* — and there are networks where that question has no work in it.
/// A pairwise network has exactly two members and nobody to discover; the one
/// peer that matters is known by construction. Running a routing table and
/// multicasting on the LAN for it is pure overhead, and a client holding one
/// node per network (Core §5.1.1) pays that overhead once per conversation.
///
/// So both are [`Toggle`]d rather than fixed. Everything else stays: a node
/// without discovery is still fully reachable, still relays, still hole-punches
/// and still serves every request-response protocol. It has given up *finding*
/// peers, not talking to them.
#[derive(NetworkBehaviour)]
pub struct MemberBehaviour {
    /// WAN peer and content routing, absent on a node built without discovery.
    pub kad: DirectOnly<Toggle<kad::Behaviour<kad::store::MemoryStore>>>,
    /// LAN peer discovery — address caching only. Absent without discovery.
    pub mdns: Toggle<mdns::tokio::Behaviour>,
    /// Peer metadata exchange.
    pub identify: identify::Behaviour,
    /// Liveness.
    pub ping: DirectOnly<ping::Behaviour>,
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
    pub sync: DirectOnly<request_response::Behaviour<SyncCodec>>,
    /// Capability ledger gossip — §4.5.
    ///
    /// A separate protocol from the governance log rather than a second message
    /// type on the same one, because the two reconcile differently: the log by
    /// ancestry, the ledger by per-node freshness. Sharing a protocol would mean
    /// one version number covering two things that will not change together.
    pub ledger: DirectOnly<request_response::Behaviour<LedgerCodec>>,
    /// Ballot collection — §2.6.1.
    ///
    /// Pull-based like everything else here, and for a reason specific to votes:
    /// §2.6.1 blesses a certificate assembled long after close from ballots
    /// validly cast before it, which is only reachable if those ballots can
    /// still be obtained late. A broadcast has no history, so a node partitioned
    /// during the voting window could never assemble the certificate the spec
    /// says is valid.
    pub ballot: DirectOnly<request_response::Behaviour<BallotCodec>>,
    /// The join handshake — §5.6–5.7.
    ///
    /// The one protocol a node speaks before it is a member of anything, which
    /// is what makes its refusals the network's outermost door.
    pub join: DirectOnly<request_response::Behaviour<JoinCodec>>,
    /// Epoch key delivery — §3.5.
    ///
    /// The one protocol here that moves key material, and therefore the one
    /// whose refusals matter as much as its successes: a waiting-room identity
    /// under explicit intake is a valid, non-revoked identity holding no
    /// capability, and it must come away with nothing (§2.4).
    pub epoch: DirectOnly<request_response::Behaviour<EpochCodec>>,
    /// Chunk transfer — Storage Spec §4.
    ///
    /// Its own protocol rather than a message on either of the others, because
    /// it moves bulk content rather than metadata: the size ceilings, the
    /// backpressure story (§4.5) and the authorization gate (§5.4) are all
    /// specific to it.
    pub chunk: DirectOnly<request_response::Behaviour<ChunkCodec>>,
    /// Mutable pointer sync — Storage Spec §2.2.
    ///
    /// Its own protocol rather than a message on chunk transfer, because the two
    /// move different things under different rules: chunks are immutable bytes
    /// addressed by their own hash, while a pointer is a small signed record
    /// that is *replaced* over time and whose replacement rule — higher version,
    /// then lower record hash — is the whole substance of the protocol.
    pub pointer: DirectOnly<request_response::Behaviour<PointerCodec>>,
    /// Append-set collection enumeration — Storage Spec §2.5.
    ///
    /// One primitive, several consumers: search postings (Search Spec §3.1) and
    /// the app name registry (App Hosting Spec §4.3–4.4) both build on it, which
    /// is why it carries opaque payloads rather than either consumer's type.
    pub collection: DirectOnly<request_response::Behaviour<CollectionCodec>>,
    /// Live delivery for consuming specs — Chat Application Spec §6.1.
    ///
    /// The one broadcast primitive here, and the only place a broadcast is the
    /// right shape: everything else in this behaviour is pull-based because it
    /// carries state a partitioned node must be able to obtain *late*, and a
    /// broadcast has no history. Live delivery is the opposite case — a payload
    /// nobody needs to receive at all. Missing one costs latency and nothing
    /// else, because the same record arrives on the durable path.
    ///
    /// **Message signing is deliberately `None`.** A consuming spec's payload is
    /// expected to carry its own signature — chat records do (spec 07 §2.5) — so
    /// gossipsub-level signing would sign the same bytes a second time with a
    /// second key, and a receiver would then have two answers to "who wrote
    /// this" and no rule for which wins. Validation belongs to the consumer,
    /// which is the only layer that knows what the payload means.
    pub gossip: DirectOnly<gossipsub::Behaviour>,
    /// Direct member-to-member delivery — Core Protocol Spec §5.1.
    ///
    /// The one protocol here that carries a message rather than state. Everything
    /// else is pull-based because it moves something a partitioned node must be
    /// able to obtain *late*; this moves a payload whose whole value is having
    /// reached a particular person, so there is nothing to catch up on and
    /// nothing is stored by either side.
    ///
    /// Generic by the same reasoning as Core §2.7.2's application entry: it
    /// arrived as chat's `/chat/dm-invite/1.0.0` and carries `(namespace, kind,
    /// payload)` instead, because an application's vocabulary in this struct is
    /// what Core §0 rules out. See [`crate::direct`].
    pub direct: DirectOnly<request_response::Behaviour<DirectCodec>>,
    /// Call signalling — Real-Time Spec §1.4.
    ///
    /// The session-scoped channel §1.4 says participants already need for the
    /// initial mesh and that renegotiation reuses rather than duplicating.
    ///
    /// **Flagged:** two participants with no direct or hole-punched path cannot
    /// call. Signalling travels member to member, a blind relay deliberately
    /// does not carry it (Real-Time §2.2), and §5.2 keeps it off circuits — so
    /// neither mesh nor relay mode helps them. Core §5.2's answer for such a
    /// pair, convergence through a member both reach, is about pull-based state
    /// and does not cover a call. The Real-Time spec says nothing of the case;
    /// the circuit hid it until 2026-10-12.
    pub signal: DirectOnly<request_response::Behaviour<SignalCodec>>,
    /// Call media — Real-Time Spec §2.2.
    ///
    /// Deliberately a separate protocol from signalling. A blind relay speaks
    /// this and not the other, which is what makes "architecturally incapable of
    /// decrypting" true rather than a promise: key envelopes travel on a channel
    /// the relay is never asked to carry.
    pub media: DirectOnly<request_response::Behaviour<MediaCodec>>,
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

#[cfg(test)]
mod tests {
    /// Every field of [`super::MemberBehaviour`] is [`super::DirectOnly`] unless
    /// it is one the negotiation needs or one that opens no streams.
    ///
    /// Read from the source rather than the type, because the failure this
    /// guards against is a field added later: a new protocol left bare runs over
    /// circuits and nothing else would say so (`tests/circuit_carries_nothing.rs`
    /// exercises two protocols, not every one).
    #[test]
    fn nothing_but_the_negotiation_is_left_on_circuits() {
        const BARE: [&str; 4] = ["identify", "relay_client", "dcutr", "mdns"];
        let source = include_str!("behaviour.rs");
        let start = source
            .find("pub struct MemberBehaviour {")
            .expect("the struct is in this file");
        let body = &source[start..start + source[start..].find("\n}").expect("it closes")];
        let mut fields = 0;
        for line in body.lines().map(str::trim) {
            let Some(rest) = line.strip_prefix("pub ") else {
                continue;
            };
            let Some((name, ty)) = rest.split_once(':') else {
                continue;
            };
            fields += 1;
            assert!(
                BARE.contains(&name) || ty.trim().starts_with("DirectOnly<"),
                "`{name}` is not DirectOnly, so it would run over relayed circuits, which \
                 Core \u{a7}5.2 forbids. Wrap it, or add it to BARE with the spec's reason"
            );
        }
        assert!(
            fields > 10,
            "read too few fields ({fields}) to be checking the struct"
        );
    }
}
