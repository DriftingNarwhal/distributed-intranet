//! Member and relay nodes — Core Protocol Spec §5.1–5.5.

use crate::dial::{ConnectionTier, classify};
use crate::{RelayLimits, TransportError, behaviour::*};
use intranet_crypto::{Hash, Timestamp};
use intranet_epoch::{
    EpochError, EpochKeyRequest, EpochKeyResponse, EpochKeyring, GroupSession, KeyDeliveryRefusal,
    KeyringReconciliation, PendingMember, identity_label, key_package_identity, open_history,
    seal_history,
};
use intranet_governance::{
    AdmissionMode, Ballot, BallotRefusal, BallotRequest, BallotResponse, EntryBody,
    GovernanceError, GovernanceLog, GovernanceState, GroupId, MAX_BALLOTS_PER_RESPONSE,
    QuorumCertificate,
    HistoryAccess, LogEntry, MAX_ENTRIES_PER_RESPONSE, MembershipAction, PointerId,
    RotationReason, SyncRequest, SyncResponse,
};
use intranet_invite::{
    Invite, JoinRefusal, JoinRequest, JoinResponse, WaitingRoom, WaitingRoomEntry,
};
use intranet_ledger::{
    CapabilityAdvertisement, CapabilityLedger, LedgerError, LedgerRequest, LedgerResponse,
    MAX_ADVERTISEMENTS_PER_RESPONSE, ReliabilityObservations,
};
use intranet_realtime::{CallId, MediaAck, MediaEnvelope, Signal, SignalAck, SignalBody};
use intranet_storage::{
    ChunkRefusal, ChunkRequest, ChunkResponse, ChunkStore, Cid, CollectionRequest,
    CollectionResponse, DekWrapping, FetchPlan, MAX_COLLECTION_ENTRIES,
    MAX_POINTERS_PER_RESPONSE, MutablePointer, PointerDigestEntry, PointerRecord, PointerRefusal,
    PointerRequest, PointerResponse, StorageError, may_serve,
};
use intranet_identity::{PerNetworkIdentity, PerNetworkIdentityId};
use libp2p::{
    Multiaddr, PeerId, Swarm, SwarmBuilder, dcutr, identify, kad, mdns, ping, relay,
    request_response, request_response::ResponseChannel, swarm::SwarmEvent,
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

/// Identifies one inbound join awaiting this node's decision.
///
/// Opaque and node-local, like [`EpochRequestId`]: it names a request held
/// between the event that surfaced it and the call that answers it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JoinRequestId(u64);

/// Identifies one inbound key delivery awaiting this node's decision.
///
/// Opaque and node-local: it names a request held in memory between the event
/// that surfaced it and the call that answers it, and means nothing to a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EpochRequestId(u64);

/// Something observable that happened on a node.
#[derive(Debug, Clone)]
pub enum NodeEvent {
    /// The node began listening on an address.
    Listening(Multiaddr),
    /// Ballots arrived from a peer — §2.6.1.
    BallotsReceived {
        /// The peer that sent them.
        peer: PeerId,
        /// The vote they were cast under.
        vote_id: Hash,
        /// How many this node took.
        accepted: usize,
        /// How many it refused — not in the frozen electorate, cast after close,
        /// or for a vote it does not know is open.
        rejected: usize,
        /// Whether the response was truncated.
        truncated: bool,
    },
    /// A ballot request was refused.
    BallotSyncRefused {
        /// The peer that refused.
        peer: PeerId,
        /// The vote asked about.
        vote_id: Hash,
        /// Why.
        reason: String,
    },
    /// A peer reported which pointers it holds — Storage Spec §2.2.
    ///
    /// A fetch for anything worth having is already in flight when this is
    /// surfaced; the counts are for observability, not for the caller to act on.
    PointerDigest {
        /// The peer that answered.
        peer: PeerId,
        /// How many pointers it offered.
        offered: usize,
        /// How many of those this node did not already hold at least as new.
        wanted: usize,
        /// Whether its digest was truncated, so more remain.
        truncated: bool,
    },
    /// Pointer records arrived from a peer — §2.2, §5.3.
    PointersReceived {
        /// The peer that sent them.
        peer: PeerId,
        /// How many records this node adopted.
        accepted: usize,
        /// How many it refused — a failed publish gate, a delisting, or a record
        /// that did not supersede what it already held.
        rejected: usize,
        /// How many DEK wrappings it took alongside them.
        wrappings: usize,
        /// Whether the response was truncated.
        truncated: bool,
    },
    /// A pointer request was refused.
    PointerSyncRefused {
        /// The peer that refused.
        peer: PeerId,
        /// Why.
        reason: String,
    },
    /// A peer presented an invite, and it passed every check this node can
    /// make without a clock — §5.6.
    ///
    /// Surfaced rather than answered automatically because validating an invite
    /// needs a clock and admitting needs a signature, neither of which this
    /// layer holds. Requests failing a check are refused in the loop.
    JoinRequested {
        /// The peer that asked.
        peer: PeerId,
        /// The identity asking.
        joiner: PerNetworkIdentityId,
        /// The invite presented, for an admin deciding whether to admit.
        invite: Hash,
        /// Pass to [`MemberNode::answer_join`] or [`MemberNode::decline_join`].
        request: JoinRequestId,
    },
    /// This node was admitted to the network — §2.4 auto-admit.
    ///
    /// Membership only. The epoch key is a separate, ordinary request (§5.7),
    /// so a node that stops here can replay the log and read nothing.
    Admitted {
        /// The peer that admitted it.
        peer: PeerId,
        /// The governance entry recording the admission.
        entry: Hash,
    },
    /// This node is in the waiting room — §2.4 explicit intake.
    ///
    /// A successful join, not a refusal: connectivity and a per-network identity
    /// is exactly what explicit intake grants, and nothing more until an admin
    /// acts.
    AwaitingAdmission {
        /// The peer holding the waiting-room place.
        peer: PeerId,
    },
    /// A join was refused.
    JoinRefused {
        /// The peer that refused.
        peer: PeerId,
        /// Why.
        reason: String,
    },
    /// A peer asked to be keyed into the network, and passed every check —
    /// §3.5.
    ///
    /// Surfaced rather than answered automatically because answering means
    /// signing a governance entry, which needs an identity and a timestamp this
    /// layer does not hold. Requests that fail a check are refused in the loop
    /// and never appear here, so an application that ignores this event leaves
    /// a requester unanswered rather than wrongly admitted.
    EpochKeyRequested {
        /// The peer that asked.
        peer: PeerId,
        /// The identity asking, already verified against the request signature,
        /// the connection, the `read-content` gate and its key package.
        requester: PerNetworkIdentityId,
        /// Pass to [`MemberNode::answer_epoch_key`] or
        /// [`MemberNode::decline_epoch_key`].
        request: EpochRequestId,
    },
    /// This node was keyed into the network — §3.5.
    EpochKeyDelivered {
        /// The peer that welcomed it.
        peer: PeerId,
        /// The rotation the delivered key belongs to.
        rotation_ref: Hash,
        /// How many superseded keys came with it (§3.4's full-history policy).
        historical_keys: usize,
    },
    /// A key delivery was refused, or could not be completed.
    EpochKeyUnavailable {
        /// The peer that answered.
        peer: PeerId,
        /// Why.
        reason: String,
    },
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
    /// A sync exchange with a peer completed.
    ///
    /// Reports what was actually taken up rather than what arrived. `rejected`
    /// counts entries this node refused — an unknown parent, or a structural
    /// check failing — which is the difference between "we are in step" and "we
    /// received things we could not use", and is otherwise invisible.
    Synced {
        /// The peer synced with.
        peer: PeerId,
        /// Entries accepted into the log.
        accepted: usize,
        /// Entries received but refused.
        rejected: usize,
        /// Whether the peer had more to send than one response could carry.
        ///
        /// A follow-up `Fetch` is issued automatically; this is surfaced so a
        /// caller can tell a completed sync from one still in progress rather
        /// than concluding convergence too early.
        truncated: bool,
    },
    /// A capability ledger exchange with a peer completed — §4.5.
    ///
    /// `rejected` is the interesting field on a node still catching up. An
    /// advertisement is only accepted from a current member, so a node whose
    /// governance replica has not converged yet rejects perfectly valid
    /// advertisements. That is expected and self-correcting — a governance sync
    /// that accepts anything triggers another ledger sync — but it is worth
    /// seeing rather than inferring from an oddly empty ledger.
    LedgerSynced {
        /// The peer synced with.
        peer: PeerId,
        /// Advertisements accepted.
        accepted: usize,
        /// Advertisements received but refused.
        rejected: usize,
        /// Whether the peer had more to send than one response could carry.
        truncated: bool,
    },
    /// A chunk arrived and was verified against the identifier requested.
    ///
    /// The bytes are already in this node's store by the time this is reported,
    /// which is also the moment it joins that chunk's swarm (§4.2).
    ChunkReceived {
        /// The peer that served it.
        peer: PeerId,
        /// The chunk.
        cid: Cid,
        /// How many bytes.
        bytes: usize,
    },
    /// A chunk request did not produce usable bytes.
    ///
    /// Covers all three ways that happens — refused, not held, and failed
    /// verification — because a requester's next move is the same in each case:
    /// try another holder. They are distinguished in `reason` because they mean
    /// very different things about *this* holder, and only one of them is that
    /// peer's fault.
    ChunkUnavailable {
        /// The peer asked.
        peer: PeerId,
        /// The chunk.
        cid: Cid,
        /// What happened.
        reason: String,
        /// Whether this counted against the peer's local reliability signal.
        ///
        /// True only for a verification failure. A peer that does not hold a
        /// chunk, or that declines to serve it, has done nothing wrong — holding
        /// either against it would make an honest node that dropped a cached
        /// copy look unreliable, and §4.6's signal is specifically about
        /// verification failures.
        counted_against_peer: bool,
    },
    /// The DHT answered a provider lookup — Storage Spec §4.4 step 1.
    ///
    /// Carries identities rather than PeerIds because everything downstream —
    /// ledger lookup, source selection, reliability observations — is keyed on
    /// identity, and resolving once here keeps that conversion in one place.
    ProvidersFound {
        /// The chunk asked about.
        cid: Cid,
        /// Who holds it, as far as the DHT knows.
        providers: Vec<PerNetworkIdentityId>,
        /// How many holders were found, for rarest-first ordering (§4.4 step 2).
        ///
        /// The same as `providers.len()`, reported explicitly because it is the
        /// input to a specified decision rather than an incidental property of
        /// the list.
        holder_count: usize,
    },
    /// A multi-source fetch finished — Storage Spec §4.4.
    ///
    /// Reports both halves, because a partial fetch is a real and useful
    /// outcome: an object missing one chunk is still worth knowing about, and a
    /// caller that only learned "the fetch ended" would have to work out which
    /// chunks it actually got.
    FetchComplete {
        /// Chunks that arrived and verified.
        received: Vec<Cid>,
        /// Chunks no known holder would produce.
        unavailable: Vec<Cid>,
    },
    /// The DHT answered a collection provider lookup — Storage Spec §2.5.
    ///
    /// Reported before any entries, because enumerating a collection is two
    /// steps: find who is announcing it, then ask them. A caller normally
    /// responds by calling
    /// [`request_collection`](MemberNode::request_collection) for each provider.
    CollectionProviders {
        /// The collection asked about.
        collection_id: Hash,
        /// Peers announcing it.
        providers: Vec<PeerId>,
    },
    /// A collection enumeration returned entries — Storage Spec §2.5.
    ///
    /// Payloads are opaque: the append-set is one primitive with several
    /// consumers, so decoding belongs to whichever crate owns the entry shape.
    CollectionEnumerated {
        /// The collection enumerated.
        collection_id: Hash,
        /// The peer that answered.
        peer: PeerId,
        /// Encoded entries.
        payloads: Vec<Vec<u8>>,
        /// Whether that peer held more than one response could carry.
        ///
        /// Surfaced because §2.5 makes incompleteness a specified property
        /// rather than a failure, and a consumer needing an authoritative answer
        /// has to be able to tell a partial result from a complete one.
        truncated: bool,
    },
    /// A call signalling message arrived — Real-Time Spec §1.4.
    ///
    /// Its signature was verified during decoding, so the sender named really
    /// sent it. Whether they are *entitled* to be in this call is the receiving
    /// application's decision, not the transport's.
    SignalReceived {
        /// The signed message.
        signal: Signal,
    },
    /// A media frame arrived for this node — Real-Time Spec §2.2.
    ///
    /// Carries the sealed frame, not its contents: this node still has to open
    /// it with the call key, and a frame that fails to open is a frame that was
    /// tampered with or misrouted.
    MediaReceived {
        /// The envelope, still sealed.
        envelope: MediaEnvelope,
    },
    /// This node forwarded a frame as a blind relay — Real-Time Spec §2.2.
    ///
    /// Reported so relaying is observable without being decodable. Note what is
    /// *not* here: no plaintext, no key, no frame contents. A relay operator can
    /// see that they carried traffic and for whom, which is exactly the routing
    /// metadata §2.2 says a relay sees, and nothing more.
    MediaForwarded {
        /// The call.
        call: CallId,
        /// Who sent the frame.
        from: PerNetworkIdentityId,
        /// Who it was forwarded to.
        to: PerNetworkIdentityId,
    },
    /// A sync request to a peer failed.
    ///
    /// Not fatal — the protocol is pull-based, so the next reconnect retries in
    /// full. Surfaced because a silently failing sync looks exactly like a
    /// network with nothing to say.
    SyncFailed {
        /// The peer whose sync failed.
        peer: PeerId,
        /// Why.
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

/// How long to wait for a reservation to be granted before giving up on it.
///
/// Covers a dial to the relay plus the reservation round trip, so it is
/// necessarily longer than [`LISTENER_SETTLE_TIMEOUT`], which waits only on
/// local sockets. Observed reservations land well inside a second; this is a
/// bound on a stuck relay, not a tuned value.
///
/// **Flagged: the specs do not name a value.**
const RESERVATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// The observed failure rate at which a source is deprioritized.
///
/// **Flagged: §4.6 says a peer observed failing verification is deprioritized
/// and gives no threshold.** Half is deliberately forgiving — a peer has to fail
/// as often as it succeeds before it drops behind unobserved peers — because the
/// signal is per-observer and a strict threshold would let ordinary transport
/// flakiness look like misbehaviour. Deprioritization is never exclusion: the
/// peer is still tried when nobody better is available.
const UNRELIABLE_FAILURE_RATE: f64 = 0.5;

/// The DHT key a chunk is announced under.
///
/// The content identifier's own digest, so the key is derived rather than
/// invented and two nodes cannot disagree about where a chunk should be
/// announced.
fn provider_key(cid: &Cid) -> kad::RecordKey {
    kad::RecordKey::new(&cid.hash().as_bytes())
}

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
    /// Circuit listen addresses seen so far.
    ///
    /// One appearing is the only observable signal that a relay actually
    /// *granted* a reservation, as opposed to one having been asked for.
    circuit_listeners: std::collections::BTreeSet<Multiaddr>,
    /// This node's replica of the network's governance log — §2.7.
    ///
    /// Held by the node rather than beside it because sync has to answer a
    /// peer's request from inside the event loop. Keeping the log elsewhere
    /// would mean either blocking the loop on a lock or answering from a stale
    /// copy, and a sync that answers from a stale copy is a sync that quietly
    /// fails to converge.
    log: GovernanceLog,
    /// This node's cached view of what peers have advertised — §4.5.
    ///
    /// Held beside the governance log because it cannot be validated without
    /// it: an advertisement is only accepted from a current member, so the
    /// ledger is meaningless until the log says who the members are.
    ledger: CapabilityLedger,
    /// Chunks this node holds and will serve — Storage Spec §4.2.
    chunks: ChunkStore,
    /// This node's own verification observations — Core Protocol Spec §4.6.
    ///
    /// Local-only and never gossiped. It lives here because chunk verification
    /// failures are the main thing that feeds it, and it feeds only local source
    /// selection. Nothing exposes it to a cross-node computation, which the type
    /// signatures in `intranet-ledger` are arranged to enforce.
    observations: ReliabilityObservations,
    /// Chunks requested but not yet answered, by request identifier.
    ///
    /// Needed because a response carries bytes but not the CID they are for, and
    /// the arriving bytes must be checked against the identifier that was
    /// *asked* for — checking them against an identifier derived from the bytes
    /// themselves would verify nothing at all.
    inflight: BTreeMap<request_response::OutboundRequestId, (PeerId, PerNetworkIdentityId, Cid)>,
    /// Provider lookups in flight, and what has been found so far — §4.4 step 1.
    ///
    /// Accumulated rather than reported per batch because Kademlia delivers
    /// providers incrementally across several results, and the holder *count* is
    /// what rarest-first ordering needs. Reporting each batch separately would
    /// make a chunk look scarcer than it is, purely because its providers
    /// happened to arrive spread out.
    provider_queries: std::collections::HashMap<kad::QueryId, (Cid, std::collections::BTreeSet<PeerId>)>,
    /// The multi-source fetch in progress, if any — §4.4.
    ///
    /// One plan rather than one per call: a second fetch extends the first, so
    /// concurrency stays bounded by the local limit across everything a node is
    /// pulling rather than per caller, which is the only way the limit means
    /// anything.
    fetch: Option<FetchPlan>,
    /// Requests signed once per chunk when a fetch starts.
    ///
    /// A request's signature covers the chunk and the requester, **not** the
    /// source, so one signature serves every holder that chunk is tried
    /// against. That is what lets the event loop retry elsewhere without a key:
    /// the identity is used once, at the start of the operation, matching §1.3's
    /// per-operation derivation rather than being held live so that a retry
    /// three round trips later can sign something.
    fetch_requests: BTreeMap<Cid, ChunkRequest>,
    /// Append-set entries this node holds, by collection — Storage Spec §2.5.
    ///
    /// Keyed by entry identifier within each collection so a republish replaces
    /// rather than duplicates: §2.5's freshness model is refresh-or-expire, and
    /// a collection that accumulated a new copy on every refresh would grow
    /// without bound for content that never changed.
    collections: BTreeMap<Hash, BTreeMap<Hash, Vec<u8>>>,
    /// Collection lookups in flight, and the providers found so far.
    collection_queries: std::collections::HashMap<kad::QueryId, (Hash, std::collections::BTreeSet<PeerId>)>,
    /// Enumeration requests outstanding, by request identifier.
    collection_requests: BTreeMap<request_response::OutboundRequestId, Hash>,
    /// This node's own public identifier.
    ///
    /// The public half only — no key material. Kept because the media path has
    /// to answer "is this frame for me or am I forwarding it", and deriving it
    /// from the PeerId on every frame would be wasted work on the one path where
    /// latency is the product.
    identity_id: PerNetworkIdentityId,
    /// This node's own identity, for the paths that must sign or agree inside
    /// the event loop.
    ///
    /// Held rather than passed per call — the convention everywhere else — for
    /// one reason: opening the sealed history in a §3.4 full-history delivery
    /// needs a key agreement against the sender, and that happens as a response
    /// arrives rather than when a caller asks for something. This is no new
    /// exposure; the swarm below already holds the same key material as its
    /// Noise transport identity, derived from this very keypair (§1.2).
    identity: PerNetworkIdentity,
    /// Ballots collected for open votes — §2.6.1.
    ///
    /// Keyed by vote, then by ballot hash, so a re-offered ballot replaces
    /// rather than duplicates. Deliberately *not* in the governance log: a
    /// ballot is the raw material a certificate is assembled from, and a vote
    /// that never passes should leave nothing behind in every node's replay.
    /// Once an outcome is appended the ballots have done their work — the
    /// certificate carries the ones that mattered.
    ballots: BTreeMap<Hash, BTreeMap<Hash, Ballot>>,
    /// Ballot requests outstanding, and which vote each was for.
    ballot_requests: BTreeMap<request_response::OutboundRequestId, Hash>,
    /// Mutable pointers this node holds — Storage Spec §2.2.
    ///
    /// One record per pointer, since a pointer *is* its latest record: a
    /// superseding record replaces rather than accumulates. Keeping older
    /// versions would invite serving one, and §2.2's version rule exists
    /// precisely so a stale record can never be presented as current.
    pointers: BTreeMap<PointerId, MutablePointer>,
    /// DEK wrappings held, by pointer and then by the rotation they are under.
    ///
    /// Keyed by rotation because a wrapping is only usable by someone holding
    /// that rotation's epoch key, and because cleanup after a voided branch
    /// (§5.3.1) is "replace the one under the stale rotation" rather than
    /// "replace the wrapping". Wrapping under a given rotation is deterministic,
    /// so two members re-wrapping the same object collide byte-for-byte and this
    /// map converges rather than growing.
    wrappings: BTreeMap<PointerId, BTreeMap<Hash, DekWrapping>>,
    /// Pointer digests requested and not yet answered.
    pointer_digests: BTreeMap<request_response::OutboundRequestId, PeerId>,
    /// Pointer fetches requested and not yet answered.
    pointer_fetches: BTreeMap<request_response::OutboundRequestId, PeerId>,
    /// Identities that presented an invite and are awaiting admission — §2.4.
    ///
    /// Node-local rather than a log entry, because waiting-room occupancy is not
    /// an authorization fact but precisely the absence of one. Admission *is* an
    /// authorized action and is recorded as an ordinary `MembershipChange`, at
    /// which point the identity leaves here.
    waiting_room: WaitingRoom,
    /// Inbound joins that passed every check this node can make alone.
    ///
    /// Held for the same reason inbound key deliveries are: answering means
    /// validating an invite against a clock and, under auto-admit, signing a
    /// governance entry. This layer holds no clock by design.
    inbound_joins: BTreeMap<JoinRequestId, (JoinRequest, ResponseChannel<JoinResponse>)>,
    /// Source of the next [`JoinRequestId`].
    next_join_request: u64,
    /// Joins asked for and not yet answered, and who was asked.
    join_requests: BTreeMap<request_response::OutboundRequestId, PerNetworkIdentityId>,
    /// This node's MLS group session, once it has one — §3.3.
    ///
    /// `None` covers two genuinely different states that behave identically
    /// here: a node that has not yet created a network, and one that has joined
    /// but not yet been keyed in. Neither can welcome anybody, which is why the
    /// serving path refuses with `NoGroup` rather than distinguishing them.
    group: Option<GroupSession>,
    /// Epoch keys this node holds, tentative and final — §3.3, §3.4.
    keyring: EpochKeyring,
    /// A key package generated while awaiting a Welcome.
    ///
    /// Held between asking and being answered because the private half never
    /// leaves this node: the Welcome is HPKE-sealed to this package, so a node
    /// that regenerated one in the meantime could not open the answer to its own
    /// request.
    pending_join: Option<PendingMember>,
    /// Key deliveries asked for and not yet answered, and who was asked.
    ///
    /// The responder identity is kept because sealed history (§3.4) is opened
    /// against the *sender's* key, and a response carries key material but no
    /// trustworthy statement of who sent it — that comes from who was asked.
    epoch_requests: BTreeMap<request_response::OutboundRequestId, PerNetworkIdentityId>,
    /// Inbound key deliveries that passed every check this node can make alone.
    ///
    /// Held rather than answered inline because answering means signing a
    /// governance entry, and signing needs both an identity and a timestamp
    /// this layer deliberately does not hold: timestamps are always passed in so
    /// the harness can drive finality on a virtual clock. Requests that fail a
    /// check are refused in the loop and never reach here, so ignoring an event
    /// leaves a requester unanswered rather than wrongly admitted.
    inbound_epoch_requests: BTreeMap<EpochRequestId, (EpochKeyRequest, ResponseChannel<EpochKeyResponse>)>,
    /// Source of the next [`EpochRequestId`].
    next_epoch_request: u64,
    /// Calls this node is relaying media for, and who is in them — §2.2.
    ///
    /// A relay needs the participant set so it can refuse to forward to someone
    /// outside the call; it needs nothing else, and deliberately holds nothing
    /// else. There is no key here and no place to put one, which is what
    /// "architecturally incapable of decrypting" means concretely.
    relayed_calls: BTreeMap<CallId, std::collections::BTreeSet<PerNetworkIdentityId>>,
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
                    sync: crate::sync::behaviour(),
                    ballot: crate::sync::ballot_behaviour(),
                    join: crate::sync::join_behaviour(),
                    epoch: crate::sync::epoch_behaviour(),
                    ledger: crate::sync::ledger_behaviour(),
                    chunk: crate::sync::chunk_behaviour(),
                    pointer: crate::sync::pointer_behaviour(),
                    collection: crate::sync::collection_behaviour(),
                    signal: crate::sync::signal_behaviour(),
                    media: crate::sync::media_behaviour(),
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
            circuit_listeners: std::collections::BTreeSet::new(),
            log: GovernanceLog::new(),
            ledger: CapabilityLedger::new(*identity.network()),
            chunks: ChunkStore::new(),
            observations: ReliabilityObservations::new(),
            inflight: BTreeMap::new(),
            provider_queries: std::collections::HashMap::new(),
            fetch: None,
            fetch_requests: BTreeMap::new(),
            collections: BTreeMap::new(),
            collection_queries: std::collections::HashMap::new(),
            collection_requests: BTreeMap::new(),
            identity_id: identity.id(),
            identity: identity.clone(),
            ballots: BTreeMap::new(),
            ballot_requests: BTreeMap::new(),
            pointers: BTreeMap::new(),
            wrappings: BTreeMap::new(),
            pointer_digests: BTreeMap::new(),
            pointer_fetches: BTreeMap::new(),
            waiting_room: WaitingRoom::new(),
            inbound_joins: BTreeMap::new(),
            next_join_request: 0,
            join_requests: BTreeMap::new(),
            group: None,
            keyring: EpochKeyring::new(),
            pending_join: None,
            epoch_requests: BTreeMap::new(),
            inbound_epoch_requests: BTreeMap::new(),
            next_epoch_request: 0,
            relayed_calls: BTreeMap::new(),
        })
    }


    // -----------------------------------------------------------------------
    // Epoch key delivery — Core Protocol Spec §3.5
    // -----------------------------------------------------------------------

    /// Creates this network's MLS group, with this node as its only member.
    ///
    /// The founder path. Every other node reaches a group by being welcomed
    /// into this one, so this is called once per network, by whoever created it.
    ///
    /// The resulting epoch is recorded against the **genesis** entry, because
    /// genesis is the log entry that produced it. Storage Spec §5.3 requires a
    /// wrapping to reference the entry hash that produced its epoch, and for the
    /// network's first epoch there is no rotation entry to point at.
    pub fn create_epoch_group(
        &mut self,
        identity: &PerNetworkIdentity,
    ) -> Result<(), EpochError> {
        let session = GroupSession::create(&identity_label(&identity.id()))?;
        let key = session.epoch_key()?;
        let epoch = session.epoch();

        let genesis = self
            .log
            .canonical_chain()
            .first()
            .copied()
            .ok_or_else(|| EpochError::Mls("no genesis entry to anchor the epoch to".into()))?;

        self.keyring.record(genesis, epoch, key);
        self.group = Some(session);
        Ok(())
    }

    /// Sends an already-built key delivery request — §3.5.
    ///
    /// [`Self::request_epoch_key`] is the ordinary path and builds the request
    /// itself. This exists for callers that need to control the request's
    /// contents, which in practice means tests exercising what a responder does
    /// with one it should refuse.
    pub fn send_epoch_request(
        &mut self,
        from: PerNetworkIdentityId,
        request: EpochKeyRequest,
    ) -> request_response::OutboundRequestId {
        let id = self
            .swarm
            .behaviour_mut()
            .epoch
            .send_request(&from.peer_id(), request);
        self.epoch_requests.insert(id, from);
        id
    }

    /// Rotates the epoch away from a revoked member — §3.1, §3.3.
    ///
    /// The cryptographic half of the revocation guarantee: the removed identity
    /// holds only superseded keys and cannot derive the new one, so nothing
    /// wrapped from here on is readable by them. The other half is the
    /// `read-content` serving gate refusing them new ciphertext (Storage Spec
    /// §5.4), and neither half is sufficient alone.
    ///
    /// # The membership removal must already be in the log
    ///
    /// This refuses while the target is still a current member, which enforces
    /// the ordering rather than trusting a caller to get it right. Rotating
    /// first and removing second leaves a window in which the revoked member is
    /// entitled to the key that was just minted to exclude them — and because a
    /// key cannot be un-known (§3.1), that window cannot be closed afterwards.
    ///
    /// Revoking an identity that was never keyed in is a no-op returning `None`:
    /// there is no leaf to remove, and no commit is needed to exclude somebody
    /// the tree never held.
    pub fn revoke_epoch_member(
        &mut self,
        revoked: &PerNetworkIdentityId,
        identity: &PerNetworkIdentity,
        now: Timestamp,
    ) -> Result<Option<Hash>, EpochError> {
        let state = self
            .governance_state()
            .ok_or_else(|| EpochError::Mls("no governance state to check membership".into()))?;
        if state.is_member(revoked) {
            return Err(EpochError::Mls(format!(
                "{} is still a current member: append the membership removal before rotating,                  or the rotation mints a key the revoked member is still entitled to",
                revoked.short()
            )));
        }

        let group = self
            .group
            .as_mut()
            .ok_or_else(|| EpochError::Mls("this node holds no group".into()))?;
        let Some(index) = group.leaf_index_for(revoked) else {
            return Ok(None);
        };
        let rotation = group.remove_member(index)?;

        let parent = self.log.canonical_chain().last().copied();
        let entry = LogEntry::create(
            identity,
            parent,
            now,
            EntryBody::EpochRotation {
                reason: RotationReason::MemberRevoked,
                commit: rotation.commit,
            },
        );
        let rotation_ref = self
            .log
            .insert(entry)
            .map_err(|e| EpochError::Mls(format!("rotation entry rejected: {e}")))?;
        self.keyring
            .record(rotation_ref, rotation.epoch, rotation.key);
        Ok(Some(rotation_ref))
    }

    /// Rotates the epoch without a membership change — §1.3, point 6.
    ///
    /// The self-initiated rekey any member may request after a device
    /// compromise, requiring no capability: gating it behind approval would
    /// discourage reporting a compromise, which is the wrong incentive. The
    /// commit is appended to the log like any other rotation, so other members
    /// pick it up through ordinary sync.
    pub fn rotate_epoch(
        &mut self,
        identity: &PerNetworkIdentity,
        now: Timestamp,
    ) -> Result<Hash, EpochError> {
        let group = self
            .group
            .as_mut()
            .ok_or_else(|| EpochError::Mls("this node holds no group".into()))?;
        let rotation = group.rotate()?;

        let parent = self.log.canonical_chain().last().copied();
        let entry = LogEntry::create(
            identity,
            parent,
            now,
            EntryBody::EpochRotation {
                reason: RotationReason::SelfInitiated,
                commit: rotation.commit,
            },
        );
        let rotation_ref = self
            .log
            .insert(entry)
            .map_err(|e| EpochError::Mls(format!("rotation entry rejected: {e}")))?;
        self.keyring
            .record(rotation_ref, rotation.epoch, rotation.key);
        Ok(rotation_ref)
    }

    /// This node's held epoch keys — §3.3.
    pub fn epoch_keyring(&self) -> &EpochKeyring {
        &self.keyring
    }

    /// Whether this node currently holds a usable epoch key.
    ///
    /// The honest question to ask before publishing or reading: a node with a
    /// synced log and no key can fetch every byte of a network's content and
    /// open none of it.
    pub fn holds_epoch_key(&self) -> bool {
        self.keyring.current().is_some()
    }

    /// Asks a peer to key this node into the network — §3.5.
    ///
    /// Generates a key package if one is not already outstanding, and keeps the
    /// private half locally: the answer is sealed to this package, so a node
    /// that regenerated one would be unable to open its own Welcome.
    pub fn request_epoch_key(
        &mut self,
        from: PerNetworkIdentityId,
        identity: &PerNetworkIdentity,
    ) -> Result<request_response::OutboundRequestId, EpochError> {
        if self.pending_join.is_none() {
            self.pending_join = Some(GroupSession::prepare_join(&identity_label(&identity.id()))?);
        }
        let key_package = self
            .pending_join
            .as_ref()
            .expect("just populated")
            .key_package()?;

        let request = EpochKeyRequest::create(identity, key_package);
        let id = self
            .swarm
            .behaviour_mut()
            .epoch
            .send_request(&from.peer_id(), request);
        self.epoch_requests.insert(id, from);
        Ok(id)
    }

    /// Answers a key delivery this node accepted — §3.5.
    ///
    /// Performs the MLS add, appends the rotation it produces to the governance
    /// log, and seals whatever history the network's policy grants. Every gate
    /// was already applied when the request arrived; what is left is the part
    /// that needs an identity to sign with and a clock to sign at, neither of
    /// which the event loop holds.
    ///
    /// The rotation is appended **before** the Welcome is sent. A member keyed
    /// into a group whose commit no peer can order is a member nobody else will
    /// agree with, so if the append fails the admission does not happen.
    pub fn answer_epoch_key(
        &mut self,
        request: EpochRequestId,
        identity: &PerNetworkIdentity,
        now: Timestamp,
    ) -> Result<Hash, EpochError> {
        let (request, channel) = self
            .inbound_epoch_requests
            .remove(&request)
            .ok_or_else(|| EpochError::Mls("no such pending key delivery".into()))?;

        let group = self
            .group
            .as_mut()
            .ok_or_else(|| EpochError::Mls("this node holds no group".into()))?;
        let rotation = group.add_member(&request.key_package)?;
        let welcome = rotation
            .welcome
            .ok_or_else(|| EpochError::Mls("an add produced no welcome".into()))?;

        let parent = self.log.canonical_chain().last().copied();
        let entry = LogEntry::create(
            identity,
            parent,
            now,
            EntryBody::EpochRotation {
                reason: RotationReason::MemberAdmitted,
                commit: rotation.commit,
            },
        );
        let rotation_ref = self
            .log
            .insert(entry)
            .map_err(|e| EpochError::Mls(format!("rotation entry rejected: {e}")))?;
        self.keyring
            .record(rotation_ref, rotation.epoch, rotation.key);

        // Superseded epochs only: the joiner derives the current key from the
        // Welcome itself, so re-sending it would be shipping raw key material
        // for something they are about to compute anyway.
        let history = match self.governance_state().map(|state| state.policy.history_access) {
            Some(HistoryAccess::FullHistory) => {
                let keys: Vec<_> = self
                    .keyring
                    .keys_for_new_member(HistoryAccess::FullHistory)
                    .into_iter()
                    .filter(|(hash, _)| *hash != rotation_ref)
                    .collect();
                seal_history(identity, &request.requester, &keys)?
            }
            _ => Vec::new(),
        };

        let _ = self.swarm.behaviour_mut().epoch.send_response(
            channel,
            EpochKeyResponse::Welcome {
                welcome,
                rotation_ref,
                history,
            },
        );
        Ok(rotation_ref)
    }

    /// Refuses a key delivery this node had accepted for consideration.
    ///
    /// Distinct from letting it lapse: a requester that is told no can act on
    /// the answer, where one left waiting cannot tell refusal from a peer that
    /// simply went away.
    pub fn decline_epoch_key(&mut self, request: EpochRequestId, reason: KeyDeliveryRefusal) {
        if let Some((_, channel)) = self.inbound_epoch_requests.remove(&request) {
            let _ = self
                .swarm
                .behaviour_mut()
                .epoch
                .send_response(channel, EpochKeyResponse::Refused { reason });
        }
    }

    /// Applies canonical rotation commits this node has not yet applied — §3.3.
    ///
    /// This is the other half of putting commits in the log: a member that syncs
    /// a rotation entry must actually process its commit, or its MLS state falls
    /// behind the network's and it derives the wrong epoch key from that point
    /// on. Called after a sync, and idempotent — a commit already applied is
    /// skipped by the keyring rather than reapplied.
    ///
    /// Commits are applied in canonical chain order, which is the ordering the
    /// log exists to supply in place of a Delivery Service.
    pub fn apply_pending_rotations(&mut self) -> Vec<Hash> {
        let Some(group) = self.group.as_mut() else {
            return Vec::new();
        };

        let mut applied = Vec::new();
        for hash in self.log.canonical_chain() {
            if self.keyring.holds(&hash) {
                continue;
            }
            let Some(entry) = self.log.get(&hash) else {
                continue;
            };
            let EntryBody::EpochRotation { commit, .. } = &entry.body else {
                continue;
            };
            // A commit this node authored was merged when it was produced, so it
            // cannot be applied a second time; the keyring check above covers
            // that case, and anything reaching here is genuinely another
            // member's. A commit that will not apply is skipped rather than
            // fatal: it may belong to a branch this node cannot reach from its
            // current MLS state, which reconciliation resolves by re-welcome.
            if let Ok(key) = group.apply_commit(commit) {
                let epoch = group.epoch();
                self.keyring.record(hash, epoch, key);
                applied.push(hash);
            }
        }
        applied
    }

    /// Reconciles held epoch keys against the log — §3.3, §2.7.1.
    ///
    /// Reports what became final, what was voided, and whether this node needs a
    /// re-welcome because the rotation it was operating under lost.
    pub fn reconcile_epoch_keys(&mut self) -> KeyringReconciliation {
        self.keyring.reconcile(&self.log)
    }

    /// Accepts a Welcome, joining this node to the network's group.
    ///
    /// Split out from the event loop for the same reason [`Self::answer_epoch_key`]
    /// is: it consumes the pending key package, and a node that joined silently
    /// on an arriving message would have no way to refuse one it did not ask for.
    fn accept_welcome(
        &mut self,
        welcome: &[u8],
        rotation_ref: Hash,
        history: &[intranet_epoch::SealedEpochKey],
        sender: PerNetworkIdentityId,
    ) -> Result<(), EpochError> {
        let pending = self
            .pending_join
            .take()
            .ok_or_else(|| EpochError::Mls("no key package is outstanding".into()))?;

        let session = pending.join(welcome)?;
        let key = session.epoch_key()?;
        let epoch = session.epoch();

        // History first, so that `record` leaves the current rotation canonical
        // rather than an older delivered one.
        if !history.is_empty() {
            let keys = open_history(&self.identity.clone(), &sender, history)?;
            self.keyring.accept_delivered(keys)?;
        }
        self.keyring.record(rotation_ref, epoch, key);
        self.group = Some(session);
        Ok(())
    }

    /// This node's replica of the governance log.
    pub fn governance_log(&self) -> &GovernanceLog {
        &self.log
    }

    /// Adds a locally authored entry to the log.
    ///
    /// Deliberately *not* followed by a push to connected peers. The protocol is
    /// pull-based (§2.7, and see [`crate::sync`]): peers learn about this entry
    /// the next time they sync, which is on their next connection or their next
    /// [`Self::sync_with`]. Adding an eager push would create a second
    /// propagation path that only runs while peers happen to be connected, and
    /// the pull path would then be exercised far less often than it is relied
    /// on — precisely the arrangement in which a heal-time bug hides.
    pub fn append_entry(&mut self, entry: LogEntry) -> Result<Hash, GovernanceError> {
        self.log.insert(entry)
    }

    /// This node's cached view of the capability ledger — §4.5.
    ///
    /// The input to HRW replica placement and media-relay selection. Note what
    /// determinism this does and does not give: the *ranking function* is
    /// deterministic given a candidate set, but the candidate set is each node's
    /// own cache, which depends on what has propagated and on each node's local
    /// staleness judgment. Two nodes agree on placement once their ledgers
    /// agree, not before — which is why the repair loop (Storage Spec §3.4)
    /// exists rather than placement being assumed correct on first computation.
    pub fn capability_ledger(&self) -> &CapabilityLedger {
        &self.ledger
    }

    /// Publishes this node's own advertisement — §4.2.
    ///
    /// Inserted into this node's own ledger, from where peers pull it. Refusing
    /// an advertisement this node cannot validate against its own governance
    /// replica is deliberate: a node that cannot yet see itself as a member has
    /// no business claiming capacity, and silently accepting it locally would
    /// hide the fact that no peer will accept it either.
    pub fn advertise(
        &mut self,
        advertisement: CapabilityAdvertisement,
    ) -> Result<(), LedgerError> {
        let state = self.governance_state().ok_or(LedgerError::NotAMember {
            node: advertisement.node.short(),
        })?;
        self.ledger.insert(advertisement, &state)
    }

    /// Chunks this node holds and will serve — Storage Spec §4.2.
    pub fn chunk_store(&self) -> &ChunkStore {
        &self.chunks
    }

    /// Mutable access to the chunk store.
    ///
    /// For eviction, for pre-seeding a durability replica, and for tests that
    /// need to construct a peer behaving badly.
    pub fn chunk_store_mut(&mut self) -> &mut ChunkStore {
        &mut self.chunks
    }

    /// Stores locally produced content, joining its swarm.
    ///
    /// There is no separate "start serving" step: §4.2 makes swarm membership
    /// automatic for any node holding the bytes, whether it published them,
    /// was assigned them as a durability replica, or simply viewed the content.
    /// Announcing to the DHT is part of that, not a further opt-in — a node that
    /// holds bytes but never says so is in the swarm in name only.
    pub fn store_chunk(&mut self, bytes: Vec<u8>) -> Cid {
        let cid = self.chunks.put(bytes);
        self.announce_chunk(cid);
        cid
    }

    /// Forces this node to serve DHT queries, rather than only issuing them.
    ///
    /// libp2p keeps Kademlia in client mode until the node has a *confirmed*
    /// external address, on the sound reasoning that a node nobody can dial
    /// makes a poor DHT server. That default is right in production and has a
    /// consequence worth knowing: a member behind NAT stays a client, and the
    /// nodes actually holding provider records are the ones with public
    /// addresses — which is exactly why [`RelayNode`] runs Kademlia too, as §5.5
    /// describes, serving as the rendezvous point for the members around it.
    ///
    /// It also means that on a network with **no** publicly addressable node —
    /// a LAN, or a test on loopback — nothing ever confirms an external address,
    /// every node stays a client, and the DHT answers every provider query with
    /// "nobody". That is indistinguishable from content genuinely having no
    /// holders, which is why this exists rather than leaving callers to discover
    /// it.
    pub fn set_dht_server_mode(&mut self, enabled: bool) {
        self.swarm.behaviour_mut().kad.set_mode(Some(if enabled {
            kad::Mode::Server
        } else {
            kad::Mode::Client
        }));
    }

    /// Announces that this node holds `cid` — §4.4 step 1.
    ///
    /// Failure is logged rather than returned: Kademlia refuses to start
    /// providing when it has no peers to publish to, which on a node that has
    /// not yet connected to anything is ordinary rather than exceptional. The
    /// announcement is retried whenever the chunk is stored again.
    pub fn announce_chunk(&mut self, cid: Cid) {
        if let Err(error) = self
            .swarm
            .behaviour_mut()
            .kad
            .start_providing(provider_key(&cid))
        {
            tracing::debug!(cid = %cid.short(), %error, "could not announce chunk yet");
        }
    }

    /// Stops announcing `cid`, and drops it.
    ///
    /// Both together, because they are the same event: §4.2 makes holding the
    /// bytes the whole of swarm membership.
    ///
    /// **Withdrawal is not immediate, and cannot be.** Kademlia has no
    /// un-publish: this drops the local record and stops republishing, but
    /// copies already pushed to other peers persist until they expire. So this
    /// node keeps being advertised for a while after it has stopped holding
    /// anything, and provider records are a hint rather than a promise. That is
    /// why a request for a chunk this node does not hold answers
    /// [`ChunkResponse::NotHeld`] explicitly and why that outcome counts against
    /// nobody — following a stale record has to cost a requester one round trip
    /// and nothing more.
    pub fn forget_chunk(&mut self, cid: &Cid) -> Option<Vec<u8>> {
        self.swarm
            .behaviour_mut()
            .kad
            .stop_providing(&provider_key(cid));
        self.chunks.remove(cid)
    }

    /// Sends a signed signalling message to a participant — §1.4.
    pub fn send_signal(
        &mut self,
        to: PerNetworkIdentityId,
        sender: &PerNetworkIdentity,
        body: SignalBody,
    ) -> request_response::OutboundRequestId {
        self.swarm
            .behaviour_mut()
            .signal
            .send_request(&to.peer_id(), Signal::create(sender, body))
    }

    /// Sends one media frame — §2.2.
    ///
    /// `via` is the node that should receive the envelope: the recipient
    /// themselves in a mesh call, or the relay in a relayed one. The envelope's
    /// `to` field is the participant it is ultimately for, which is what lets
    /// the relay forward without the sender needing a different message shape
    /// for the two topologies.
    pub fn send_media(
        &mut self,
        via: PerNetworkIdentityId,
        envelope: MediaEnvelope,
    ) -> request_response::OutboundRequestId {
        self.swarm
            .behaviour_mut()
            .media
            .send_request(&via.peer_id(), envelope)
    }

    /// Agrees to relay media for a call — §2.2.
    ///
    /// The participant set is the entirety of what a relay is told. It exists so
    /// the relay can refuse to forward to a non-participant, which stops a relay
    /// being used as an open reflector; it is not, and must not become, a place
    /// to accumulate anything about the call's content.
    pub fn relay_call(
        &mut self,
        call: CallId,
        participants: impl IntoIterator<Item = PerNetworkIdentityId>,
    ) {
        self.relayed_calls
            .insert(call, participants.into_iter().collect());
    }

    /// Stops relaying a call.
    pub fn stop_relaying(&mut self, call: &CallId) {
        self.relayed_calls.remove(call);
    }

    /// Whether this node is relaying `call`.
    pub fn is_relaying(&self, call: &CallId) -> bool {
        self.relayed_calls.contains_key(call)
    }

    /// Publishes an entry into an append-set collection — Storage Spec §2.5.
    ///
    /// Stores the payload locally and announces this node as a provider of the
    /// collection. Nothing is overwritten and no conflict resolution is needed:
    /// independent publishers' entries simply coexist as separate announcements
    /// under the same key, which is the whole reason the primitive is built on
    /// provider records rather than on writing to a shared value.
    ///
    /// The same entry may be published into several collections — a search
    /// posting is announced under every term it matched (Search Spec §3.1),
    /// built and signed once and announced many times.
    pub fn publish_to_collection(&mut self, collection_id: Hash, entry_id: Hash, payload: Vec<u8>) {
        self.collections
            .entry(collection_id)
            .or_default()
            .insert(entry_id, payload);
        if let Err(error) = self
            .swarm
            .behaviour_mut()
            .kad
            .start_providing(kad::RecordKey::new(&collection_id.as_bytes()))
        {
            tracing::debug!(%error, "could not announce collection yet");
        }
    }

    /// Entries this node holds for a collection.
    pub fn collection_entries(&self, collection_id: &Hash) -> Vec<&[u8]> {
        self.collections
            .get(collection_id)
            .map(|entries| entries.values().map(Vec::as_slice).collect())
            .unwrap_or_default()
    }

    /// Enumerates a collection across the network — Storage Spec §2.5.
    ///
    /// Finds the collection's providers via the DHT and asks each for its
    /// entries. Results arrive as [`NodeEvent::CollectionEnumerated`].
    ///
    /// **Best-effort by design, not by accident.** §2.5 is explicit that real
    /// Kademlia implementations cap providers per key, so a popular collection
    /// may not be fully enumerable in one pass. That is acceptable where partial
    /// discovery is the actual requirement — search — and unacceptable where a
    /// missing entry means a wrong answer rather than a shorter list, which is
    /// why name ownership anchors elsewhere (App Hosting Spec §4.3).
    pub fn enumerate_collection(&mut self, collection_id: Hash) -> kad::QueryId {
        let id = self
            .swarm
            .behaviour_mut()
            .kad
            .get_providers(kad::RecordKey::new(&collection_id.as_bytes()));
        self.collection_queries
            .insert(id, (collection_id, std::collections::BTreeSet::new()));
        id
    }

    /// Asks one provider for its entries in a collection.
    ///
    /// Separate from [`enumerate_collection`](Self::enumerate_collection)
    /// because §2.5 makes enumeration two steps — find the providers, then ask
    /// them — and a caller may reasonably ask only some of them, which is the
    /// difference between a cheap search and one that contacts every node
    /// announcing a popular term.
    pub fn request_collection(
        &mut self,
        peer: PeerId,
        collection_id: Hash,
        requester: &PerNetworkIdentity,
    ) -> request_response::OutboundRequestId {
        let id = self.swarm.behaviour_mut().collection.send_request(
            &peer,
            CollectionRequest::create(requester, collection_id),
        );
        self.collection_requests.insert(id, collection_id);
        id
    }

    /// Answers a peer's enumeration request, applying the same gate as content.
    fn serve_collection(&self, request: &CollectionRequest) -> CollectionResponse {
        let Some(state) = self.governance_state() else {
            return CollectionResponse::Refused {
                reason: ChunkRefusal::CannotEvaluate,
            };
        };
        if may_serve(&request.requester, &state).is_err() {
            return CollectionResponse::Refused {
                reason: ChunkRefusal::NoReadContent,
            };
        }
        let held = self.collection_entries(&request.collection_id);
        let truncated = held.len() > MAX_COLLECTION_ENTRIES;
        CollectionResponse::Entries {
            payloads: held
                .into_iter()
                .take(MAX_COLLECTION_ENTRIES)
                .map(<[u8]>::to_vec)
                .collect(),
            truncated,
        }
    }

    /// Fetches chunks from the swarm — Storage Spec §4.4, end to end.
    ///
    /// Queries the DHT for holders of each chunk not already held, orders them
    /// rarest-first, selects a source per chunk by the §4.3 criteria, and keeps
    /// several requests outstanding at once. Failures retry against the next
    /// holder. Completion is reported as [`NodeEvent::FetchComplete`].
    ///
    /// Chunks already in the store are skipped rather than re-fetched — the
    /// point of §4.2's automatic swarm membership is that holding the bytes
    /// already is the common case for anything popular.
    ///
    /// Calling this while a fetch is running extends it, so the concurrency
    /// limit bounds everything this node is pulling rather than each call
    /// separately.
    pub fn fetch_chunks(
        &mut self,
        cids: impl IntoIterator<Item = Cid>,
        requester: &PerNetworkIdentity,
        concurrency: usize,
    ) {
        let wanted: Vec<Cid> = cids
            .into_iter()
            .filter(|cid| !self.chunks.has(cid))
            .collect();
        for cid in &wanted {
            self.fetch_requests
                .entry(*cid)
                .or_insert_with(|| ChunkRequest::create(requester, *cid));
        }
        match &mut self.fetch {
            Some(plan) => plan.extend(wanted),
            None => self.fetch = Some(FetchPlan::new(wanted, concurrency)),
        }
        for cid in self
            .fetch
            .as_ref()
            .map(FetchPlan::providers_needed)
            .unwrap_or_default()
        {
            self.find_providers(cid);
        }
        self.drive_fetch();
    }

    /// Issues whatever the plan says to issue next.
    fn drive_fetch(&mut self) {
        let Some(plan) = &mut self.fetch else {
            return;
        };
        let next = plan.next_requests();
        for (cid, source) in next {
            let Some(request) = self.fetch_requests.get(&cid).cloned() else {
                continue;
            };
            self.send_chunk_request(source, request);
        }
    }

    /// Records a chunk outcome against the running plan and issues what is next.
    ///
    /// Every outcome feeds the plan, including refusals and not-helds. A plan
    /// that only heard about verification failures would leave a chunk in flight
    /// forever whenever a holder simply had nothing to give, and the fetch would
    /// never complete.
    fn note_fetch_outcome(&mut self, cid: Cid, received: bool) {
        let Some(plan) = &mut self.fetch else {
            return;
        };
        if received {
            plan.record_received(cid);
        } else {
            plan.record_failed(cid);
        }
        self.drive_fetch();
        if let Some(done) = self.completed_fetch() {
            // Buffered rather than returned, because this is called from an arm
            // that is about to return the chunk outcome itself and only one
            // event can be returned at a time.
            //
            // **Every caller must return immediately after calling this.**
            // `next_swarm_event` drains `pending` only on entry, so an event
            // buffered here is delivered on the *next* call — which never comes
            // if the loop simply continues and nothing else happens. The
            // collection provider path was written that way at first and hung
            // exactly like that.
            self.pending.push_back(done);
        }
    }

    /// Takes the completion event if the fetch has just finished.
    fn completed_fetch(&mut self) -> Option<NodeEvent> {
        let plan = self.fetch.as_ref()?;
        if !plan.is_complete() {
            return None;
        }
        let event = NodeEvent::FetchComplete {
            received: plan.received(),
            unavailable: plan.unavailable(),
        };
        self.fetch = None;
        self.fetch_requests.clear();
        Some(event)
    }

    /// Whether a fetch is running.
    pub fn fetch_in_progress(&self) -> bool {
        self.fetch.as_ref().is_some_and(|plan| !plan.is_complete())
    }

    /// Asks the DHT who holds `cid` — §4.4 step 1.
    ///
    /// Results arrive as [`NodeEvent::ProvidersFound`], which also carries the
    /// holder count rarest-first ordering needs.
    pub fn find_providers(&mut self, cid: Cid) -> kad::QueryId {
        let id = self
            .swarm
            .behaviour_mut()
            .kad
            .get_providers(provider_key(&cid));
        self.provider_queries
            .insert(id, (cid, std::collections::BTreeSet::new()));
        id
    }

    /// This node's own verification observations — Core Protocol Spec §4.6.
    ///
    /// Local-only, never gossiped, and usable only for local per-requester
    /// decisions such as source selection. Exposed read-only because there is no
    /// legitimate reason for anything outside this node to write to it.
    pub fn reliability_observations(&self) -> &ReliabilityObservations {
        &self.observations
    }

    /// Requests one chunk from a peer.
    ///
    /// `requester` signs the request, and is passed in rather than held by the
    /// node because §1.3 has a per-network private key derived in memory for an
    /// operation rather than kept live for the process lifetime. The signature
    /// is what lets the serving node evaluate `read-content` (§5.4) against a
    /// requester it can be sure actually asked.
    /// The source is named by *identity* rather than by PeerId because that is
    /// what selection produces — `select_sources` ranks capability ledger
    /// entries, which are keyed by identity — and because a verification failure
    /// has to be recorded against an identity (§4.6). Taking a PeerId here would
    /// mean the caller resolving it one way and this node resolving it back
    /// another, with nothing keeping the two in step.
    pub fn request_chunk(
        &mut self,
        source: PerNetworkIdentityId,
        cid: Cid,
        requester: &PerNetworkIdentity,
    ) -> request_response::OutboundRequestId {
        self.send_chunk_request(source, ChunkRequest::create(requester, cid))
    }

    /// Sends a prepared request and remembers what it was for.
    fn send_chunk_request(
        &mut self,
        source: PerNetworkIdentityId,
        request: ChunkRequest,
    ) -> request_response::OutboundRequestId {
        let peer = source.peer_id();
        let cid = request.cid;
        let id = self
            .swarm
            .behaviour_mut()
            .chunk
            .send_request(&peer, request);
        // Remembered because the response carries bytes but not the identifier
        // they were requested under, and verifying arriving bytes against an
        // identifier derived from those same bytes would verify nothing.
        self.inflight.insert(id, (peer, source, cid));
        id
    }

    // -----------------------------------------------------------------------
    // The join handshake — Core Protocol Spec §5.6–5.7, §2.4
    // -----------------------------------------------------------------------

    /// Identities awaiting explicit admission on this node — §2.4.
    pub fn waiting_room(&self) -> &WaitingRoom {
        &self.waiting_room
    }

    /// The waiting room as `requester` is entitled to see it — §2.4.
    ///
    /// `None` when they hold no `manage-membership:everyone`. Exposing the queue
    /// more widely would leak who is trying to join to members who could do
    /// nothing about it, and the capability that gates it is the one that lets
    /// somebody actually act on what they see.
    pub fn waiting_room_for(
        &self,
        requester: &PerNetworkIdentityId,
    ) -> Option<Vec<&WaitingRoomEntry>> {
        let state = self.governance_state()?;
        self.waiting_room
            .visible_to(requester, &state)
            .then(|| self.waiting_room.occupants())
    }

    /// Presents an invite to a member, asking to join — §5.6.
    pub fn request_join(
        &mut self,
        member: PerNetworkIdentityId,
        invite: Invite,
        identity: &PerNetworkIdentity,
    ) -> request_response::OutboundRequestId {
        let request = JoinRequest::create(identity, invite);
        let id = self
            .swarm
            .behaviour_mut()
            .join
            .send_request(&member.peer_id(), request);
        self.join_requests.insert(id, member);
        id
    }

    /// Answers a join this node accepted for consideration — §2.4, §5.6.
    ///
    /// Validates the invite against replayed governance state and the supplied
    /// clock, then branches on the network's admission mode. Under auto-admit
    /// this appends the `MembershipChange` that grants `everyone`; under
    /// explicit intake it records a waiting-room place and grants nothing.
    ///
    /// Deliberately does **not** deliver an epoch key in either case. §5.7 says
    /// an invite's job ends at the first connection, so a newly admitted member
    /// asks for a key over the ordinary delivery protocol — the same path a
    /// re-welcome uses, rather than a join-time special case exercised once per
    /// node lifetime.
    pub fn answer_join(
        &mut self,
        request: JoinRequestId,
        identity: &PerNetworkIdentity,
        now: Timestamp,
    ) -> Result<JoinResponse, TransportError> {
        let (request, channel) = self
            .inbound_joins
            .remove(&request)
            .ok_or_else(|| TransportError::Dial("no such pending join".into()))?;

        let response = self.decide_join(&request, identity, now);
        let _ = self
            .swarm
            .behaviour_mut()
            .join
            .send_response(channel, response.clone());
        Ok(response)
    }

    /// Refuses a join without evaluating it further.
    pub fn decline_join(&mut self, request: JoinRequestId, reason: JoinRefusal) {
        if let Some((_, channel)) = self.inbound_joins.remove(&request) {
            let _ = self
                .swarm
                .behaviour_mut()
                .join
                .send_response(channel, JoinResponse::Refused { reason });
        }
    }

    /// Works out what a validated join should produce.
    fn decide_join(
        &mut self,
        request: &JoinRequest,
        identity: &PerNetworkIdentity,
        now: Timestamp,
    ) -> JoinResponse {
        let Some(state) = self.governance_state() else {
            return JoinResponse::Refused {
                reason: JoinRefusal::CannotEvaluate,
            };
        };

        // One refusal for every way an invite can fail to validate. A joiner
        // acts on all of them identically — get a better invite — while
        // distinguishing them would let anyone holding a rejected invite probe
        // governance state through the refusals.
        let Ok(provenance) = request.invite.validate(&request.joiner, &state, now) else {
            return JoinResponse::Refused {
                reason: JoinRefusal::InviteInvalid,
            };
        };

        match state.policy.admission_mode {
            AdmissionMode::AutoAdmit => {
                let entry = LogEntry::create(
                    identity,
                    self.log.canonical_chain().last().copied(),
                    now,
                    EntryBody::MembershipChange {
                        group: GroupId::everyone(),
                        identity: request.joiner,
                        action: MembershipAction::Add {
                            via_invite: Some(provenance),
                        },
                    },
                );
                match self.log.insert(entry) {
                    Ok(hash) => {
                        self.waiting_room.remove(&request.joiner);
                        JoinResponse::Admitted { entry: hash }
                    }
                    // The commonest cause is this node not holding
                    // `manage-membership:everyone`. Refusing is right: an
                    // auto-admit network still requires the *admitting* node to
                    // be authorized to admit, and a joiner should try a member
                    // who is.
                    Err(_) => JoinResponse::Refused {
                        reason: JoinRefusal::CannotEvaluate,
                    },
                }
            }
            AdmissionMode::ExplicitIntake => {
                self.waiting_room
                    .admit_to_waiting(request.joiner, provenance, now);
                JoinResponse::Waiting
            }
        }
    }

    // -----------------------------------------------------------------------
    // Mutable pointer distribution — Storage Spec §2.2, §5.3
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Ballot collection — Core Protocol Spec §2.6.1
    // -----------------------------------------------------------------------

    /// Ballots this node holds for a vote.
    pub fn ballots_for(&self, vote_id: &Hash) -> Vec<&Ballot> {
        self.ballots
            .get(vote_id)
            .map(|by_hash| by_hash.values().collect())
            .unwrap_or_default()
    }

    /// Casts this node's own ballot and records it — §2.6.1, point 2.
    ///
    /// Recorded locally rather than pushed: peers collect it by asking, which is
    /// what lets a certificate be assembled later from ballots cast earlier.
    pub fn cast_ballot(
        &mut self,
        vote_id: Hash,
        approve: bool,
        now: Timestamp,
        identity: &PerNetworkIdentity,
    ) -> Result<Ballot, GovernanceError> {
        let ballot = Ballot::cast(identity, vote_id, approve, now);
        if !self.record_ballot(ballot.clone()) {
            return Err(GovernanceError::InvalidQuorumCertificate {
                reason: "this node knows of no open vote matching that ballot".into(),
            });
        }
        Ok(ballot)
    }

    /// Records a ballot, if it qualifies for a vote this node knows is open.
    ///
    /// Every check that can be made from replayed state is made here, because a
    /// collection is only useful if what it holds can go into a certificate: the
    /// signature, that the vote is open, that the voter is in *that vote's*
    /// frozen electorate, and that the ballot was cast at or before close. A
    /// collection that accepted anything would hand an assembler ballots that
    /// make the certificate they build invalid.
    pub fn record_ballot(&mut self, ballot: Ballot) -> bool {
        if ballot.verify().is_err() {
            return false;
        }
        let Some(state) = self.governance_state() else {
            return false;
        };
        let Some(proposal) = state.open_votes.get(&ballot.vote_id) else {
            return false;
        };
        if !proposal.electorate_snapshot.contains(&ballot.voter)
            || ballot.cast_at > proposal.close_time
        {
            return false;
        }
        self.ballots
            .entry(ballot.vote_id)
            .or_default()
            .insert(ballot.hash(), ballot);
        true
    }

    /// Asks a peer for ballots this node does not hold — §2.6.1.
    pub fn sync_ballots_with(
        &mut self,
        peer: PeerId,
        vote_id: Hash,
    ) -> request_response::OutboundRequestId {
        let have: Vec<Hash> = self
            .ballots
            .get(&vote_id)
            .map(|by_hash| by_hash.keys().copied().collect())
            .unwrap_or_default();
        let request = BallotRequest::create(&self.identity.clone(), vote_id, have);
        let id = self
            .swarm
            .behaviour_mut()
            .ballot
            .send_request(&peer, request);
        self.ballot_requests.insert(id, vote_id);
        id
    }

    /// Asks a peer for ballots on every vote this node knows is open.
    ///
    /// Which votes exist is answered by the log, not by the peer — proposals are
    /// entries — so there is no digest to exchange first.
    pub fn sync_open_votes_with(&mut self, peer: PeerId) -> usize {
        let Some(state) = self.governance_state() else {
            return 0;
        };
        let open: Vec<Hash> = state.open_votes.keys().copied().collect();
        for vote_id in &open {
            self.sync_ballots_with(peer, *vote_id);
        }
        open.len()
    }

    /// Assembles a certificate from the ballots collected for a vote — §2.6.1.
    ///
    /// `None` when this node knows of no such open vote. A certificate that does
    /// not reach quorum is still returned: whether it passes is the *verifier's*
    /// question, and hiding a short certificate here would make "no certificate"
    /// mean both "the vote failed" and "I did not build one".
    pub fn assemble_certificate(&self, vote_id: &Hash) -> Option<QuorumCertificate> {
        let state = self.governance_state()?;
        let proposal = state.open_votes.get(vote_id)?;
        Some(QuorumCertificate::assemble(
            proposal,
            self.ballots_for(vote_id).into_iter().cloned(),
        ))
    }

    /// Answers a peer's ballot request.
    fn serve_ballots(&self, request: &BallotRequest) -> BallotResponse {
        let Some(state) = self.governance_state() else {
            return BallotResponse::Refused {
                reason: BallotRefusal::CannotEvaluate,
            };
        };
        if !state.is_member(&request.requester) {
            return BallotResponse::Refused {
                reason: BallotRefusal::NotAMember,
            };
        }
        if !state.open_votes.contains_key(&request.vote_id) {
            return BallotResponse::Refused {
                reason: BallotRefusal::UnknownVote,
            };
        }

        let have: std::collections::BTreeSet<Hash> = request.have.iter().copied().collect();
        let mut ballots: Vec<Ballot> = self
            .ballots
            .get(&request.vote_id)
            .map(|by_hash| {
                by_hash
                    .iter()
                    .filter(|(hash, _)| !have.contains(*hash))
                    .map(|(_, ballot)| ballot.clone())
                    .collect()
            })
            .unwrap_or_default();
        let truncated = ballots.len() > MAX_BALLOTS_PER_RESPONSE;
        ballots.truncate(MAX_BALLOTS_PER_RESPONSE);
        BallotResponse::Ballots { ballots, truncated }
    }

    /// A pointer's current record, if this node holds one.
    pub fn pointer(&self, pointer_id: &PointerId) -> Option<&MutablePointer> {
        self.pointers.get(pointer_id)
    }

    /// Every pointer this node holds.
    pub fn pointers(&self) -> impl Iterator<Item = &MutablePointer> {
        self.pointers.values()
    }

    /// Wrappings held for a pointer, by rotation.
    pub fn wrappings_for(&self, pointer_id: &PointerId) -> Vec<&DekWrapping> {
        self.wrappings
            .get(pointer_id)
            .map(|by_rotation| by_rotation.values().collect())
            .unwrap_or_default()
    }

    /// The wrapping for a pointer under a specific rotation, if held.
    pub fn wrapping_under(
        &self,
        pointer_id: &PointerId,
        rotation_ref: &Hash,
    ) -> Option<&DekWrapping> {
        self.wrappings.get(pointer_id)?.get(rotation_ref)
    }

    /// Accepts a pointer record, keeping whichever record wins — §2.2.
    ///
    /// Returns whether this node's view changed. The resolution rule is the
    /// primitive's own: a higher version supersedes outright, and two records
    /// claiming the *same* version are settled by lower record hash — the same
    /// deterministic tie-break sibling governance entries use, so every node
    /// holding both reaches the same answer regardless of arrival order.
    ///
    /// Records failing validation are refused rather than stored, so nothing
    /// unusable can be served on. Validation is [`Self::pointer_is_publishable`].
    pub fn accept_pointer(&mut self, pointer: MutablePointer) -> bool {
        if !self.pointer_is_publishable(&pointer) {
            return false;
        }
        match self.pointers.get(&pointer.pointer_id) {
            Some(current) if !pointer.supersedes(current) => false,
            _ => {
                self.pointers.insert(pointer.pointer_id, pointer);
                true
            }
        }
    }

    /// Accepts a DEK wrapping — §5.3.
    ///
    /// Any current member may publish one, so this checks membership and the
    /// wrapper's signature rather than ownership. What makes a wrapping
    /// *usable* is that it unwraps to the owner's committed DEK, which only a
    /// holder of the relevant epoch key can check and which is therefore left to
    /// whoever opens it — storing an unusable wrapping costs a little space and
    /// is corrected by the next re-wrap, whereas refusing one this node cannot
    /// yet check would drop wrappings for rotations it has not caught up to.
    pub fn accept_wrapping(&mut self, wrapping: DekWrapping) -> bool {
        if wrapping.verify_signature().is_err() {
            return false;
        }
        let Some(state) = self.governance_state() else {
            return false;
        };
        if !state.is_member(&wrapping.wrapper_identity) {
            return false;
        }
        self.wrappings
            .entry(wrapping.pointer_id)
            .or_default()
            .insert(wrapping.rotation_ref, wrapping);
        true
    }

    /// Whether a pointer record may be stored and served here — §2.8, §2.2.
    ///
    /// Both publish gates, re-checked against this node's own replayed state.
    /// §2.2 is explicit that either check failing means the publish is "rejected
    /// outright by receiving/replicating nodes, fail-closed and protocol-enforced,
    /// not merely conventional" — so a receiving node re-derives them rather than
    /// trusting that the publisher checked.
    ///
    /// Delisted pointers are refused too. §3.4 of App Hosting defines delisting
    /// as stopping content being "servable and surfaced", and a node that stored
    /// and re-served a delisted record would leave moderation effective only
    /// against nodes that happened to be listening at the time.
    fn pointer_is_publishable(&self, pointer: &MutablePointer) -> bool {
        if pointer.verify().is_err() {
            return false;
        }
        let Some(state) = self.governance_state() else {
            return false;
        };
        if state.delisted.contains(&pointer.pointer_id) {
            return false;
        }
        state.allows_content_type(&pointer.content_type)
            && state.identity_holds(
                &pointer.owner_identity,
                &intranet_governance::Capability::Publish(pointer.content_type.clone()),
            )
    }

    /// Asks a peer what pointers it holds, starting a pointer sync — §2.2.
    ///
    /// Pull-based like the governance log: a pointer published during a
    /// partition arrives on heal because the far side asks for it, not because
    /// anybody replays an announcement nobody heard.
    pub fn sync_pointers_with(&mut self, peer: PeerId) -> request_response::OutboundRequestId {
        let request = PointerRequest::digest(&self.identity.clone());
        let id = self
            .swarm
            .behaviour_mut()
            .pointer
            .send_request(&peer, request);
        self.pointer_digests.insert(id, peer);
        id
    }

    /// Asks a peer for specific pointer records and their wrappings.
    pub fn request_pointers(
        &mut self,
        peer: PeerId,
        wanted: Vec<PointerId>,
    ) -> request_response::OutboundRequestId {
        let request = PointerRequest::fetch(&self.identity.clone(), wanted);
        let id = self
            .swarm
            .behaviour_mut()
            .pointer
            .send_request(&peer, request);
        self.pointer_fetches.insert(id, peer);
        id
    }

    /// Answers a peer's pointer request, applying the §5.4 serving gate.
    fn serve_pointers(&self, request: &PointerRequest) -> PointerResponse {
        // Gated before anything is consulted, so a refusal never depends on what
        // this node happens to hold. The digest is gated as tightly as the
        // records: a digest is a list of everything published, which is the
        // content graph itself, and handing it to a waiting-room identity would
        // disclose the shape of a network's contents to somebody §2.4 promises
        // essentially nothing.
        let Some(state) = self.governance_state() else {
            return PointerResponse::Refused {
                reason: PointerRefusal::CannotEvaluate,
            };
        };
        if may_serve(request.requester(), &state).is_err() {
            return PointerResponse::Refused {
                reason: PointerRefusal::NoReadContent,
            };
        }

        match request {
            PointerRequest::Digest { .. } => {
                let mut entries: Vec<PointerDigestEntry> = self
                    .pointers
                    .values()
                    .filter(|pointer| !state.delisted.contains(&pointer.pointer_id))
                    .map(|pointer| PointerDigestEntry {
                        pointer_id: pointer.pointer_id,
                        version: pointer.version,
                        record_hash: pointer.record_hash(),
                    })
                    .collect();
                let truncated = entries.len() > MAX_POINTERS_PER_RESPONSE;
                entries.truncate(MAX_POINTERS_PER_RESPONSE);
                PointerResponse::Digest { entries, truncated }
            }
            PointerRequest::Fetch { wanted, .. } => {
                let mut records: Vec<PointerRecord> = wanted
                    .iter()
                    .filter(|id| !state.delisted.contains(*id))
                    .filter_map(|id| {
                        let pointer = self.pointers.get(id)?;
                        Some(PointerRecord {
                            pointer: pointer.clone(),
                            wrappings: self
                                .wrappings
                                .get(id)
                                .map(|by_rotation| by_rotation.values().cloned().collect())
                                .unwrap_or_default(),
                        })
                    })
                    .collect();
                let truncated = records.len() > MAX_POINTERS_PER_RESPONSE;
                records.truncate(MAX_POINTERS_PER_RESPONSE);
                PointerResponse::Records { records, truncated }
            }
        }
    }

    /// Which of a peer's digest entries are worth fetching.
    ///
    /// Anything unknown, anything at a higher version, and — the case a
    /// version-only comparison misses — anything at the *same* version with a
    /// different record hash. That last one is a genuine same-version fork
    /// (§2.2), and skipping it would leave two nodes permanently disagreeing
    /// while each believed it was up to date.
    fn pointers_worth_fetching(&self, entries: &[PointerDigestEntry]) -> Vec<PointerId> {
        entries
            .iter()
            .filter(|entry| match self.pointers.get(&entry.pointer_id) {
                None => true,
                Some(held) => {
                    entry.version > held.version
                        || (entry.version == held.version
                            && entry.record_hash != held.record_hash())
                }
            })
            .map(|entry| entry.pointer_id)
            .collect()
    }

    /// Applies every §5.6 check this node can make without a clock.
    fn screen_join(&self, request: &JoinRequest, peer: PeerId) -> Result<(), JoinRefusal> {
        // A signed request proves the named joiner asked; it does not prove the
        // peer delivering it is that joiner. This is the outermost door in the
        // protocol, so the binding matters more here than anywhere else.
        if request.joiner.peer_id() != peer {
            return Err(JoinRefusal::NotConnectionOwner);
        }

        let Some(state) = self.governance_state() else {
            return Err(JoinRefusal::CannotEvaluate);
        };
        if state.is_member(&request.joiner) {
            return Err(JoinRefusal::AlreadyMember);
        }

        // §5.3's per-invite scoping. A waiting-room identity is free to mint
        // under a bearer or multi-use invite, so per-identity limits meter
        // nothing in this window — the invite is the scarce resource.
        //
        // **Flagged: §5.3 requires per-invite scoping but gives no number.** The
        // ceiling is the invite's own *remaining* uses rather than an invented
        // constant: an invite that can admit no more members has no legitimate
        // reason to accumulate further pre-admission arrivals, and deriving the
        // bound from the credential keeps it correct for a one-use invite and a
        // hundred-use invite without tuning either.
        let invite_id = request.invite.invite_id();
        let used = state.invite_use_count(&invite_id);
        let remaining = (request.invite.max_uses as usize).saturating_sub(used);
        if self.waiting_room.arrivals_for_invite(&invite_id) >= remaining {
            return Err(JoinRefusal::InviteCeiling);
        }

        Ok(())
    }

    /// Applies every §3.5 check this node can make on its own.
    ///
    /// Ordered so that a refusal never depends on state a requester could probe
    /// for: the gate is evaluated before the group is consulted, so "no group"
    /// cannot be used to learn whether this node holds keys it will not hand
    /// over.
    fn screen_epoch_request(
        &self,
        request: &EpochKeyRequest,
        peer: PeerId,
    ) -> Result<(), KeyDeliveryRefusal> {
        // The signature was verified during decoding, so the named requester
        // really did ask. That does not establish that the peer delivering it is
        // that requester — a signed request is replayable by anyone who captured
        // it, and here the prize is key material rather than a chunk.
        if request.requester.peer_id() != peer {
            return Err(KeyDeliveryRefusal::NoReadContent);
        }

        let Some(state) = self.governance_state() else {
            return Err(KeyDeliveryRefusal::CannotEvaluate);
        };
        if may_serve(&request.requester, &state).is_err() {
            return Err(KeyDeliveryRefusal::NoReadContent);
        }

        // Binds the MLS credential to the per-network identity. Without it a
        // member could present a package built under someone else's label and be
        // welcomed into the group as them.
        match key_package_identity(&request.key_package) {
            Ok(label) if label == identity_label(&request.requester) => {}
            Ok(_) => return Err(KeyDeliveryRefusal::IdentityMismatch),
            Err(_) => return Err(KeyDeliveryRefusal::IdentityMismatch),
        }

        if self.group.is_none() {
            return Err(KeyDeliveryRefusal::NoGroup);
        }
        Ok(())
    }

    /// Answers a peer's chunk request, applying the §5.4 serving gate.
    fn serve_chunk(&self, request: &ChunkRequest) -> ChunkResponse {
        // The gate is evaluated before the store is consulted, so a refusal
        // never depends on whether this node happens to hold the chunk — which
        // would otherwise turn "refused" into a probe for what a node has.
        let Some(state) = self.governance_state() else {
            return ChunkResponse::Refused {
                reason: ChunkRefusal::CannotEvaluate,
            };
        };
        if may_serve(&request.requester, &state).is_err() {
            return ChunkResponse::Refused {
                reason: ChunkRefusal::NoReadContent,
            };
        }
        match self.chunks.get(&request.cid) {
            Some(bytes) => ChunkResponse::Chunk {
                bytes: bytes.to_vec(),
            },
            None => ChunkResponse::NotHeld,
        }
    }

    /// Asks a peer what its ledger holds, starting a ledger sync.
    ///
    /// Runs automatically on every new connection, and again whenever a
    /// governance sync accepted anything — see the handler for why.
    pub fn sync_ledger_with(&mut self, peer: PeerId) {
        self.swarm
            .behaviour_mut()
            .ledger
            .send_request(&peer, LedgerRequest::Digest);
    }

    /// Replays the canonical governance chain, or `None` if it cannot be.
    ///
    /// `None` is ordinary rather than exceptional on a node that has not yet
    /// synced: an empty or partial log has no replayable state, and the ledger
    /// simply has nothing it can validate against until it does.
    fn governance_state(&self) -> Option<GovernanceState> {
        self.log.replay_canonical().ok()
    }

    /// Asks a peer for its branch tips, starting a sync.
    ///
    /// Runs automatically on every new connection, so this is only needed to
    /// re-sync an already-connected peer.
    pub fn sync_with(&mut self, peer: PeerId) {
        self.swarm
            .behaviour_mut()
            .sync
            .send_request(&peer, SyncRequest::Heads);
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
    /// Announces an address peers should use to reach this relay.
    ///
    /// # Why listening is not enough
    ///
    /// A relay normally promotes its own non-loopback listen addresses, which is
    /// right when the address the world uses is an address the relay is bound
    /// to. Behind a load balancer or TCP proxy it is not: the public host *and*
    /// port both differ from the container's, and nothing in the process can
    /// infer them. libp2p builds the address list it returns in a reservation
    /// from external addresses only, so without this a relay deployed behind a
    /// proxy hands clients its private container address — reservations are
    /// granted, circuits are unusable, and the health check reports ready
    /// throughout.
    ///
    /// Call it once per public address before listening.
    pub fn add_public_address(&mut self, address: Multiaddr) {
        self.swarm.add_external_address(address);
    }

    /// Listens on the dual-stack defaults — TCP and QUIC over IPv4 and IPv6.
    ///
    /// §5.1 requires both families and both transports. Binding all four is what
    /// gives two peers behind CGNAT a path at all: IPv6 needs no traversal, so
    /// a pair that can never hole-punch over IPv4 may still reach each other
    /// directly (§5.2).
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
        // Waiting for *any* listener is not enough. libp2p pairs a listener with
        // a dial only when **both** the address family and the loopback-ness
        // match, so a wait satisfied by a listener failing either test proceeds
        // while nothing the dial can actually use is registered.
        //
        // Both halves bite in practice, and differently:
        //
        // - loopback: a wildcard bind reports `127.0.0.1` before its routable
        //   interface, so a naive wait is satisfied by a listener that cannot
        //   serve a dial to a routable relay.
        // - family: a dual-stack node listens on IPv4 and IPv6, and they do not
        //   arrive together. Waiting on an IPv6 listener while dialling an IPv4
        //   relay registers nothing usable — which matters more as IPv6
        //   deployment grows, since dual-stack is the case where both are live
        //   at once and the race is real rather than theoretical.
        let want = AddressShape::of(&relay);
        let usable = |listeners: &std::collections::BTreeSet<Multiaddr>| {
            listeners
                .iter()
                .any(|address| AddressShape::of(address) == want)
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

    /// Waits until a relay has actually *granted* a reservation.
    ///
    /// Returns whether one was granted before [`RESERVATION_TIMEOUT`] elapsed.
    ///
    /// # Why a caller about to dial a circuit must await this
    ///
    /// [`MemberNode::reserve_via_relay`] only *starts* a reservation: it dials
    /// the relay and asks. Dialling a `/p2p-circuit` address before the answer
    /// arrives finds no transport willing to take it, and fails with "Failed to
    /// negotiate transport protocol(s)".
    ///
    /// That error is actively misleading about its own cause. It names the
    /// circuit address, so it reads as the relay being unsupported or
    /// unreachable rather than as having been asked too early; and it takes out
    /// tiers 2 and 3 together while tier 1 keeps working, so the node looks
    /// selectively broken rather than early.
    ///
    /// # Why this is separate from `reserve_via_relay`
    ///
    /// Waiting here means driving this node's swarm and no other. That is right
    /// when the relay is a different process, and wrong when a caller owns the
    /// relay too — an in-process test drives its nodes in one loop, so a peer
    /// that blocks internally waits for a grant from a relay that is not being
    /// polled, and deadlocks until the timeout. Keeping the wait opt-in lets
    /// such a caller drive every node itself, which is the only way it can work.
    ///
    /// Events observed while waiting are buffered and replayed, so a caller
    /// loses nothing by awaiting this.
    pub async fn await_reservation(&mut self) -> bool {
        let deadline = tokio::time::Instant::now() + RESERVATION_TIMEOUT;
        while self.circuit_listeners.is_empty() {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, self.next_swarm_event()).await {
                Ok(event) => self.pending.push_back(event),
                Err(_) => break,
            }
        }

        if self.circuit_listeners.is_empty() {
            // Not fatal, for the same reason as a missing direct listener: tier
            // 1 is unaffected, and a caller with a direct address to try should
            // not be refused because a relay was slow.
            tracing::warn!(
                "no relay reservation granted within {RESERVATION_TIMEOUT:?}; \
                 circuit dials will fail and tiers 2 and 3 are unavailable"
            );
            return false;
        }
        true
    }

    /// Drives the swarm, bypassing the replay buffer.
    async fn next_swarm_event(&mut self) -> NodeEvent {
        loop {
            let event = futures::StreamExt::select_next_some(&mut self.swarm).await;
            match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    // Circuit addresses are not local sockets, so they are not
                    // what port reuse can bind against.
                    if crate::dial::is_circuit(&address) {
                        self.circuit_listeners.insert(address.clone());
                    } else {
                        self.direct_listeners.insert(address.clone());
                    }
                    return NodeEvent::Listening(address);
                }

                SwarmEvent::ConnectionEstablished {
                    peer_id, endpoint, ..
                } => {
                    let address = endpoint.get_remote_address().clone();
                    let tier = classify(&address);
                    // Tier 2 is defined by what happened to the *connection* —
                    // §5.2: a relayed connection that became direct — not by
                    // which peer's dial won the race to make it so.
                    //
                    // DCUtR's own event reports only *our* dial's fate, and both
                    // peers dial simultaneously. If theirs lands first ours is
                    // reported as failed, or the direct connection simply arrives
                    // before the event does; either way, attributing tier from
                    // that event alone reports a successful upgrade as tier 1 and
                    // fails a conformance check that should pass.
                    //
                    // The transition is the evidence, and it is unambiguous here:
                    // a relayed connection to a peer, followed by a direct one to
                    // the same peer, is an upgrade. Nothing else in this stack
                    // produces that sequence — mDNS discovery never auto-dials
                    // (§5.1), so a direct connection cannot appear behind a relay
                    // by accident.
                    //
                    // Note this does *not* soften the distinction the harness
                    // exists to make: where no upgrade occurs the connection
                    // stays relayed and is still reported as tier 3, which is
                    // what scenarios 4 and 5 assert.
                    let tier = match self.tiers.get(&peer_id) {
                        // Already upgraded: never downgrade on a later event.
                        Some(ConnectionTier::HolePunched) if !tier.relay_in_data_path() => {
                            ConnectionTier::HolePunched
                        }
                        // Relayed, now direct — that is the upgrade.
                        Some(ConnectionTier::Relayed) if !tier.relay_in_data_path() => {
                            ConnectionTier::HolePunched
                        }
                        _ => tier,
                    };
                    self.tiers.insert(peer_id, tier);
                    // A heal is a reconnect, and a reconnect is a sync. Doing
                    // this unconditionally is what means there is no separate
                    // partition-recovery path to get wrong: a peer that has been
                    // unreachable for an hour and a peer seen for the first time
                    // take exactly the same code path. Peers that do not speak
                    // the protocol — a relay, say — answer with an unsupported
                    // protocol failure, which is ignored below.
                    self.sync_with(peer_id);
                    self.sync_ledger_with(peer_id);
                    self.sync_pointers_with(peer_id);
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

                SwarmEvent::Behaviour(MemberBehaviourEvent::Sync(
                    request_response::Event::Message { peer, message, .. },
                )) => match message {
                    request_response::Message::Request {
                        request, channel, ..
                    } => {
                        let response = match request {
                            SyncRequest::Heads => SyncResponse::Heads {
                                heads: self.log.heads(),
                            },
                            SyncRequest::Fetch { wanted, have } => {
                                // `ancestors_first` owns the ordering guarantee:
                                // `insert` refuses an entry whose parent it has
                                // not seen, so a receiver handed a child first
                                // silently drops it.
                                let (entries, truncated) = self.log.ancestors_first(
                                    &wanted,
                                    &have,
                                    MAX_ENTRIES_PER_RESPONSE,
                                );
                                SyncResponse::Entries { entries, truncated }
                            }
                        };
                        // Fails only if the peer disconnected mid-exchange, in
                        // which case there is nothing to report and nothing to
                        // do: the next connection syncs from scratch.
                        let _ = self
                            .swarm
                            .behaviour_mut()
                            .sync
                            .send_response(channel, response);
                    }
                    request_response::Message::Response { response, .. } => match response {
                        SyncResponse::Heads { heads } => {
                            let wanted: Vec<Hash> = heads
                                .into_iter()
                                .filter(|hash| self.log.get(hash).is_none())
                                .collect();
                            if !wanted.is_empty() {
                                let have = self.log.heads();
                                self.swarm.behaviour_mut().sync.send_request(
                                    &peer,
                                    SyncRequest::Fetch { wanted, have },
                                );
                            }
                        }
                        SyncResponse::Entries { entries, truncated } => {
                            let mut accepted = 0;
                            let mut rejected = 0;
                            for entry in entries {
                                match self.log.insert(entry) {
                                    Ok(_) => accepted += 1,
                                    // Counted rather than logged and forgotten.
                                    // Every entry arriving here has already had
                                    // its signature verified during decoding, so
                                    // a rejection means a structural problem —
                                    // most likely an ancestor this node still
                                    // lacks — and that is worth surfacing.
                                    Err(_) => rejected += 1,
                                }
                            }
                            if truncated {
                                // Restart the exchange rather than tracking what
                                // is left. The log has grown, so the next `have`
                                // is further along and progress is monotonic —
                                // which makes resumption stateless and removes
                                // any chance of the two sides disagreeing about
                                // where a partial transfer stopped.
                                self.sync_with(peer);
                            }
                            if accepted > 0 {
                                // Governance just moved, so membership may have
                                // expanded — and an advertisement is only
                                // accepted from a current member. Both syncs
                                // start together on connect and there is no
                                // ordering between them, so a fresh node will
                                // routinely reject every advertisement it is
                                // offered before its log catches up. Re-asking
                                // here is what makes that self-correcting rather
                                // than leaving the ledger empty until the next
                                // reconnect.
                                self.sync_ledger_with(peer);
                                // And re-ask for pointers, for the same reason
                                // one step removed: a pointer is refused unless
                                // its owner currently holds `publish:<type>` and
                                // its type is allowed, both of which are answers
                                // this node's log has just changed. A record
                                // rejected a moment ago may be perfectly valid
                                // now, and nothing else would ever re-offer it.
                                self.sync_pointers_with(peer);
                            }
                            return NodeEvent::Synced {
                                peer,
                                accepted,
                                rejected,
                                truncated,
                            };
                        }
                    },
                },

                SwarmEvent::Behaviour(MemberBehaviourEvent::Kad(
                    kad::Event::OutboundQueryProgressed { id, result, step, .. },
                )) => {
                    if let kad::QueryResult::GetProviders(result) = result {
                        if let Some((_, found)) = self.collection_queries.get_mut(&id) {
                            if let Ok(kad::GetProvidersOk::FoundProviders { providers, .. }) =
                                &result
                            {
                                found.extend(providers.iter().copied());
                            }
                        }
                        if step.last
                            && let Some((collection_id, found)) =
                                self.collection_queries.remove(&id)
                        {
                            // Returned rather than buffered. `next_swarm_event`
                            // only drains `pending` on entry, so an event pushed
                            // from inside its loop waits for some *other* event
                            // to return before it is ever delivered — which,
                            // when nothing else is happening, is never.
                            return NodeEvent::CollectionProviders {
                                collection_id,
                                providers: found.iter().copied().collect(),
                            };
                        }
                        if let Some((_, found)) = self.provider_queries.get_mut(&id) {
                            // Providers arrive incrementally, so they are
                            // accumulated and only reported when the query is
                            // done. Reporting each batch would understate the
                            // holder count, which is precisely the number
                            // rarest-first ordering depends on.
                            if let Ok(kad::GetProvidersOk::FoundProviders { providers, .. }) =
                                &result
                            {
                                found.extend(providers.iter().copied());
                            }
                        }
                        if step.last && let Some((cid, found)) = self.provider_queries.remove(&id) {
                            let providers: Vec<PerNetworkIdentityId> = found
                                .iter()
                                .filter_map(PerNetworkIdentityId::from_peer_id)
                                .collect();
                            if let Some(plan) = &mut self.fetch {
                                plan.record_providers(
                                    cid,
                                    providers.clone(),
                                    &self.ledger,
                                    &self.observations,
                                    UNRELIABLE_FAILURE_RATE,
                                );
                                self.drive_fetch();
                                if let Some(done) = self.completed_fetch() {
                                    self.pending.push_back(done);
                                }
                            }
                            return NodeEvent::ProvidersFound {
                                cid,
                                holder_count: providers.len(),
                                providers,
                            };
                        }
                    }
                }

                SwarmEvent::Behaviour(MemberBehaviourEvent::Signal(
                    request_response::Event::Message { peer, message, .. },
                )) => {
                    if let request_response::Message::Request {
                        request, channel, ..
                    } = message
                    {
                        let _ = self
                            .swarm
                            .behaviour_mut()
                            .signal
                            .send_response(channel, SignalAck);
                        // Bound to the connection for the same reason a chunk
                        // request is: the signature proves the sender composed
                        // the message, not that whoever delivered it is them,
                        // and a replayed `Leave` would drop someone from a call
                        // they are still in.
                        if request.sender.peer_id() == peer {
                            return NodeEvent::SignalReceived { signal: request };
                        }
                    }
                }

                SwarmEvent::Behaviour(MemberBehaviourEvent::Media(
                    request_response::Event::Message { message, .. },
                )) => {
                    if let request_response::Message::Request {
                        request, channel, ..
                    } = message
                    {
                        let _ = self
                            .swarm
                            .behaviour_mut()
                            .media
                            .send_response(channel, MediaAck);

                        if request.to == self.identity_id {
                            return NodeEvent::MediaReceived { envelope: request };
                        }
                        // Not for us — forward it if we agreed to relay this
                        // call, and drop it otherwise. Refusing to forward for a
                        // call this node never agreed to carry is what stops a
                        // media relay being usable as an open reflector by
                        // anyone who knows its address.
                        let carries = self
                            .relayed_calls
                            .get(&request.call)
                            .is_some_and(|participants| {
                                participants.contains(&request.to)
                                    && participants.contains(&request.from)
                            });
                        if carries {
                            let (call, from, to) = (request.call, request.from, request.to);
                            self.send_media(to, request);
                            return NodeEvent::MediaForwarded { call, from, to };
                        }
                    }
                }

                SwarmEvent::Behaviour(MemberBehaviourEvent::Collection(
                    request_response::Event::Message { peer, message, .. },
                )) => match message {
                    request_response::Message::Request {
                        request, channel, ..
                    } => {
                        let response = if request.requester.peer_id() != peer {
                            CollectionResponse::Refused {
                                reason: ChunkRefusal::NoReadContent,
                            }
                        } else {
                            self.serve_collection(&request)
                        };
                        let _ = self
                            .swarm
                            .behaviour_mut()
                            .collection
                            .send_response(channel, response);
                    }
                    request_response::Message::Response {
                        request_id,
                        response,
                    } => {
                        let Some(collection_id) = self.collection_requests.remove(&request_id)
                        else {
                            continue;
                        };
                        match response {
                            CollectionResponse::Entries {
                                payloads,
                                truncated,
                            } => {
                                return NodeEvent::CollectionEnumerated {
                                    collection_id,
                                    peer,
                                    payloads,
                                    truncated,
                                };
                            }
                            // A refusal is reported as an empty enumeration
                            // rather than as an error: the requester's next move
                            // is the same either way, and a collection nobody
                            // will serve it is, from where it stands, a
                            // collection with nothing in it.
                            CollectionResponse::Refused { .. } => {
                                return NodeEvent::CollectionEnumerated {
                                    collection_id,
                                    peer,
                                    payloads: Vec::new(),
                                    truncated: false,
                                };
                            }
                        }
                    }
                },

                SwarmEvent::Behaviour(MemberBehaviourEvent::Identify(
                    identify::Event::Received { peer_id, info, .. },
                )) => {
                    // Kademlia only routes to peers it has an address for, and
                    // nothing else populates that. Without this the DHT is a
                    // behaviour that compiles and answers every query with
                    // "nobody" — which looks exactly like content genuinely
                    // having no providers.
                    for address in info.listen_addrs {
                        self.swarm
                            .behaviour_mut()
                            .kad
                            .add_address(&peer_id, address);
                    }
                }

                SwarmEvent::Behaviour(MemberBehaviourEvent::Ballot(
                    request_response::Event::Message { peer, message, .. },
                )) => match message {
                    request_response::Message::Request {
                        request, channel, ..
                    } => {
                        let response = if request.requester.peer_id() != peer {
                            BallotResponse::Refused {
                                reason: BallotRefusal::NotAMember,
                            }
                        } else {
                            self.serve_ballots(&request)
                        };
                        let _ = self
                            .swarm
                            .behaviour_mut()
                            .ballot
                            .send_response(channel, response);
                    }
                    request_response::Message::Response {
                        request_id,
                        response,
                    } => {
                        let Some(vote_id) = self.ballot_requests.remove(&request_id) else {
                            continue;
                        };
                        match response {
                            BallotResponse::Ballots { ballots, truncated } => {
                                let offered = ballots.len();
                                let accepted = ballots
                                    .into_iter()
                                    .filter(|ballot| self.record_ballot(ballot.clone()))
                                    .count();
                                return NodeEvent::BallotsReceived {
                                    peer,
                                    vote_id,
                                    accepted,
                                    rejected: offered - accepted,
                                    truncated,
                                };
                            }
                            BallotResponse::Refused { reason } => {
                                return NodeEvent::BallotSyncRefused {
                                    peer,
                                    vote_id,
                                    reason: match reason {
                                        BallotRefusal::NotAMember => {
                                            "refused: requester is not a current member".into()
                                        }
                                        BallotRefusal::CannotEvaluate => {
                                            "refused: responder cannot evaluate governance state"
                                                .into()
                                        }
                                        BallotRefusal::UnknownVote => {
                                            "refused: responder knows of no such open vote".into()
                                        }
                                    },
                                };
                            }
                        }
                    }
                },

                SwarmEvent::Behaviour(MemberBehaviourEvent::Pointer(
                    request_response::Event::Message { peer, message, .. },
                )) => match message {
                    request_response::Message::Request {
                        request, channel, ..
                    } => {
                        // Bound to the connection, as chunk requests are: a
                        // signature proves the named identity asked, never that
                        // whoever delivered it is that identity.
                        let response = if request.requester().peer_id() != peer {
                            PointerResponse::Refused {
                                reason: PointerRefusal::NoReadContent,
                            }
                        } else {
                            self.serve_pointers(&request)
                        };
                        let _ = self
                            .swarm
                            .behaviour_mut()
                            .pointer
                            .send_response(channel, response);
                    }
                    request_response::Message::Response {
                        request_id,
                        response,
                    } => {
                        let digest_peer = self.pointer_digests.remove(&request_id);
                        let fetch_peer = self.pointer_fetches.remove(&request_id);
                        if digest_peer.is_none() && fetch_peer.is_none() {
                            continue;
                        }
                        match response {
                            PointerResponse::Digest { entries, truncated } => {
                                let wanted = self.pointers_worth_fetching(&entries);
                                let count = wanted.len();
                                if !wanted.is_empty() {
                                    self.request_pointers(peer, wanted);
                                }
                                return NodeEvent::PointerDigest {
                                    peer,
                                    offered: entries.len(),
                                    wanted: count,
                                    truncated,
                                };
                            }
                            PointerResponse::Records { records, truncated } => {
                                let mut accepted = 0;
                                let mut rejected = 0;
                                let mut wrappings = 0;
                                for record in records {
                                    if self.accept_pointer(record.pointer) {
                                        accepted += 1;
                                    } else {
                                        rejected += 1;
                                    }
                                    for wrapping in record.wrappings {
                                        if self.accept_wrapping(wrapping) {
                                            wrappings += 1;
                                        }
                                    }
                                }
                                return NodeEvent::PointersReceived {
                                    peer,
                                    accepted,
                                    rejected,
                                    wrappings,
                                    truncated,
                                };
                            }
                            PointerResponse::Refused { reason } => {
                                return NodeEvent::PointerSyncRefused {
                                    peer,
                                    reason: match reason {
                                        PointerRefusal::NoReadContent => {
                                            "refused: requester holds no read-content".into()
                                        }
                                        PointerRefusal::CannotEvaluate => {
                                            "refused: responder cannot evaluate governance state"
                                                .into()
                                        }
                                    },
                                };
                            }
                        }
                    }
                },

                SwarmEvent::Behaviour(MemberBehaviourEvent::Join(
                    request_response::Event::Message { peer, message, .. },
                )) => match message {
                    request_response::Message::Request {
                        request, channel, ..
                    } => match self.screen_join(&request, peer) {
                        Err(reason) => {
                            let _ = self
                                .swarm
                                .behaviour_mut()
                                .join
                                .send_response(channel, JoinResponse::Refused { reason });
                        }
                        Ok(()) => {
                            let id = JoinRequestId(self.next_join_request);
                            self.next_join_request += 1;
                            let joiner = request.joiner;
                            let invite = request.invite.invite_id();
                            self.inbound_joins.insert(id, (request, channel));
                            return NodeEvent::JoinRequested {
                                peer,
                                joiner,
                                invite,
                                request: id,
                            };
                        }
                    },
                    request_response::Message::Response {
                        request_id,
                        response,
                    } => {
                        if self.join_requests.remove(&request_id).is_none() {
                            continue;
                        }
                        return match response {
                            JoinResponse::Admitted { entry } => {
                                NodeEvent::Admitted { peer, entry }
                            }
                            // Recorded as waiting is a *successful* join under
                            // explicit intake, not a failure: connectivity and
                            // an identity is the entirety of what §2.4 promises.
                            JoinResponse::Waiting => NodeEvent::AwaitingAdmission { peer },
                            JoinResponse::Refused { reason } => NodeEvent::JoinRefused {
                                peer,
                                reason: reason.as_str().to_owned(),
                            },
                        };
                    }
                },

                SwarmEvent::Behaviour(MemberBehaviourEvent::Epoch(
                    request_response::Event::Message { peer, message, .. },
                )) => match message {
                    request_response::Message::Request {
                        request, channel, ..
                    } => {
                        // Every check this node can make without an identity or
                        // a clock happens here, and a failure is answered
                        // immediately. Only a request that survives all of them
                        // is surfaced for a decision — so an application that
                        // ignores the event leaves a requester unanswered, never
                        // wrongly keyed in.
                        match self.screen_epoch_request(&request, peer) {
                            Err(reason) => {
                                let _ = self.swarm.behaviour_mut().epoch.send_response(
                                    channel,
                                    EpochKeyResponse::Refused { reason },
                                );
                            }
                            Ok(()) => {
                                let id = EpochRequestId(self.next_epoch_request);
                                self.next_epoch_request += 1;
                                let requester = request.requester;
                                self.inbound_epoch_requests.insert(id, (request, channel));
                                return NodeEvent::EpochKeyRequested {
                                    peer,
                                    requester,
                                    request: id,
                                };
                            }
                        }
                    }
                    request_response::Message::Response {
                        request_id,
                        response,
                    } => {
                        let Some(sender) = self.epoch_requests.remove(&request_id) else {
                            continue;
                        };
                        match response {
                            EpochKeyResponse::Welcome {
                                welcome,
                                rotation_ref,
                                history,
                            } => {
                                let count = history.len();
                                match self.accept_welcome(&welcome, rotation_ref, &history, sender)
                                {
                                    Ok(()) => {
                                        return NodeEvent::EpochKeyDelivered {
                                            peer,
                                            rotation_ref,
                                            historical_keys: count,
                                        };
                                    }
                                    Err(error) => {
                                        return NodeEvent::EpochKeyUnavailable {
                                            peer,
                                            reason: error.to_string(),
                                        };
                                    }
                                }
                            }
                            EpochKeyResponse::Refused { reason } => {
                                return NodeEvent::EpochKeyUnavailable {
                                    peer,
                                    reason: format!("refused: {}", reason.as_str()),
                                };
                            }
                        }
                    }
                },

                SwarmEvent::Behaviour(MemberBehaviourEvent::Chunk(
                    request_response::Event::Message { peer, message, .. },
                )) => match message {
                    request_response::Message::Request {
                        request, channel, ..
                    } => {
                        // The request's signature was verified during decoding,
                        // so `request.requester` really did ask. What that does
                        // *not* establish is that the peer delivering it is that
                        // requester — a signed request is replayable by anyone
                        // who captured it. Binding it to the connection closes
                        // that: a third party cannot borrow a member's standing
                        // by replaying their request.
                        let response = if request.requester.peer_id() != peer {
                            ChunkResponse::Refused {
                                reason: ChunkRefusal::NoReadContent,
                            }
                        } else {
                            self.serve_chunk(&request)
                        };
                        let _ = self
                            .swarm
                            .behaviour_mut()
                            .chunk
                            .send_response(channel, response);
                    }
                    request_response::Message::Response {
                        request_id,
                        response,
                    } => {
                        let Some((peer, source, cid)) = self.inflight.remove(&request_id) else {
                            continue;
                        };
                        match response {
                            ChunkResponse::Chunk { bytes } => {
                                let len = bytes.len();
                                // Verified against the CID that was *asked for*
                                // (§4.4 step 5). `insert` refuses on mismatch, so
                                // a bad chunk never enters the store and can
                                // never be passed on.
                                match self.chunks.insert(cid, bytes) {
                                    Ok(()) => {
                                        self.observations.record_verified(source);
                                        // §4.2 again: having the bytes *is*
                                        // swarm membership, and a holder the
                                        // DHT does not know about is a holder
                                        // no requester can reach. Announcing
                                        // here is what makes the fetcher a real
                                        // source for the next requester rather
                                        // than only in principle.
                                        self.announce_chunk(cid);
                                        self.note_fetch_outcome(cid, true);
                                        return NodeEvent::ChunkReceived {
                                            peer,
                                            cid,
                                            bytes: len,
                                        };
                                    }
                                    Err(StorageError::ChunkVerificationFailed { .. }) => {
                                        // The one case that counts against the
                                        // peer: it served bytes that are not
                                        // what it said they were. §4.6 is
                                        // specifically about verification
                                        // failures, and this is one.
                                        self.observations.record_failed(source);
                                        self.note_fetch_outcome(cid, false);
                                        return NodeEvent::ChunkUnavailable {
                                            peer,
                                            cid,
                                            reason: "failed verification against its content id"
                                                .into(),
                                            counted_against_peer: true,
                                        };
                                    }
                                    Err(error) => {
                                        self.note_fetch_outcome(cid, false);
                                        return NodeEvent::ChunkUnavailable {
                                            peer,
                                            cid,
                                            reason: error.to_string(),
                                            counted_against_peer: false,
                                        };
                                    }
                                }
                            }
                            ChunkResponse::NotHeld => {
                                self.note_fetch_outcome(cid, false);
                                return NodeEvent::ChunkUnavailable {
                                    peer,
                                    cid,
                                    reason: "not held".into(),
                                    counted_against_peer: false,
                                };
                            }
                            ChunkResponse::Refused { reason } => {
                                self.note_fetch_outcome(cid, false);
                                return NodeEvent::ChunkUnavailable {
                                    peer,
                                    cid,
                                    reason: match reason {
                                        ChunkRefusal::NoReadContent => {
                                            "refused: requester holds no read-content".into()
                                        }
                                        ChunkRefusal::CannotEvaluate => {
                                            "refused: responder cannot evaluate the gate yet".into()
                                        }
                                    },
                                    counted_against_peer: false,
                                };
                            }
                        }
                    }
                },

                SwarmEvent::Behaviour(MemberBehaviourEvent::Chunk(
                    request_response::Event::OutboundFailure {
                        peer, request_id, error, ..
                    },
                )) => {
                    if let Some((_, _, cid)) = self.inflight.remove(&request_id) {
                        self.note_fetch_outcome(cid, false);
                        return NodeEvent::ChunkUnavailable {
                            peer,
                            cid,
                            reason: error.to_string(),
                            counted_against_peer: false,
                        };
                    }
                }

                SwarmEvent::Behaviour(MemberBehaviourEvent::Ledger(
                    request_response::Event::Message { peer, message, .. },
                )) => match message {
                    request_response::Message::Request {
                        request, channel, ..
                    } => {
                        let response = match request {
                            LedgerRequest::Digest => LedgerResponse::Digest {
                                entries: self.ledger.digest(),
                            },
                            LedgerRequest::Fetch { nodes } => {
                                let (advertisements, truncated) =
                                    self.ledger.fetch(&nodes, MAX_ADVERTISEMENTS_PER_RESPONSE);
                                LedgerResponse::Advertisements {
                                    advertisements,
                                    truncated,
                                }
                            }
                        };
                        let _ = self
                            .swarm
                            .behaviour_mut()
                            .ledger
                            .send_response(channel, response);
                    }
                    request_response::Message::Response { response, .. } => match response {
                        LedgerResponse::Digest { entries } => {
                            // `wanted_from` asks for what is missing *and* for
                            // what this node holds a staler copy of. The second
                            // half is what makes refreshes propagate at all.
                            let nodes = self.ledger.wanted_from(&entries);
                            if !nodes.is_empty() {
                                self.swarm
                                    .behaviour_mut()
                                    .ledger
                                    .send_request(&peer, LedgerRequest::Fetch { nodes });
                            }
                        }
                        LedgerResponse::Advertisements {
                            advertisements,
                            truncated,
                        } => {
                            let mut accepted = 0;
                            let mut rejected = 0;
                            // Replayed once for the whole batch rather than per
                            // advertisement: replay walks the canonical chain,
                            // and doing it per item would make a ledger sync
                            // quadratic in the log.
                            match self.governance_state() {
                                Some(state) => {
                                    for advertisement in advertisements {
                                        match self.ledger.insert(advertisement, &state) {
                                            Ok(()) => accepted += 1,
                                            Err(_) => rejected += 1,
                                        }
                                    }
                                }
                                // No replayable governance state yet, so there is
                                // nothing to validate membership against. Counted
                                // rather than dropped silently, and retried once
                                // the log catches up.
                                None => rejected += advertisements.len(),
                            }
                            if truncated {
                                self.sync_ledger_with(peer);
                            }
                            return NodeEvent::LedgerSynced {
                                peer,
                                accepted,
                                rejected,
                                truncated,
                            };
                        }
                    },
                },

                SwarmEvent::Behaviour(MemberBehaviourEvent::Ledger(
                    request_response::Event::OutboundFailure { peer, error, .. },
                )) => {
                    if !matches!(
                        error,
                        request_response::OutboundFailure::UnsupportedProtocols
                    ) {
                        return NodeEvent::SyncFailed {
                            peer,
                            error: error.to_string(),
                        };
                    }
                }

                SwarmEvent::Behaviour(MemberBehaviourEvent::Sync(
                    request_response::Event::OutboundFailure { peer, error, .. },
                )) => {
                    // A relay does not run this protocol, and every node syncs
                    // on connect — including with relays. Reporting that as a
                    // failure would mean an error on every relayed connection.
                    if !matches!(
                        error,
                        request_response::OutboundFailure::UnsupportedProtocols
                    ) {
                        return NodeEvent::SyncFailed {
                            peer,
                            error: error.to_string(),
                        };
                    }
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
    /// Announces an address peers should use to reach this relay.
    ///
    /// # Why listening is not enough
    ///
    /// A relay normally promotes its own non-loopback listen addresses, which is
    /// right when the address the world uses is an address the relay is bound
    /// to. Behind a load balancer or TCP proxy it is not: the public host *and*
    /// port both differ from the container's, and nothing in the process can
    /// infer them. libp2p builds the address list it returns in a reservation
    /// from external addresses only, so without this a relay deployed behind a
    /// proxy hands clients its private container address — reservations are
    /// granted, circuits are unusable, and the health check reports ready
    /// throughout.
    ///
    /// Call it once per public address before listening.
    pub fn add_public_address(&mut self, address: Multiaddr) {
        self.swarm.add_external_address(address);
    }

    /// Listens on the dual-stack defaults — TCP and QUIC over IPv4 and IPv6.
    ///
    /// A relay is reached by peers whose own connectivity varies, so it offers
    /// every combination rather than assuming which one a given client can use.
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

/// The properties that decide whether a listener can serve a dial.
///
/// Mirrors libp2p's own port-reuse rule, which pairs a listener with a remote
/// only when the address family and loopback-ness both agree. Kept as a type so
/// the two halves cannot drift apart, and so a future third condition has an
/// obvious home.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AddressShape {
    ipv4: bool,
    loopback: bool,
}

impl AddressShape {
    fn of(address: &Multiaddr) -> Self {
        let mut shape = Self {
            // Absent an IP component there is nothing to pair on; treating it as
            // IPv4 keeps the comparison total rather than introducing an
            // "unknown" that silently matches everything.
            ipv4: true,
            loopback: false,
        };
        for part in address.iter() {
            match part {
                libp2p::multiaddr::Protocol::Ip4(ip) => {
                    shape.ipv4 = true;
                    shape.loopback = ip.is_loopback();
                    return shape;
                }
                libp2p::multiaddr::Protocol::Ip6(ip) => {
                    shape.ipv4 = false;
                    shape.loopback = ip.is_loopback();
                    return shape;
                }
                _ => {}
            }
        }
        shape
    }
}

/// Whether an address is loopback.
///
/// Used for whether a relay may advertise an address as external; listener
/// pairing uses [`AddressShape`], which also accounts for address family.
fn is_loopback(address: &Multiaddr) -> bool {
    address.iter().any(|part| match part {
        libp2p::multiaddr::Protocol::Ip4(ip) => ip.is_loopback(),
        libp2p::multiaddr::Protocol::Ip6(ip) => ip.is_loopback(),
        _ => false,
    })
}
