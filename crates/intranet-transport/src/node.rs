//! Member and relay nodes — Core Protocol Spec §5.1–5.5.

use crate::dial::{ConnectionTier, classify};
use crate::{RelayLimits, TransportError, behaviour::*};
use intranet_crypto::Hash;
use intranet_governance::{
    GovernanceError, GovernanceLog, GovernanceState, LogEntry, MAX_ENTRIES_PER_RESPONSE,
    SyncRequest, SyncResponse,
};
use intranet_ledger::{
    CapabilityAdvertisement, CapabilityLedger, LedgerError, LedgerRequest, LedgerResponse,
    MAX_ADVERTISEMENTS_PER_RESPONSE, ReliabilityObservations,
};
use intranet_storage::{
    ChunkRefusal, ChunkRequest, ChunkResponse, ChunkStore, Cid, FetchPlan, StorageError, may_serve,
};
use intranet_identity::{PerNetworkIdentity, PerNetworkIdentityId};
use libp2p::{
    Multiaddr, PeerId, Swarm, SwarmBuilder, dcutr, identify, kad, mdns, ping, relay,
    request_response, swarm::SwarmEvent,
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
                    ledger: crate::sync::ledger_behaviour(),
                    chunk: crate::sync::chunk_behaviour(),
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
        })
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
