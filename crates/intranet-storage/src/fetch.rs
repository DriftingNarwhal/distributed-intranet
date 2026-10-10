//! Multi-source parallel chunk fetch — Storage Spec §4.4.
//!
//! # Why this is a plan rather than a loop in the transport layer
//!
//! §4.4 specifies four decisions — which chunks to ask for first, whom to ask,
//! how many at once, and what to do when a source fails — and none of them need
//! a network to test. Keeping them here means they can be exercised directly,
//! including the awkward cases (every source exhausted, a chunk with no holders
//! at all) that are tedious to provoke over a real connection and easy to get
//! wrong.
//!
//! The transport layer drives this: it reports what the DHT said and what each
//! request produced, and asks what to do next.
//!
//! # The specified behaviours this implements
//!
//! - **Rarest-first** (step 2): chunks with fewest holders are requested first,
//!   so scarce chunks get additional copies into circulation sooner.
//! - **Per-chunk source selection** (step 3): the §4.3 criteria applied per
//!   chunk rather than per object, so one slow holder does not bottleneck an
//!   object it happens to be first for.
//! - **Simultaneous fetch from different sources** (step 4), bounded by a
//!   concurrency limit that §4.4 is explicit is a local setting with no
//!   cross-node consistency requirement.
//! - **Retry elsewhere on failure** (step 5): a source that fails verification
//!   or has nothing to give is dropped for that chunk and the next candidate
//!   tried, rather than the fetch failing.
//! - **No more bytes than the manifest declares** (step 6): chunks added under a
//!   budget stop being asked for once what arrived for them passes it, so a
//!   manifest that understates its length costs its declared size rather than
//!   whatever its chunks turn out to hold.

use crate::serving::{SourceCandidate, select_sources};
use crate::{Cid, rarest_first};
use intranet_identity::PerNetworkIdentityId;
use intranet_ledger::{CapabilityLedger, ReliabilityObservations};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// How many chunks to have in flight at once, by default.
///
/// **Flagged: §4.4 states concurrency is deliberately a local setting and gives
/// no number.** Four is a reasonable default for a residential downlink; callers
/// with more bandwidth should raise it, which is exactly the tuning the spec has
/// in mind.
pub const DEFAULT_CONCURRENCY: usize = 4;

/// Where one chunk has got to.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ChunkState {
    /// The DHT has not answered for this chunk yet.
    AwaitingProviders,
    /// Holders are known and none is being asked right now.
    Ready {
        /// Candidates in selection order, best first.
        candidates: VecDeque<PerNetworkIdentityId>,
        /// How many holders the DHT reported, for rarest-first ordering.
        holder_count: u32,
    },
    /// A request is outstanding.
    InFlight {
        /// Candidates left to try if this one fails.
        candidates: VecDeque<PerNetworkIdentityId>,
        /// The holder count, retained so a retry keeps its place in the order.
        holder_count: u32,
    },
    /// Every known holder was tried and none produced the bytes.
    Exhausted,
    /// The bytes arrived and verified.
    Done,
    /// Given up on because every budget it was wanted under ran out (§4.4
    /// step 6). Not asked for again by this plan.
    OverBudget,
}

/// A byte allowance over a set of chunks — §4.4 step 6.
#[derive(Debug, Clone)]
struct Budget {
    /// The object the allowance is for, normally its manifest's CID.
    object: Cid,
    chunks: BTreeSet<Cid>,
    remaining: u64,
    exceeded: bool,
}

/// A multi-source fetch in progress.
#[derive(Debug, Clone)]
pub struct FetchPlan {
    chunks: BTreeMap<Cid, ChunkState>,
    concurrency: usize,
    inflight: usize,
    budgets: Vec<Budget>,
    /// Chunks some caller wanted with no budget, which no budget may abandon.
    unbudgeted: BTreeSet<Cid>,
}

impl FetchPlan {
    /// Starts a plan for `cids`.
    pub fn new(cids: impl IntoIterator<Item = Cid>, concurrency: usize) -> Self {
        let mut plan = Self {
            chunks: BTreeMap::new(),
            // A concurrency of zero would stall silently, which is a worse
            // outcome than quietly correcting an obviously unintended value.
            concurrency: concurrency.max(1),
            inflight: 0,
            budgets: Vec::new(),
            unbudgeted: BTreeSet::new(),
        };
        plan.extend(cids);
        plan
    }

    /// Adds more chunks to an existing plan.
    pub fn extend(&mut self, cids: impl IntoIterator<Item = Cid>) {
        for cid in cids {
            self.unbudgeted.insert(cid);
            self.want(cid);
        }
    }

    /// Adds `object`'s chunks, which together may take no more than `bytes` —
    /// §4.4 step 6. `object` names the budget, normally by its manifest's CID,
    /// so a caller can learn which objects ran out
    /// ([`overrun_objects`](Self::overrun_objects)).
    ///
    /// Every verified chunk that arrives is charged against each budget it
    /// belongs to. A chunk that would take a budget past its allowance is
    /// refused rather than kept (see [`admit`](Self::admit)), and from then on
    /// that budget's chunks are not asked for — unless another caller still
    /// wants one, without a budget or under one that has room. A chunk named by
    /// a manifest that lied about its size may well be somebody else's honest
    /// chunk, and abandoning it for them would let one bad manifest starve
    /// another object of content it shares.
    ///
    /// **What this bounds is the bytes kept, not the bytes received.** A request
    /// already in flight when a budget runs out still delivers its response, and
    /// a response is read whole before anybody sees it, so the overshoot is up to
    /// one response per concurrent request. Bounding that needs a transport that
    /// stops reading mid-response, which this plan cannot be.
    pub fn extend_within(&mut self, object: Cid, cids: impl IntoIterator<Item = Cid>, bytes: u64) {
        let chunks: BTreeSet<Cid> = cids.into_iter().collect();
        for cid in &chunks {
            self.want(*cid);
        }
        self.budgets.push(Budget {
            object,
            chunks,
            remaining: bytes,
            exceeded: false,
        });
    }

    fn want(&mut self, cid: Cid) {
        let state = self
            .chunks
            .entry(cid)
            .or_insert(ChunkState::AwaitingProviders);
        // Wanted again by a caller with room: an abandoned chunk is worth
        // asking for after all.
        if matches!(state, ChunkState::OverBudget) {
            *state = ChunkState::AwaitingProviders;
        }
    }

    /// Charges `bytes` that verified as `cid` against its budgets, and says
    /// whether to keep them — §4.4 step 6.
    ///
    /// Call this only for bytes that **verified**: a holder that serves garbage
    /// is that holder's fault (§4.6), and charging it to the object would let
    /// any one bad source exhaust an honest object's allowance and abandon it.
    ///
    /// `false` means keep nothing: the chunk is marked over budget, and so is
    /// every chunk of each budget that has now run out and that nobody else
    /// still wants. Record nothing further for it.
    ///
    /// Only a chunk this plan has **in flight** is charged. Anything else — a
    /// chunk the plan never asked for, such as a caller's own one-off request
    /// on the same connection, or a second response for one already done — is
    /// not this plan's to weigh, and charging it twice would run an honest
    /// object out.
    pub fn admit(&mut self, cid: Cid, bytes: usize) -> bool {
        if !matches!(self.chunks.get(&cid), Some(ChunkState::InFlight { .. })) {
            return true;
        }
        let bytes = bytes as u64;
        let mut room = self.unbudgeted.contains(&cid);
        let mut ran_out = false;
        for budget in &mut self.budgets {
            if budget.exceeded || !budget.chunks.contains(&cid) {
                continue;
            }
            match budget.remaining.checked_sub(bytes) {
                Some(left) => {
                    budget.remaining = left;
                    room = true;
                }
                None => {
                    budget.exceeded = true;
                    ran_out = true;
                }
            }
        }
        // Charged only when admitted would be tidier, and wrong: a budget that
        // ran out ran out whichever other budget the chunk also belongs to.
        if ran_out {
            self.abandon_exhausted_budgets();
        }
        if room {
            return true;
        }
        if let Some(state) = self.chunks.get_mut(&cid) {
            if matches!(state, ChunkState::InFlight { .. }) {
                self.inflight = self.inflight.saturating_sub(1);
            }
            *state = ChunkState::OverBudget;
        }
        false
    }

    /// Whether only budgets that have run out still want `cid`.
    fn doomed(&self, cid: &Cid) -> bool {
        !self.unbudgeted.contains(cid)
            && self
                .budgets
                .iter()
                .any(|budget| budget.chunks.contains(cid))
            && self
                .budgets
                .iter()
                .filter(|budget| budget.chunks.contains(cid))
                .all(|budget| budget.exceeded)
    }

    /// Marks over budget every pending chunk that only exhausted budgets want.
    ///
    /// A chunk in flight is left alone, since its response is already coming:
    /// [`admit`](Self::admit) refuses it on arrival, and
    /// [`record_failed`](Self::record_failed) does not send it again.
    fn abandon_exhausted_budgets(&mut self) {
        let doomed: BTreeSet<Cid> = self
            .budgets
            .iter()
            .filter(|budget| budget.exceeded)
            .flat_map(|budget| budget.chunks.iter().copied())
            .filter(|cid| self.doomed(cid))
            .collect();
        for cid in doomed {
            if let Some(state) = self.chunks.get_mut(&cid)
                && matches!(
                    state,
                    ChunkState::AwaitingProviders | ChunkState::Ready { .. }
                )
            {
                *state = ChunkState::OverBudget;
            }
        }
    }

    /// Chunks the DHT has not been asked about yet.
    pub fn providers_needed(&self) -> Vec<Cid> {
        self.chunks
            .iter()
            .filter(|(_, state)| matches!(state, ChunkState::AwaitingProviders))
            .map(|(cid, _)| *cid)
            .collect()
    }

    /// Records what the DHT said about `cid`.
    ///
    /// An empty provider list marks the chunk exhausted rather than leaving it
    /// waiting forever: "nobody holds this" is an answer, and a plan that
    /// treated it as pending would never report completion.
    /// `fallback` is asked only when the lookup named nobody usable.
    ///
    /// **Two different questions, and they were one parameter.** Who *holds*
    /// this chunk is a fact about replication — it is the count this plan orders
    /// by and the count an under-replication report is made of. Who to *ask
    /// next* is a routing decision, and a provider record was never the only
    /// possible answer to it.
    ///
    /// Collapsing them meant that a lookup returning nothing ended the fetch:
    /// the chunk was marked exhausted and the content became unreachable for the
    /// life of the process. On a two-member network that is the ordinary case
    /// rather than an edge one — provider records have nowhere to live but the
    /// holder, a member behind NAT never becomes a DHT server, and the one node
    /// holding the bytes is the peer already on the other end of a socket.
    ///
    /// So a fallback is asked, and `holder_count` stays the number the lookup
    /// actually produced. A fallback candidate is therefore correctly counted as
    /// **zero known holders** — scarcest, which is where rarest-first should put
    /// it — and nothing here inflates a replication figure with a peer that
    /// merely might have something.
    pub fn record_providers(
        &mut self,
        cid: Cid,
        providers: Vec<PerNetworkIdentityId>,
        fallback: Vec<PerNetworkIdentityId>,
        ledger: &CapabilityLedger,
        observations: &ReliabilityObservations,
        failure_threshold: f64,
    ) {
        let Some(state) = self.chunks.get_mut(&cid) else {
            return;
        };
        if !matches!(state, ChunkState::AwaitingProviders) {
            return;
        }
        let holder_count = providers.len() as u32;
        let mut ordered = order_sources(providers, ledger, observations, failure_threshold);
        if ordered.is_empty() {
            // The ledger still filters and ranks these, so a peer that never
            // volunteered to serve is not asked, and a peer known to fail is
            // ordered last exactly as a named provider would be.
            ordered = order_sources(fallback, ledger, observations, failure_threshold);
        }
        *state = if ordered.is_empty() {
            ChunkState::Exhausted
        } else {
            ChunkState::Ready {
                candidates: ordered,
                holder_count,
            }
        };
    }

    /// The next requests to issue, rarest-first and within the concurrency limit.
    ///
    /// Returns `(chunk, source)` pairs. Each is marked in flight, so calling
    /// this twice without recording an outcome does not re-issue the same
    /// request.
    pub fn next_requests(&mut self) -> Vec<(Cid, PerNetworkIdentityId)> {
        let mut ready: Vec<(Cid, u32)> = self
            .chunks
            .iter()
            .filter_map(|(cid, state)| match state {
                ChunkState::Ready { holder_count, .. } => Some((*cid, *holder_count)),
                _ => None,
            })
            .collect();
        // Scarcity order, from the same routine §4.4 step 2 specifies, rather
        // than a second ordering that could drift from it.
        ready.sort_by_key(|(_, holders)| *holders);
        let order = rarest_first(&ready);

        let mut issued = Vec::new();
        for cid in order {
            if self.inflight >= self.concurrency {
                break;
            }
            let Some(ChunkState::Ready {
                candidates,
                holder_count,
            }) = self.chunks.get_mut(&cid)
            else {
                continue;
            };
            let Some(source) = candidates.pop_front() else {
                continue;
            };
            let remaining = std::mem::take(candidates);
            let holders = *holder_count;
            self.chunks.insert(
                cid,
                ChunkState::InFlight {
                    candidates: remaining,
                    holder_count: holders,
                },
            );
            self.inflight += 1;
            issued.push((cid, source));
        }
        issued
    }

    /// Records that a chunk arrived and verified.
    pub fn record_received(&mut self, cid: Cid) {
        if let Some(state) = self.chunks.get_mut(&cid)
            && matches!(state, ChunkState::InFlight { .. })
        {
            *state = ChunkState::Done;
            self.inflight = self.inflight.saturating_sub(1);
        }
    }

    /// Objects whose budget ran out: their chunks took more than allowed.
    pub fn overrun_objects(&self) -> Vec<Cid> {
        self.budgets
            .iter()
            .filter(|budget| budget.exceeded)
            .map(|budget| budget.object)
            .collect()
    }

    /// Chunks given up on because every budget they were wanted under ran out.
    pub fn over_budget(&self) -> Vec<Cid> {
        self.collect(|state| matches!(state, ChunkState::OverBudget))
    }

    /// Records that a source did not produce the bytes.
    ///
    /// The chunk returns to the queue against its remaining candidates, so one
    /// bad or departed holder costs a round trip rather than the chunk. Only
    /// when every known holder has been tried is it given up on — and even then
    /// the plan reports it rather than failing, since a caller may well want the
    /// chunks it *did* get.
    ///
    /// A chunk whose every budget has run out while it was in flight is given
    /// up on instead (§4.4 step 6): retrying it elsewhere would fetch bytes the
    /// plan has already decided not to keep.
    pub fn record_failed(&mut self, cid: Cid) {
        let doomed = self.doomed(&cid);
        let Some(state) = self.chunks.get_mut(&cid) else {
            return;
        };
        let ChunkState::InFlight {
            candidates,
            holder_count,
        } = state
        else {
            return;
        };
        self.inflight = self.inflight.saturating_sub(1);
        *state = if doomed {
            ChunkState::OverBudget
        } else if candidates.is_empty() {
            ChunkState::Exhausted
        } else {
            ChunkState::Ready {
                candidates: std::mem::take(candidates),
                holder_count: *holder_count,
            }
        };
    }

    /// Whether every chunk has either arrived or been given up on.
    pub fn is_complete(&self) -> bool {
        self.chunks.values().all(|state| {
            matches!(
                state,
                ChunkState::Done | ChunkState::Exhausted | ChunkState::OverBudget
            )
        })
    }

    /// Chunks that arrived.
    pub fn received(&self) -> Vec<Cid> {
        self.collect(|state| matches!(state, ChunkState::Done))
    }

    /// Chunks no known holder would produce.
    pub fn unavailable(&self) -> Vec<Cid> {
        self.collect(|state| matches!(state, ChunkState::Exhausted))
    }

    /// How many requests are outstanding.
    pub fn inflight(&self) -> usize {
        self.inflight
    }

    fn collect(&self, matches: impl Fn(&ChunkState) -> bool) -> Vec<Cid> {
        self.chunks
            .iter()
            .filter(|(_, state)| matches(state))
            .map(|(cid, _)| *cid)
            .collect()
    }
}

/// Orders holders by the §4.3 criteria.
///
/// Latency and load are unknown here — the DHT reports who holds a chunk, not
/// how busy they are — so those criteria fall through to the ones that *are*
/// known: local reliability observations and advertised throughput. This calls
/// the same `select_sources` the spec names rather than a reduced copy, so a
/// caller that later learns latency or load can supply it without a second
/// ranking appearing.
fn order_sources(
    providers: Vec<PerNetworkIdentityId>,
    ledger: &CapabilityLedger,
    observations: &ReliabilityObservations,
    failure_threshold: f64,
) -> VecDeque<PerNetworkIdentityId> {
    let candidates: Vec<SourceCandidate> = providers
        .into_iter()
        .map(|peer| SourceCandidate {
            peer,
            latency_millis: None,
            current_load: 0,
        })
        .collect();
    let wanted = candidates.len();
    select_sources(&candidates, ledger, observations, failure_threshold, wanted)
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use intranet_crypto::Timestamp;
    use intranet_governance::{
        Capability, EntryBody, GovernanceState, GroupId, LogEntry, MembershipAction, NetworkPolicy,
    };
    use intranet_identity::{MasterSeed, NetworkId, PerNetworkIdentity};
    use intranet_ledger::{BandwidthCap, CapabilityAdvertisement, ComputeClass};

    const NETWORK: NetworkId = NetworkId::from_bytes([42u8; 32]);

    fn identity(n: u8) -> PerNetworkIdentity {
        MasterSeed::from_entropy([n; 32])
            .identity_for(&NETWORK)
            .unwrap()
    }

    /// A ledger in which every named node advertises upload capacity.
    ///
    /// Capacity matters: `select_sources` drops a peer advertising none, since
    /// it has not volunteered to serve, so a ledger missing an entry silently
    /// removes that source.
    fn ledger_with(nodes: &[(u8, u64)]) -> CapabilityLedger {
        let founder = identity(1);
        let mut chain = vec![LogEntry::create(
            &founder,
            None,
            Timestamp::from_millis(0),
            EntryBody::Genesis {
                network: NETWORK,
                policy: NetworkPolicy::conservative_default(),
                everyone_capabilities: [Capability::ReadContent].into_iter().collect(),
            },
        )];
        for (seed, _) in nodes {
            let parent = chain.last().map(LogEntry::hash);
            chain.push(LogEntry::create(
                &founder,
                parent,
                Timestamp::from_millis(i64::from(*seed) + 1),
                EntryBody::MembershipChange {
                    group: GroupId::everyone(),
                    identity: identity(*seed).id(),
                    action: MembershipAction::Add { via_invite: None },
                },
            ));
        }
        let state = GovernanceState::replay(chain.iter().collect::<Vec<_>>()).unwrap();

        let mut ledger = CapabilityLedger::new(NETWORK);
        for (seed, up) in nodes {
            ledger
                .insert(
                    CapabilityAdvertisement::create(
                        &identity(*seed),
                        1 << 30,
                        BandwidthCap {
                            up_bytes_per_sec: *up,
                            down_bytes_per_sec: *up,
                            active_window: None,
                        },
                        false,
                        false,
                        ComputeClass::Modest,
                        Timestamp::from_millis(10),
                    ),
                    &state,
                )
                .unwrap();
        }
        ledger
    }

    fn cid(n: u8) -> Cid {
        Cid::of(&[n; 8])
    }

    fn record(plan: &mut FetchPlan, which: Cid, providers: &[u8], ledger: &CapabilityLedger) {
        plan.record_providers(
            which,
            providers.iter().map(|s| identity(*s).id()).collect(),
            // No fallback: these tests are about what a lookup's own answer
            // produces, and one supplied here would mask an empty result.
            Vec::new(),
            ledger,
            &ReliabilityObservations::new(),
            0.5,
        );
    }

    /// Records a lookup that named nobody, with peers to fall back on.
    fn record_with_fallback(
        plan: &mut FetchPlan,
        which: Cid,
        fallback: &[u8],
        ledger: &CapabilityLedger,
    ) {
        plan.record_providers(
            which,
            Vec::new(),
            fallback.iter().map(|s| identity(*s).id()).collect(),
            ledger,
            &ReliabilityObservations::new(),
            0.5,
        );
    }

    #[test]
    fn a_lookup_that_named_nobody_falls_back_to_a_reachable_peer() {
        // **The failure this prevents made a two-member network unable to
        // reconcile anything.** Both members wrote while apart; on meeting, each
        // fetched the other's pointer from the other, then asked the DHT who
        // held the segment it named. Over a two-peer routing table the lookup
        // named nobody — without asking anybody — the chunk was marked
        // exhausted, and the content stayed unreachable while its holder sat one
        // hop away.
        let mut plan = FetchPlan::new(vec![cid(1)], 4);
        let ledger = ledger_with(&[(2, 1_000)]);

        record(&mut plan, cid(1), &[], &ledger);
        assert!(
            plan.next_requests().is_empty(),
            "with no providers and nothing to fall back on there is nobody to ask"
        );

        let mut plan = FetchPlan::new(vec![cid(1)], 4);
        record_with_fallback(&mut plan, cid(1), &[2], &ledger);
        let issued = plan.next_requests();
        assert_eq!(
            issued.len(),
            1,
            "a reachable peer must be asked when the lookup named nobody"
        );
        assert_eq!(issued[0].1, identity(2).id());
    }

    #[test]
    fn a_fallback_is_not_counted_as_a_holder() {
        // The other half, and the reason the fallback is a separate parameter.
        // `holder_count` is what rarest-first orders by and what an
        // under-replication report is made of, so a peer that merely might have
        // something must not raise it. Zero known holders is also the truth, and
        // it puts this chunk first where scarcity decides.
        let ledger = ledger_with(&[(2, 1_000), (3, 1_000)]);

        let mut scarce = FetchPlan::new(vec![cid(1), cid(2)], 4);
        record_with_fallback(&mut scarce, cid(1), &[2, 3], &ledger);
        record(&mut scarce, cid(2), &[2, 3], &ledger);

        let issued = scarce.next_requests();
        assert_eq!(
            issued.first().map(|(chunk, _)| *chunk),
            Some(cid(1)),
            "the chunk no holder is known for is the scarcest and goes first: {issued:?}"
        );
    }

    #[test]
    fn scarce_chunks_are_requested_before_plentiful_ones() {
        // §4.4 step 2. A plentiful chunk can wait: its holders are unlikely to
        // all vanish. A chunk held by one peer is the one at risk, so getting a
        // second copy into circulation is the urgent work.
        let ledger = ledger_with(&[(2, 1_000), (3, 1_000), (4, 1_000)]);
        let mut plan = FetchPlan::new([cid(1), cid(2), cid(3)], 1);

        record(&mut plan, cid(1), &[2, 3, 4], &ledger); // plentiful
        record(&mut plan, cid(2), &[2], &ledger); // scarce
        record(&mut plan, cid(3), &[2, 3], &ledger); // middling

        let first = plan.next_requests();
        assert_eq!(first.len(), 1, "concurrency of 1 should issue one request");
        assert_eq!(
            first[0].0,
            cid(2),
            "the chunk with a single holder should be requested first"
        );

        plan.record_received(cid(2));
        let second = plan.next_requests();
        assert_eq!(second[0].0, cid(3), "then the next scarcest");
    }

    #[test]
    fn requests_run_in_parallel_up_to_the_concurrency_limit() {
        // §4.4 step 4: a large object's fetch time is bounded by the swarm's
        // aggregate throughput, not one source's, which only happens if several
        // requests are genuinely outstanding at once.
        let ledger = ledger_with(&[(2, 1_000), (3, 1_000)]);
        let mut plan = FetchPlan::new([cid(1), cid(2), cid(3), cid(4), cid(5)], 3);
        for which in [cid(1), cid(2), cid(3), cid(4), cid(5)] {
            record(&mut plan, which, &[2, 3], &ledger);
        }

        let issued = plan.next_requests();
        assert_eq!(issued.len(), 3, "three should go out at once");
        assert_eq!(plan.inflight(), 3);

        assert!(
            plan.next_requests().is_empty(),
            "nothing more should be issued while at the limit"
        );

        plan.record_received(issued[0].0);
        assert_eq!(plan.next_requests().len(), 1, "one slot freed, one issued");
    }

    #[test]
    fn a_failed_source_is_retried_against_a_different_holder() {
        // §4.4 step 5. A corrupt or departed holder must cost a round trip, not
        // the chunk — otherwise a single bad peer can deny content it happens to
        // be ranked first for.
        let ledger = ledger_with(&[(2, 5_000), (3, 1_000)]);
        let mut plan = FetchPlan::new([cid(1)], 2);
        record(&mut plan, cid(1), &[2, 3], &ledger);

        let first = plan.next_requests();
        assert_eq!(first.len(), 1);
        let first_source = first[0].1;

        plan.record_failed(cid(1));
        assert!(!plan.is_complete(), "a failure is not the end of the chunk");

        let retry = plan.next_requests();
        assert_eq!(retry.len(), 1);
        assert_ne!(
            retry[0].1, first_source,
            "the retry must go to a different holder, not the one that just failed"
        );

        plan.record_received(cid(1));
        assert!(plan.is_complete());
        assert_eq!(plan.received(), vec![cid(1)]);
        assert!(plan.unavailable().is_empty());
    }

    #[test]
    fn a_chunk_whose_every_holder_fails_is_reported_not_retried_forever() {
        let ledger = ledger_with(&[(2, 1_000), (3, 1_000)]);
        let mut plan = FetchPlan::new([cid(1)], 2);
        record(&mut plan, cid(1), &[2, 3], &ledger);

        for _ in 0..2 {
            assert_eq!(plan.next_requests().len(), 1);
            plan.record_failed(cid(1));
        }

        assert!(
            plan.next_requests().is_empty(),
            "with every holder tried there is nobody left to ask"
        );
        assert!(plan.is_complete());
        assert_eq!(plan.unavailable(), vec![cid(1)]);
        assert!(plan.received().is_empty());
    }

    #[test]
    fn a_chunk_with_no_holders_completes_rather_than_hanging() {
        // "Nobody holds this" is an answer. A plan that treated it as still
        // pending would never report completion, and a caller waiting on the
        // whole object would wait forever for one missing chunk.
        let ledger = ledger_with(&[(2, 1_000)]);
        let mut plan = FetchPlan::new([cid(1), cid(2)], 2);
        record(&mut plan, cid(1), &[2], &ledger);
        record(&mut plan, cid(2), &[], &ledger);

        assert_eq!(plan.next_requests().len(), 1);
        plan.record_received(cid(1));

        assert!(plan.is_complete());
        assert_eq!(plan.received(), vec![cid(1)]);
        assert_eq!(plan.unavailable(), vec![cid(2)]);
    }

    #[test]
    fn a_holder_advertising_no_upload_capacity_is_not_asked() {
        // `select_sources` drops a peer offering no throughput: it holds the
        // bytes but has not volunteered to serve them. Worth pinning here
        // because the DHT will still report it as a provider, so the filtering
        // has to happen on this side.
        let ledger = ledger_with(&[(2, 0), (3, 1_000)]);
        let mut plan = FetchPlan::new([cid(1)], 2);
        record(&mut plan, cid(1), &[2, 3], &ledger);

        let issued = plan.next_requests();
        assert_eq!(issued.len(), 1);
        assert_eq!(
            issued[0].1,
            identity(3).id(),
            "only the holder that advertised upload capacity should be asked"
        );

        plan.record_failed(cid(1));
        assert!(
            plan.is_complete() && plan.unavailable() == vec![cid(1)],
            "with the only willing holder failed, the chunk is unavailable"
        );
    }

    #[test]
    fn providers_are_only_needed_once_per_chunk() {
        let ledger = ledger_with(&[(2, 1_000)]);
        let mut plan = FetchPlan::new([cid(1), cid(2)], 2);
        assert_eq!(plan.providers_needed().len(), 2);

        record(&mut plan, cid(1), &[2], &ledger);
        assert_eq!(plan.providers_needed(), vec![cid(2)]);

        // A late duplicate answer must not reset a chunk already in progress.
        plan.next_requests();
        record(&mut plan, cid(1), &[2], &ledger);
        assert_eq!(plan.inflight(), 1);
    }

    /// Issues every ready request and returns the chunks, in issue order.
    fn issue_all(plan: &mut FetchPlan) -> Vec<Cid> {
        plan.next_requests().into_iter().map(|(c, _)| c).collect()
    }

    #[test]
    fn a_budget_that_runs_out_abandons_the_rest_of_its_chunks() {
        // §4.4 step 6. A manifest declaring 100 bytes whose chunks hold far more
        // costs its declared size, not its contents: the chunk that would take
        // the fetch past it is refused, and nothing more is asked for.
        let ledger = ledger_with(&[(2, 1_000)]);
        let mut plan = FetchPlan::new(Vec::new(), 1);
        plan.extend_within(cid(9), [cid(1), cid(2), cid(3)], 100);
        for which in [cid(1), cid(2), cid(3)] {
            record(&mut plan, which, &[2], &ledger);
        }

        let first = issue_all(&mut plan);
        assert!(plan.admit(first[0], 60), "within the allowance is kept");
        plan.record_received(first[0]);

        let second = issue_all(&mut plan);
        assert!(!plan.admit(second[0], 60), "past the allowance is refused");
        assert!(
            issue_all(&mut plan).is_empty(),
            "and nothing more is asked for"
        );
        assert!(plan.is_complete(), "an abandoned chunk ends the fetch");
        assert_eq!(plan.received(), vec![first[0]]);
        assert_eq!(plan.over_budget().len(), 2);
        assert_eq!(plan.inflight(), 0, "the refused request freed its slot");
        assert_eq!(plan.overrun_objects(), vec![cid(9)]);
    }

    #[test]
    fn a_chunk_the_plan_never_asked_for_is_not_its_to_refuse() {
        // A caller's one-off request shares the connection and the response
        // path with the plan. Its bytes are not the plan's to weigh, and nor is
        // a second response for a chunk already done.
        let ledger = ledger_with(&[(2, 1_000)]);
        let mut plan = FetchPlan::new(Vec::new(), 1);
        plan.extend_within(cid(9), [cid(1)], 10);
        record(&mut plan, cid(1), &[2], &ledger);
        assert!(
            plan.admit(cid(5), 1_000),
            "a chunk outside the plan is kept"
        );

        let issued = issue_all(&mut plan);
        assert!(plan.admit(issued[0], 10));
        plan.record_received(issued[0]);
        assert!(
            plan.admit(issued[0], 10),
            "a duplicate is not charged again"
        );
        assert!(plan.overrun_objects().is_empty());
        assert_eq!(plan.received(), vec![cid(1)]);
    }

    #[test]
    fn a_chunk_in_flight_when_its_budget_ran_out_is_not_sent_again() {
        // The request was out before the budget ran out, so it is let finish.
        // If it fails, retrying it with the next holder would fetch bytes the
        // plan has already decided not to keep.
        let ledger = ledger_with(&[(2, 1_000), (3, 1_000)]);
        let mut plan = FetchPlan::new(Vec::new(), 2);
        plan.extend_within(cid(9), [cid(1), cid(2)], 50);
        record(&mut plan, cid(1), &[2, 3], &ledger);
        record(&mut plan, cid(2), &[2, 3], &ledger);

        let issued = issue_all(&mut plan);
        assert_eq!(issued.len(), 2);
        assert!(!plan.admit(issued[0], 60), "the first response runs it out");
        plan.record_failed(issued[1]);
        assert!(issue_all(&mut plan).is_empty(), "the other is not retried");
        assert!(plan.is_complete());
        assert_eq!(plan.over_budget().len(), 2);
        assert!(
            plan.unavailable().is_empty(),
            "it was abandoned, not unfindable"
        );
    }

    #[test]
    fn a_chunk_abandoned_for_one_object_is_fetched_again_for_another() {
        // Content addressing means a liar can name an honest chunk. Once the
        // liar's budget abandons it, an honest object wanting it later must
        // still get it.
        let ledger = ledger_with(&[(2, 1_000)]);
        let mut plan = FetchPlan::new(Vec::new(), 1);
        plan.extend_within(cid(8), [cid(1), cid(2)], 10);
        record(&mut plan, cid(1), &[2], &ledger);
        record(&mut plan, cid(2), &[2], &ledger);
        let first = issue_all(&mut plan)[0];
        assert!(!plan.admit(first, 50));
        assert_eq!(plan.over_budget().len(), 2);

        plan.extend_within(cid(9), [cid(1), cid(2)], 1_000);
        assert_eq!(plan.providers_needed().len(), 2, "both are wanted again");
        record(&mut plan, cid(1), &[2], &ledger);
        record(&mut plan, cid(2), &[2], &ledger);
        while let Some(&next) = issue_all(&mut plan).first() {
            assert!(plan.admit(next, 50));
            plan.record_received(next);
        }
        assert_eq!(plan.received().len(), 2);
        assert_eq!(plan.overrun_objects(), vec![cid(8)]);
    }

    #[test]
    fn a_budget_with_room_rescues_a_chunk_an_exhausted_one_shares() {
        // The same rescue as below, with no unbudgeted caller to lean on: only
        // the other object's room keeps the shared chunk wanted.
        let ledger = ledger_with(&[(2, 1_000)]);
        let mut plan = FetchPlan::new(Vec::new(), 1);
        plan.extend_within(cid(8), [cid(1), cid(3)], 10);
        plan.extend_within(cid(9), [cid(2), cid(3)], 1_000);
        for which in [cid(1), cid(2), cid(3)] {
            record(&mut plan, which, &[2], &ledger);
        }
        while let Some(&next) = issue_all(&mut plan).first() {
            if plan.admit(next, 50) {
                plan.record_received(next);
            }
        }
        assert!(plan.received().contains(&cid(2)) && plan.received().contains(&cid(3)));
        assert!(!plan.received().contains(&cid(1)));
        assert_eq!(plan.overrun_objects(), vec![cid(8)]);
    }

    #[test]
    fn a_chunk_another_caller_still_wants_is_not_abandoned() {
        // A manifest that lies about its size can name somebody else's honest
        // chunk. Running out its budget must not cost the other object that
        // chunk, or one bad manifest starves content it shares.
        let ledger = ledger_with(&[(2, 1_000)]);
        let mut plan = FetchPlan::new([cid(3)], 1);
        plan.extend_within(cid(8), [cid(1), cid(3)], 10);
        plan.extend_within(cid(9), [cid(2), cid(3)], 1_000);
        for which in [cid(1), cid(2), cid(3)] {
            record(&mut plan, which, &[2], &ledger);
        }

        let mut seen = Vec::new();
        while let Some(&next) = issue_all(&mut plan).first() {
            let kept = plan.admit(next, 50);
            if kept {
                plan.record_received(next);
            }
            seen.push((next, kept));
        }
        assert!(plan.is_complete());
        assert!(
            plan.received().contains(&cid(2)) && plan.received().contains(&cid(3)),
            "both chunks someone with room wanted arrive: {seen:?}"
        );
        assert!(
            !plan.received().contains(&cid(1)),
            "the chunk only the exhausted budget wanted does not: {seen:?}"
        );
        assert_eq!(plan.overrun_objects(), vec![cid(8)]);
    }

    #[test]
    fn an_honest_object_fetches_whole_at_exactly_its_budget() {
        // The bound is inclusive. An honest manifest's chunks sum to exactly
        // its ciphertext bound, so a budget that refused at equality would
        // refuse every honest object.
        let ledger = ledger_with(&[(2, 1_000)]);
        let mut plan = FetchPlan::new(Vec::new(), 2);
        plan.extend_within(cid(9), [cid(1), cid(2)], 80);
        record(&mut plan, cid(1), &[2], &ledger);
        record(&mut plan, cid(2), &[2], &ledger);
        for which in issue_all(&mut plan) {
            assert!(plan.admit(which, 40));
            plan.record_received(which);
        }
        assert!(plan.is_complete());
        assert!(plan.over_budget().is_empty());
        assert!(plan.overrun_objects().is_empty());
    }
}
