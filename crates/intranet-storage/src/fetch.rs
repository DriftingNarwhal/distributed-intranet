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

use crate::serving::{SourceCandidate, select_sources};
use crate::{Cid, rarest_first};
use intranet_identity::PerNetworkIdentityId;
use intranet_ledger::{CapabilityLedger, ReliabilityObservations};
use std::collections::{BTreeMap, VecDeque};

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
}

/// A multi-source fetch in progress.
#[derive(Debug, Clone)]
pub struct FetchPlan {
    chunks: BTreeMap<Cid, ChunkState>,
    concurrency: usize,
    inflight: usize,
}

impl FetchPlan {
    /// Starts a plan for `cids`.
    pub fn new(cids: impl IntoIterator<Item = Cid>, concurrency: usize) -> Self {
        Self {
            chunks: cids
                .into_iter()
                .map(|cid| (cid, ChunkState::AwaitingProviders))
                .collect(),
            // A concurrency of zero would stall silently, which is a worse
            // outcome than quietly correcting an obviously unintended value.
            concurrency: concurrency.max(1),
            inflight: 0,
        }
    }

    /// Adds more chunks to an existing plan.
    pub fn extend(&mut self, cids: impl IntoIterator<Item = Cid>) {
        for cid in cids {
            self.chunks
                .entry(cid)
                .or_insert(ChunkState::AwaitingProviders);
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
    pub fn record_providers(
        &mut self,
        cid: Cid,
        providers: Vec<PerNetworkIdentityId>,
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
        let ordered = order_sources(providers, ledger, observations, failure_threshold);
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

    /// Records that a source did not produce the bytes.
    ///
    /// The chunk returns to the queue against its remaining candidates, so one
    /// bad or departed holder costs a round trip rather than the chunk. Only
    /// when every known holder has been tried is it given up on — and even then
    /// the plan reports it rather than failing, since a caller may well want the
    /// chunks it *did* get.
    pub fn record_failed(&mut self, cid: Cid) {
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
        *state = if candidates.is_empty() {
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
        self.chunks
            .values()
            .all(|state| matches!(state, ChunkState::Done | ChunkState::Exhausted))
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
        MasterSeed::from_entropy([n; 32]).identity_for(&NETWORK).unwrap()
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

    fn record(
        plan: &mut FetchPlan,
        which: Cid,
        providers: &[u8],
        ledger: &CapabilityLedger,
    ) {
        plan.record_providers(
            which,
            providers.iter().map(|s| identity(*s).id()).collect(),
            ledger,
            &ReliabilityObservations::new(),
            0.5,
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
}
