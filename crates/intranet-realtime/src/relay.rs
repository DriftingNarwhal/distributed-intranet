//! Media relay selection — Real-Time Spec §2.1, §2.3.
//!
//! # A different role from bootstrap relaying
//!
//! Bootstrap relaying helps two NAT'd peers establish a connection and then gets
//! out of the way: short-lived, low continuous bandwidth. Media relaying
//! continuously forwards encrypted audio and video for the duration of a call:
//! sustained bandwidth, latency-sensitive. A node may offer either, both, or
//! neither, and conflating them would put a node that volunteered for a few
//! seconds of hole-punch assistance on the hook for an hour-long call.

use intranet_identity::PerNetworkIdentityId;
use intranet_ledger::{CapabilityLedger, ReliabilityObservations};
use std::collections::BTreeMap;

/// One participant's measurement of one candidate relay.
///
/// Latency is measured per participant because a relay's suitability is not a
/// property of the relay alone — it is a property of the relay *relative to this
/// call's participants*, who may be scattered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayObservation {
    /// The candidate relay.
    pub relay: PerNetworkIdentityId,
    /// The participant who measured it.
    pub participant: PerNetworkIdentityId,
    /// Observed round-trip latency in milliseconds.
    pub latency_millis: u32,
}

/// A selected relay and the figures behind the choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayChoice {
    /// The chosen relay.
    pub relay: PerNetworkIdentityId,
    /// The worst latency any participant measured to it.
    pub worst_latency_millis: u32,
    /// Its declared upload capacity.
    pub upload_capacity: u64,
}

/// Selects a relay for a call — §2.3.
///
/// # Why the worst case rather than the average
///
/// A call is only as good as its least well-served participant. A relay two
/// milliseconds from three people and four hundred from the fourth is a bad
/// choice, and averaging hides exactly that. Minimising the maximum is what
/// "evaluated collectively across all current participants' vantage points"
/// means in practice — the spec is explicit that this is not the proposer's own
/// view alone. **Flagged: the specs do not prescribe an aggregation function;
/// worst-case is a deliberate choice.**
///
/// Latency dominates capacity here, unlike static content selection where it
/// barely matters: a relay that is fast but modest serves a call better than one
/// that is capacious but distant, because conversation breaks on delay long
/// before it breaks on throughput.
///
/// Local reliability observations participate, which is legitimate precisely
/// because this is a local, per-call decision with no cross-node consistency
/// requirement — §1.4's proposal and tie-break already resolve disagreement
/// between participants. That is what distinguishes it from stream first-tier
/// assignment, which must be computed identically everywhere and therefore
/// cannot use the signal at all.
pub fn select(
    observations: &[RelayObservation],
    participants: &std::collections::BTreeSet<PerNetworkIdentityId>,
    ledger: &CapabilityLedger,
    reliability: &ReliabilityObservations,
    failure_threshold: f64,
) -> Option<RelayChoice> {
    // Worst observed latency per candidate, plus how many participants reported.
    let mut worst: BTreeMap<PerNetworkIdentityId, (u32, usize)> = BTreeMap::new();
    for observation in observations {
        if !participants.contains(&observation.participant) {
            continue;
        }
        let entry = worst.entry(observation.relay).or_insert((0, 0));
        entry.0 = entry.0.max(observation.latency_millis);
        entry.1 += 1;
    }

    let mut ranked: Vec<(RelayChoice, u8)> = worst
        .into_iter()
        .filter_map(|(relay, (worst_latency, reporters))| {
            // A candidate not measured by every participant is skipped: an
            // unmeasured leg could be the bad one, and choosing on partial
            // information is how the worst-case criterion gets quietly defeated.
            if reporters < participants.len() {
                return None;
            }
            let advertisement = ledger.get(&relay)?;
            // Only nodes that volunteered for *media* relaying, never bootstrap
            // relays pressed into a role they did not offer.
            if !advertisement.relay_media_willing {
                return None;
            }
            let upload_capacity = advertisement.bandwidth_cap.up_bytes_per_sec;
            if upload_capacity == 0 {
                return None;
            }

            let reliability_band = match reliability.for_peer(&relay).failure_rate() {
                Some(rate) if rate >= failure_threshold => 2u8,
                None => 1,
                Some(_) => 0,
            };

            Some((
                RelayChoice {
                    relay,
                    worst_latency_millis: worst_latency,
                    upload_capacity,
                },
                reliability_band,
            ))
        })
        .collect();

    ranked.sort_by(|a, b| {
        a.1.cmp(&b.1)
            .then_with(|| a.0.worst_latency_millis.cmp(&b.0.worst_latency_millis))
            .then_with(|| b.0.upload_capacity.cmp(&a.0.upload_capacity))
            .then_with(|| a.0.relay.cmp(&b.0.relay))
    });

    ranked.into_iter().next().map(|(choice, _)| choice)
}

/// Candidate relays a network currently offers.
pub fn candidates(ledger: &CapabilityLedger) -> Vec<PerNetworkIdentityId> {
    ledger
        .media_relay_candidates()
        .map(|advertisement| advertisement.node)
        .collect()
}
