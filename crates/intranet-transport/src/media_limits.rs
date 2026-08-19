//! Media relay resource ceilings — Real-Time Spec §2.2.1, Core Protocol Spec §4.3.
//!
//! # The gap this closes
//!
//! A node advertises what it will contribute — `relay_media_willing`, and a
//! `bandwidth_cap` it declares alongside it (§4.2). Until this module, that
//! advertisement was read by everybody *except* the node that made it: it drove
//! relay selection and swarm source selection, so other nodes avoided a
//! saturated peer, while the peer itself enforced nothing. A volunteer could
//! declare 256 KiB/s and then carry every call it was asked to.
//!
//! That was tolerable while a relay forwarded one envelope for each one it
//! received. Fan-out (§2.2.1) changed the arithmetic: one accepted envelope now
//! costs the volunteer N−1 sends, so the gap between what a node promised and
//! what it can be asked to do became a multiplier. §2.2.1 says amplification is
//! "bounded by the relay's own agreement" and that a relay wanting a ceiling
//! "enforces it locally". This is that enforcement.
//!
//! # Why local rather than network policy
//!
//! These are per-node resource decisions with no cross-node consistency
//! requirement, which is the same reasoning §2.3 gives for relay selection being
//! local. Two relays choosing different ceilings costs nothing: a call whose
//! relay refuses simply selects another, exactly as it would if that relay were
//! offline. Making them network policy would mean a network could compel a
//! member to spend bandwidth it never offered — the opposite of §4.3's opt-in.
//!
//! # A denied verdict that cannot be ignored
//!
//! [`crate::relay_limits`] names the bug it was built against: a limiter that
//! computed a decision and never enforced it. The same structural answer applies
//! here. [`MediaRelayGuard::authorize`] is the **only** way to learn who a frame
//! should be forwarded to — the participant set lives in the guard and nowhere
//! else — and it charges the allowance in the same call that answers. A caller
//! cannot obtain recipients without paying for them, and cannot pay without
//! being told whether it may proceed.
//!
//! # Why the byte ceiling is refilled by an explicit call
//!
//! A rate is a quantity per unit time, and this crate's node deliberately holds
//! no clock — timestamps are passed in so the harness can drive a virtual one.
//! So the bucket is refilled by [`MediaRelayGuard::refill`] rather than by
//! reading the time when a frame arrives. The consequence is worth stating
//! plainly: a caller that never refills will forward until the burst allowance
//! is spent and then refuse everything. That is fail-closed, which is the right
//! direction for a resource limiter to fail, but it is a real obligation on the
//! caller rather than something this type can guarantee alone.

use intranet_crypto::Timestamp;
use intranet_identity::PerNetworkIdentityId;
use intranet_ledger::BandwidthCap;
use intranet_realtime::{CallId, Recipient};
use std::collections::{BTreeMap, BTreeSet};

/// Configured ceilings for the media relay role.
///
/// Defaults are deliberately modest. **Flagged: the specs give no numbers for
/// any of these** — §2.2.1 states that a ceiling is a local choice and declines
/// to prescribe one, so these are starting values a deployment is expected to
/// raise or lower, not constants with authority behind them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MediaRelayLimits {
    /// Concurrent calls this node will carry.
    ///
    /// Media relaying is sustained for a call's duration, unlike a bootstrap
    /// circuit which is capped at two minutes and eight megabytes
    /// ([`crate::relay_limits`]). A small number of simultaneous calls is
    /// therefore a much larger commitment than the same number of circuits.
    pub max_calls: u32,

    /// Participants in any one call this node will carry.
    ///
    /// This is the amplification factor, and bounding it is the point: with
    /// fan-out, one inbound envelope becomes one send per other participant, so
    /// the participant count *is* the multiplier applied to every frame.
    ///
    /// The default is 50 because that is where §1.2 and §4 already place the
    /// boundary — past roughly fifty the call path is the wrong primitive
    /// regardless of how well the relay fans out, and the answer is the
    /// live-stream path rather than a bigger relay.
    pub max_participants_per_call: u32,

    /// Sustained bytes per second this node will forward, across all calls.
    ///
    /// Charged against what actually leaves the node — frame size times the
    /// number of recipients — because that is what fan-out spends.
    pub forward_bytes_per_sec: u64,

    /// Bytes the allowance may accumulate to while idle.
    ///
    /// Media arrives in frames rather than in a smooth stream, so a bucket with
    /// no burst room refuses ordinary traffic. This is the tolerance for that,
    /// not extra capacity.
    pub burst_bytes: u64,
}

impl Default for MediaRelayLimits {
    fn default() -> Self {
        Self {
            max_calls: 8,
            max_participants_per_call: 50,
            forward_bytes_per_sec: 1024 * 1024,
            burst_bytes: 2 * 1024 * 1024,
        }
    }
}

impl MediaRelayLimits {
    /// Ceilings that do not exceed what this node advertised.
    ///
    /// The advertisement is a public promise about upload capacity (§4.2) and
    /// this is what makes it binding on the node that made it. Note the
    /// direction: this never raises the byte ceiling above the declared cap, so
    /// a node cannot be held to more than it offered, and a node offering
    /// nothing forwards nothing.
    pub fn within(cap: &BandwidthCap) -> Self {
        let default = Self::default();
        Self {
            forward_bytes_per_sec: cap.up_bytes_per_sec,
            burst_bytes: cap.up_bytes_per_sec.saturating_mul(2),
            ..default
        }
    }
}

/// Why a media relay refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MediaRelayDenied {
    /// This node is already carrying as many calls as it agreed to.
    #[error("relay is carrying its ceiling of {limit} calls")]
    CallCeiling {
        /// The configured ceiling.
        limit: u32,
    },

    /// The call has more participants than this node will fan out to.
    #[error("call has {requested} participants, above the ceiling of {limit}")]
    ParticipantCeiling {
        /// The configured ceiling.
        limit: u32,
        /// How many were asked for.
        requested: usize,
    },

    /// This node never agreed to carry the call.
    ///
    /// The check that stops a media relay being an open reflector: without it,
    /// anyone knowing this node's address could have it forward arbitrary
    /// traffic at this node's expense and with this node's address on it.
    #[error("not carrying this call")]
    NotCarried,

    /// The frame's sender is not in the call.
    ///
    /// Under fan-out this is the only sender check there is, since the envelope
    /// names no recipient to check instead (§2.2.1 rule 2).
    #[error("sender is not a participant of this call")]
    SenderNotParticipant,

    /// A named envelope was addressed outside the call.
    #[error("recipient is not a participant of this call")]
    RecipientNotParticipant,

    /// Forwarding this frame would exceed the byte allowance.
    #[error("forwarding {needed} bytes exceeds the {available} available")]
    AllowanceExhausted {
        /// What the fan-out would have cost.
        needed: u64,
        /// What was left.
        available: u64,
    },
}

/// Who a frame should go to, and whether this node is one of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FanOut {
    /// Participants to send a copy to, already excluding the sender and this
    /// node. Each copy is readdressed by the caller (§2.2.1 rule 4).
    pub recipients: Vec<PerNetworkIdentityId>,
    /// Whether this node is a participant and should receive the frame itself.
    ///
    /// A participant carrying the call for the others is a sensible topology,
    /// and it costs no upload — which is why it is reported separately rather
    /// than folded into `recipients` and charged for.
    pub deliver_locally: bool,
}

/// Enforces what a node agreed to spend on relaying media.
///
/// Holds the participant set for every carried call, which is the entirety of
/// what a blind relay knows about one: no key, and no place to put one.
#[derive(Debug, Clone)]
pub struct MediaRelayGuard {
    limits: MediaRelayLimits,
    calls: BTreeMap<CallId, BTreeSet<PerNetworkIdentityId>>,
    allowance: u64,
    last_refill: Option<Timestamp>,
    forwarded_bytes: u64,
    refusals: u64,
}

impl MediaRelayGuard {
    /// A guard with the given ceilings, starting with a full allowance.
    pub fn new(limits: MediaRelayLimits) -> Self {
        Self {
            allowance: limits.burst_bytes,
            limits,
            calls: BTreeMap::new(),
            last_refill: None,
            forwarded_bytes: 0,
            refusals: 0,
        }
    }

    /// The ceilings in force.
    pub fn limits(&self) -> &MediaRelayLimits {
        &self.limits
    }

    /// Replaces the ceilings, keeping the calls already being carried.
    ///
    /// Lowering a ceiling below what is already in flight does **not** drop
    /// anything: this node agreed to those calls, and tearing them down because
    /// a setting changed would turn a preference into a hangup with no
    /// explanation at the other end. New calls are refused until the count is
    /// back under the ceiling, which is the same shape as any other full
    /// resource.
    ///
    /// The byte allowance is clamped to the new burst, so lowering a cap takes
    /// effect immediately rather than after the old, larger allowance drains.
    /// Raising one deliberately grants nothing: allowance is earned from elapsed
    /// time by [`refill`](Self::refill), and a config change that minted it
    /// would be a rate limit anyone could step around by toggling a setting.
    pub fn set_limits(&mut self, limits: MediaRelayLimits) {
        self.limits = limits;
        self.allowance = self.allowance.min(limits.burst_bytes);
    }

    /// Agrees to carry a call, if the ceilings allow it.
    ///
    /// The participant set is the entirety of what a relay is told, and it is
    /// what fan-out replicates to. Re-agreeing to a call already carried
    /// replaces its participant set rather than counting against the call
    /// ceiling again — that is how a roster change reaches the relay.
    pub fn try_carry(
        &mut self,
        call: CallId,
        participants: impl IntoIterator<Item = PerNetworkIdentityId>,
    ) -> Result<(), MediaRelayDenied> {
        let participants: BTreeSet<_> = participants.into_iter().collect();
        if participants.len() > self.limits.max_participants_per_call as usize {
            self.refusals += 1;
            return Err(MediaRelayDenied::ParticipantCeiling {
                limit: self.limits.max_participants_per_call,
                requested: participants.len(),
            });
        }
        let known = self.calls.contains_key(&call);
        if !known && self.calls.len() >= self.limits.max_calls as usize {
            self.refusals += 1;
            return Err(MediaRelayDenied::CallCeiling {
                limit: self.limits.max_calls,
            });
        }
        self.calls.insert(call, participants);
        Ok(())
    }

    /// Stops carrying a call.
    pub fn stop_carrying(&mut self, call: &CallId) {
        self.calls.remove(call);
    }

    /// Whether this node is carrying `call`.
    pub fn is_carrying(&self, call: &CallId) -> bool {
        self.calls.contains_key(call)
    }

    /// How many calls are being carried.
    pub fn call_count(&self) -> usize {
        self.calls.len()
    }

    /// Decides where a frame goes, and charges what sending it will cost.
    ///
    /// This is the only way to obtain recipients: the participant set lives here
    /// and nowhere else, so there is no path by which a caller forwards a frame
    /// this method did not authorize and meter.
    ///
    /// A fan-out that would exceed the allowance is refused **whole**. Forwarding
    /// to some participants and not others would turn a bandwidth ceiling into
    /// silent, one-sided call degradation, which is harder to diagnose than a
    /// refusal and worse to experience.
    pub fn authorize(
        &mut self,
        call: &CallId,
        from: &PerNetworkIdentityId,
        to: &Recipient,
        frame_bytes: usize,
        self_id: &PerNetworkIdentityId,
    ) -> Result<FanOut, MediaRelayDenied> {
        let Some(participants) = self.calls.get(call) else {
            self.refusals += 1;
            return Err(MediaRelayDenied::NotCarried);
        };
        if !participants.contains(from) {
            self.refusals += 1;
            return Err(MediaRelayDenied::SenderNotParticipant);
        }

        let (recipients, deliver_locally) = match to {
            Recipient::Participants => (
                participants
                    .iter()
                    .filter(|id| *id != from && *id != self_id)
                    .copied()
                    .collect::<Vec<_>>(),
                participants.contains(self_id),
            ),
            Recipient::One(target) if participants.contains(target) => (vec![*target], false),
            Recipient::One(_) => {
                self.refusals += 1;
                return Err(MediaRelayDenied::RecipientNotParticipant);
            }
        };

        // What leaves the node, not what arrived at it. Under fan-out those
        // differ by the participant count, and charging the inbound size would
        // under-meter by exactly the factor this ceiling exists to bound.
        let cost = (frame_bytes as u64).saturating_mul(recipients.len() as u64);
        if cost > self.allowance {
            self.refusals += 1;
            return Err(MediaRelayDenied::AllowanceExhausted {
                needed: cost,
                available: self.allowance,
            });
        }
        self.allowance -= cost;
        self.forwarded_bytes += cost;

        Ok(FanOut {
            recipients,
            deliver_locally,
        })
    }

    /// Refills the byte allowance for the time elapsed since the last refill.
    ///
    /// The first call establishes the baseline and grants nothing, since there
    /// is no elapsed interval to earn against yet.
    pub fn refill(&mut self, now: Timestamp) {
        let Some(last) = self.last_refill else {
            self.last_refill = Some(now);
            return;
        };
        let elapsed = now.millis_since(last);
        if elapsed <= 0 {
            // A clock that went backwards must not mint allowance. Rebase on the
            // earlier reading and wait for it to advance.
            self.last_refill = Some(now);
            return;
        }
        let earned = (self.limits.forward_bytes_per_sec as u128)
            .saturating_mul(elapsed as u128)
            / 1000;
        let earned = u64::try_from(earned).unwrap_or(u64::MAX);
        self.allowance = self
            .allowance
            .saturating_add(earned)
            .min(self.limits.burst_bytes);
        self.last_refill = Some(now);
    }

    /// Bytes currently available to forward.
    pub fn allowance(&self) -> u64 {
        self.allowance
    }

    /// Bytes forwarded over this guard's lifetime.
    ///
    /// Reported so an operator can see what relaying actually cost them, which
    /// is the figure a contribution setting is really about.
    pub fn forwarded_bytes(&self) -> u64 {
        self.forwarded_bytes
    }

    /// How many requests this guard refused.
    ///
    /// Observable on purpose: a refusal that only appears in a log is
    /// indistinguishable from a limiter that never ran.
    pub fn refusals(&self) -> u64 {
        self.refusals
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use intranet_identity::{MasterSeed, NetworkId};

    const NETWORK: NetworkId = NetworkId::from_bytes([9u8; 32]);

    fn id(n: u8) -> PerNetworkIdentityId {
        MasterSeed::from_entropy([n; 32])
            .identity_for(&NETWORK)
            .unwrap()
            .id()
    }

    fn call(n: u8) -> CallId {
        CallId::from_bytes([n; 32])
    }

    fn guard() -> MediaRelayGuard {
        MediaRelayGuard::new(MediaRelayLimits::default())
    }

    #[test]
    fn a_call_beyond_the_ceiling_is_refused() {
        let mut g = MediaRelayGuard::new(MediaRelayLimits {
            max_calls: 2,
            ..MediaRelayLimits::default()
        });
        assert!(g.try_carry(call(1), [id(1), id(2)]).is_ok());
        assert!(g.try_carry(call(2), [id(1), id(2)]).is_ok());
        assert_eq!(
            g.try_carry(call(3), [id(1), id(2)]).unwrap_err(),
            MediaRelayDenied::CallCeiling { limit: 2 }
        );
        assert_eq!(g.call_count(), 2, "a refused call is not carried");
    }

    #[test]
    fn re_agreeing_to_a_carried_call_updates_its_roster_without_spending_a_slot() {
        // A roster change reaches the relay by re-agreeing. If that counted
        // against the call ceiling, a call whose membership churned would
        // eventually be refused by a relay already carrying it.
        let mut g = MediaRelayGuard::new(MediaRelayLimits {
            max_calls: 1,
            ..MediaRelayLimits::default()
        });
        g.try_carry(call(1), [id(1), id(2)]).unwrap();
        g.try_carry(call(1), [id(1), id(2), id(3)]).unwrap();
        assert_eq!(g.call_count(), 1);

        let fan = g.authorize(&call(1), &id(1), &Recipient::Participants, 10, &id(9)).unwrap();
        assert_eq!(fan.recipients.len(), 2, "the new participant is included");
    }

    #[test]
    fn a_call_with_too_many_participants_is_refused() {
        // The participant count is the amplification factor, so this is the
        // ceiling that actually bounds what one envelope can cost.
        let mut g = MediaRelayGuard::new(MediaRelayLimits {
            max_participants_per_call: 3,
            ..MediaRelayLimits::default()
        });
        assert_eq!(
            g.try_carry(call(1), [id(1), id(2), id(3), id(4)]).unwrap_err(),
            MediaRelayDenied::ParticipantCeiling {
                limit: 3,
                requested: 4
            }
        );
        assert!(!g.is_carrying(&call(1)));
    }

    #[test]
    fn changing_the_ceilings_does_not_drop_calls_already_being_carried() {
        // A relay that forgot its calls when a setting changed would hang up on
        // everyone with no explanation at the far end. Lowering a ceiling stops
        // this node taking *new* work; it does not retract agreement already
        // given.
        let mut g = guard();
        g.try_carry(call(1), [id(1), id(2)]).unwrap();
        g.try_carry(call(2), [id(1), id(2)]).unwrap();

        g.set_limits(MediaRelayLimits {
            max_calls: 1,
            burst_bytes: 500,
            ..MediaRelayLimits::default()
        });

        assert!(g.is_carrying(&call(1)), "an in-flight call survives");
        assert!(g.is_carrying(&call(2)));
        assert!(
            g.authorize(&call(1), &id(1), &Recipient::Participants, 10, &id(9)).is_ok(),
            "and keeps being forwarded"
        );
        assert_eq!(
            g.try_carry(call(3), [id(1), id(2)]).unwrap_err(),
            MediaRelayDenied::CallCeiling { limit: 1 },
            "while a new call is refused until the count comes down"
        );
        assert!(
            g.allowance() <= 500,
            "and a lowered byte cap binds now, not once the old allowance drains"
        );
    }

    #[test]
    fn the_allowance_is_charged_for_what_leaves_not_for_what_arrived() {
        // The whole point of metering a relay under fan-out: one inbound frame
        // of N bytes costs N × recipients on the way out, and charging the
        // inbound size would under-meter by exactly the multiplier.
        let mut g = guard();
        g.try_carry(call(1), [id(1), id(2), id(3), id(4)]).unwrap();
        let before = g.allowance();

        let fan = g.authorize(&call(1), &id(1), &Recipient::Participants, 1000, &id(9)).unwrap();

        assert_eq!(fan.recipients.len(), 3, "everyone but the sender");
        assert_eq!(before - g.allowance(), 3000, "charged three copies, not one");
        assert_eq!(g.forwarded_bytes(), 3000);
    }

    #[test]
    fn a_fan_out_beyond_the_allowance_is_refused_whole() {
        // Not partially. Forwarding to some participants and not others turns a
        // bandwidth ceiling into one-sided call degradation, which is worse to
        // experience and harder to diagnose than a refusal.
        let mut g = MediaRelayGuard::new(MediaRelayLimits {
            burst_bytes: 1000,
            forward_bytes_per_sec: 0,
            ..MediaRelayLimits::default()
        });
        g.try_carry(call(1), [id(1), id(2), id(3)]).unwrap();

        let err = g
            .authorize(&call(1), &id(1), &Recipient::Participants, 600, &id(9))
            .unwrap_err();
        assert_eq!(
            err,
            MediaRelayDenied::AllowanceExhausted {
                needed: 1200,
                available: 1000
            }
        );
        assert_eq!(g.allowance(), 1000, "a refused fan-out costs nothing");
    }

    #[test]
    fn the_allowance_refills_at_the_declared_rate_and_stops_at_the_burst() {
        let mut g = MediaRelayGuard::new(MediaRelayLimits {
            forward_bytes_per_sec: 1000,
            burst_bytes: 2000,
            ..MediaRelayLimits::default()
        });
        g.try_carry(call(1), [id(1), id(2)]).unwrap();
        g.authorize(&call(1), &id(1), &Recipient::Participants, 2000, &id(9)).unwrap();
        assert_eq!(g.allowance(), 0);

        // The first refill only establishes the baseline.
        g.refill(Timestamp::from_millis(0));
        assert_eq!(g.allowance(), 0, "nothing is earned before time passes");

        g.refill(Timestamp::from_millis(500));
        assert_eq!(g.allowance(), 500, "half a second earns half the rate");

        g.refill(Timestamp::from_millis(60_000));
        assert_eq!(
            g.allowance(),
            2000,
            "a long idle period accumulates to the burst ceiling and no further"
        );
    }

    #[test]
    fn a_clock_that_goes_backwards_mints_nothing() {
        let mut g = MediaRelayGuard::new(MediaRelayLimits {
            forward_bytes_per_sec: 1000,
            burst_bytes: 1000,
            ..MediaRelayLimits::default()
        });
        g.try_carry(call(1), [id(1), id(2)]).unwrap();
        g.authorize(&call(1), &id(1), &Recipient::Participants, 1000, &id(9)).unwrap();
        g.refill(Timestamp::from_millis(10_000));
        g.refill(Timestamp::from_millis(5_000));
        assert_eq!(g.allowance(), 0);

        // And recovers normally once the clock advances past the rebased point.
        g.refill(Timestamp::from_millis(5_500));
        assert_eq!(g.allowance(), 500);
    }

    #[test]
    fn an_uncarried_call_and_a_stranger_are_both_refused() {
        let mut g = guard();
        assert_eq!(
            g.authorize(&call(1), &id(1), &Recipient::Participants, 10, &id(9))
                .unwrap_err(),
            MediaRelayDenied::NotCarried
        );

        g.try_carry(call(1), [id(1), id(2)]).unwrap();
        assert_eq!(
            g.authorize(&call(1), &id(7), &Recipient::Participants, 10, &id(9))
                .unwrap_err(),
            MediaRelayDenied::SenderNotParticipant
        );
        assert_eq!(
            g.authorize(&call(1), &id(1), &Recipient::One(id(7)), 10, &id(9))
                .unwrap_err(),
            MediaRelayDenied::RecipientNotParticipant
        );
        assert_eq!(g.refusals(), 3, "every refusal is counted");
    }

    #[test]
    fn a_carrier_that_is_a_participant_is_delivered_to_but_not_charged_for() {
        let mut g = guard();
        let carrier = id(9);
        g.try_carry(call(1), [id(1), id(2), carrier]).unwrap();
        let before = g.allowance();

        let fan = g.authorize(&call(1), &id(1), &Recipient::Participants, 100, &carrier).unwrap();

        assert!(fan.deliver_locally, "the carrier is in the call");
        assert_eq!(fan.recipients, vec![id(2)], "and is not sent to over the wire");
        assert_eq!(before - g.allowance(), 100, "one copy, not two");
    }

    #[test]
    fn limits_never_promise_more_upload_than_was_advertised() {
        let cap = BandwidthCap {
            up_bytes_per_sec: 65_536,
            down_bytes_per_sec: 1_000_000,
            active_window: None,
        };
        let limits = MediaRelayLimits::within(&cap);
        assert_eq!(limits.forward_bytes_per_sec, 65_536);

        // A node that offered nothing forwards nothing, rather than falling back
        // to a default it never agreed to.
        let none = MediaRelayLimits::within(&BandwidthCap::NONE);
        assert_eq!(none.forward_bytes_per_sec, 0);
        assert_eq!(none.burst_bytes, 0);
    }
}
