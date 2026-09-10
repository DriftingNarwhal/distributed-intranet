//! Per-sender metering for direct delivery — Core Protocol Spec §5.1.
//!
//! A carrier that hands one member's bytes to another is a spam channel unless
//! something bounds it, and spec 07 §6.2 says so in as many words about the
//! first consumer: *rate limiting applies per sending identity, or the protocol
//! becomes a spam channel*.
//!
//! # Keyed by identity, not by peer id
//!
//! Core §5.3 settles this for relays and the reasoning transfers unchanged: a
//! libp2p peer id is free to regenerate, so a limit keyed on one is
//! bypassable by anybody willing to make a new keypair, which is not protection
//! but the appearance of it. A per-network identity costs an admission (§2.4) to
//! obtain, which is a real price an attacker cannot route around.
//!
//! Note what that does **not** claim. This crate holds no governance state, so
//! it cannot tell an admitted identity from a freshly minted one — the same
//! limit §5.3.1 corrects for a stateless bootstrap relay. What it bounds is how
//! fast *one* identity may send; a consumer that wants "only from a current
//! member" replays its own log and refuses, which is a check only it can make.
//!
//! # A window rather than a token bucket
//!
//! A fixed window of a few messages per minute is coarse and legible: the answer
//! to "may this land" depends only on what this identity sent recently, so there
//! is no accumulated credit for a quiet sender to spend in a burst. That matters
//! here specifically because the first consumer's payload is a *request to talk
//! to somebody* — a burst of those is the abuse, and a bucket that let a patient
//! sender save up would permit exactly it.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use intranet_identity::PerNetworkIdentityId;

/// How many direct messages one identity may send inside [`WINDOW`].
///
/// Deliberately small. The first consumer sends one message to open a
/// conversation, and a legitimate retry after a failed delivery is a second — so
/// a handful per minute is generous for every honest use and leaves no room for
/// a flood. Not network policy: unlike a chat rate ceiling (spec 07 §4.3) no
/// two nodes have to agree on it, because refusing a message is a local act
/// whose only effect is that this node did not take it.
pub const PER_WINDOW: usize = 5;

/// The window over which [`PER_WINDOW`] is counted.
pub const WINDOW: Duration = Duration::from_secs(60);

/// How many senders are tracked before the oldest is forgotten.
///
/// The map is keyed by whatever a peer claims to be, so it is attacker-growable
/// and needs a ceiling — without one, a peer minting identities turns a rate
/// limiter into a memory leak, which is a worse outcome than the flood it was
/// added to stop.
const MAX_TRACKED: usize = 4096;

/// Per-sender send history.
///
/// Holds no clock: `now` is passed in, for the reason
/// [`crate::media_limits`] takes a refill time rather than reading one — a node
/// that owns a clock is a node whose tests cannot control time, and the
/// determinism this project depends on elsewhere starts with not reading a clock
/// where an argument would do.
#[derive(Debug, Default)]
pub struct DirectMeter {
    seen: BTreeMap<PerNetworkIdentityId, Vec<Instant>>,
}

impl DirectMeter {
    /// A meter with nothing recorded.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a message from `sender` and says whether it is within the limit.
    ///
    /// Counting happens whether or not the message is ultimately taken, which is
    /// the point: a sender that is refused for some *other* reason has still
    /// spent this node's attention, and a limiter that only counted successes
    /// would let a peer probe without cost.
    pub fn admit(&mut self, sender: &PerNetworkIdentityId, now: Instant) -> bool {
        if self.seen.len() >= MAX_TRACKED && !self.seen.contains_key(sender) {
            self.forget_stale(now);
            if self.seen.len() >= MAX_TRACKED {
                // Full of live senders. Refusing the unknown one is the
                // fail-closed answer, and it is the right way round: an
                // established sender keeps working while a node under a
                // minting attack stops taking new names.
                return false;
            }
        }

        let history = self.seen.entry(*sender).or_default();
        history.retain(|at| now.duration_since(*at) < WINDOW);
        if history.len() >= PER_WINDOW {
            return false;
        }
        history.push(now);
        true
    }

    /// Drops senders with nothing inside the window.
    fn forget_stale(&mut self, now: Instant) {
        self.seen.retain(|_, history| {
            history.retain(|at| now.duration_since(*at) < WINDOW);
            !history.is_empty()
        });
    }

    /// How many senders are currently tracked, for tests and reporting.
    pub fn tracked(&self) -> usize {
        self.seen.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use intranet_identity::{MasterSeed, NetworkId};

    fn identity(n: u8) -> PerNetworkIdentityId {
        MasterSeed::from_entropy([n; 32])
            .identity_for(&NetworkId::from_bytes([7; 32]))
            .expect("a derived identity")
            .id()
    }

    #[test]
    fn a_sender_within_the_limit_is_admitted() {
        let mut meter = DirectMeter::new();
        let who = identity(1);
        let now = Instant::now();
        for _ in 0..PER_WINDOW {
            assert!(meter.admit(&who, now));
        }
    }

    #[test]
    fn the_next_one_over_the_limit_is_refused() {
        let mut meter = DirectMeter::new();
        let who = identity(1);
        let now = Instant::now();
        for _ in 0..PER_WINDOW {
            assert!(meter.admit(&who, now));
        }
        assert!(!meter.admit(&who, now));
    }

    #[test]
    fn the_window_slides_rather_than_counting_forever() {
        let mut meter = DirectMeter::new();
        let who = identity(1);
        let start = Instant::now();
        for _ in 0..PER_WINDOW {
            assert!(meter.admit(&who, start));
        }
        assert!(!meter.admit(&who, start));
        // Past the window the earlier sends stop counting, so an honest sender
        // is not silenced for good by one burst.
        assert!(meter.admit(&who, start + WINDOW + Duration::from_secs(1)));
    }

    #[test]
    fn two_senders_are_counted_apart() {
        let mut meter = DirectMeter::new();
        let (a, b) = (identity(1), identity(2));
        let now = Instant::now();
        for _ in 0..PER_WINDOW {
            assert!(meter.admit(&a, now));
        }
        assert!(!meter.admit(&a, now));
        // One identity exhausting its allowance must not spend anybody else's,
        // or a single hostile sender would deny the whole protocol.
        assert!(meter.admit(&b, now));
    }

    #[test]
    fn a_quiet_sender_earns_no_burst() {
        let mut meter = DirectMeter::new();
        let who = identity(1);
        let start = Instant::now();
        // Waiting a long time does not accumulate credit: the allowance is what
        // fits in a window, not what was unspent in previous ones.
        let later = start + WINDOW * 10;
        for _ in 0..PER_WINDOW {
            assert!(meter.admit(&who, later));
        }
        assert!(!meter.admit(&who, later));
    }

    #[test]
    fn stale_senders_are_forgotten_rather_than_accumulated() {
        let mut meter = DirectMeter::new();
        let start = Instant::now();
        for n in 0..8 {
            assert!(meter.admit(&identity(n), start));
        }
        assert_eq!(meter.tracked(), 8);
        meter.forget_stale(start + WINDOW + Duration::from_secs(1));
        assert_eq!(meter.tracked(), 0);
    }
}
