//! Protocol timestamps.
//!
//! Time appears in this protocol in places where it is genuinely load-bearing:
//! the bounded-finality age threshold `T` (Core Protocol Spec §2.7.1, point 3),
//! ballot close times (§2.6.1, point 3), cascade time windows (§2.5), device
//! certificate issuance (§1.3), and append-set entry TTLs (Storage Spec §2.5).
//!
//! # Time is never read from the system clock inside protocol logic
//!
//! Every function in this workspace that needs "now" takes it as a parameter.
//! Two reasons, both from the specs rather than from testing convenience:
//!
//! - The harness must drive the 30-minute finality threshold on a virtual clock
//!   to stay CI-runnable (Reference Test Harness Spec §3), and must simulate
//!   deliberately skewed clocks near a vote's close boundary (§3, §2.6.1).
//! - Clock skew between honest nodes is an explicitly acknowledged condition
//!   (Core Protocol Spec §2.6.1, point 4), not an anomaly to design away.
//!
//! Ambient clock reads inside protocol code would make both untestable and would
//! hide skew rather than surface it, so the type deliberately has no `now()`.

/// A point in time, as milliseconds since the Unix epoch.
///
/// Signed, so that pre-epoch values and durations subtract without wrapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(i64);

impl Timestamp {
    /// Builds a timestamp from milliseconds since the Unix epoch.
    pub const fn from_millis(millis: i64) -> Self {
        Self(millis)
    }

    /// Returns milliseconds since the Unix epoch.
    pub const fn as_millis(&self) -> i64 {
        self.0
    }

    /// Milliseconds elapsed from `earlier` to `self`.
    ///
    /// Negative when `self` precedes `earlier`, which callers must handle rather
    /// than assume away — an entry timestamped in the future relative to the node
    /// evaluating it is a real, expected condition under clock skew.
    pub const fn millis_since(&self, earlier: Timestamp) -> i64 {
        self.0 - earlier.0
    }

    /// Returns a timestamp `millis` later than this one, saturating at the bounds.
    pub const fn plus_millis(&self, millis: i64) -> Self {
        Self(self.0.saturating_add(millis))
    }

    /// Convenience for expressing durations in tests and policy defaults.
    pub const fn minutes(n: i64) -> i64 {
        n * 60_000
    }
}

impl std::fmt::Display for Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "t{}ms", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elapsed_is_signed_so_skew_is_visible_not_hidden() {
        let early = Timestamp::from_millis(1_000);
        let late = Timestamp::from_millis(4_000);
        assert_eq!(late.millis_since(early), 3_000);
        assert_eq!(
            early.millis_since(late),
            -3_000,
            "a future-dated entry must report negative age, not underflow to a huge positive"
        );
    }

    #[test]
    fn minutes_helper_matches_finality_threshold() {
        // T = 30 minutes (Core Protocol Spec §2.7.1).
        assert_eq!(Timestamp::minutes(30), 1_800_000);
    }

    #[test]
    fn plus_millis_saturates_rather_than_panicking() {
        assert_eq!(
            Timestamp::from_millis(i64::MAX).plus_millis(1_000),
            Timestamp::from_millis(i64::MAX)
        );
    }
}
