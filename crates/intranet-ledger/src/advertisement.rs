//! Capability advertisements — Core Protocol Spec §4.2–4.4.

use intranet_crypto::{Enc, Signature, Timestamp};
use intranet_identity::{NetworkId, PerNetworkIdentity, PerNetworkIdentityId};

/// Domain tag for capability advertisement signatures.
const ADVERTISEMENT_DOMAIN: &str = "intranet.capability-advertisement.v1";

/// Declared throughput limits, optionally scoped to a time of day.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BandwidthCap {
    /// Upload bytes per second the node will contribute.
    ///
    /// Upload is the scarce resource on a residential connection, which is why
    /// it is the figure that drives mesh-versus-relay decisions (Real-Time Spec
    /// §1.1) and swarm source selection.
    pub up_bytes_per_sec: u64,
    /// Download bytes per second.
    pub down_bytes_per_sec: u64,
    /// Optional window during which this cap applies.
    ///
    /// `None` means it applies at all times. §4.2 allows time-of-day scoping so
    /// a node can contribute generously overnight without degrading its own
    /// daytime use.
    pub active_window: Option<TimeOfDayWindow>,
}

impl BandwidthCap {
    /// A cap that contributes nothing.
    pub const NONE: Self = Self {
        up_bytes_per_sec: 0,
        down_bytes_per_sec: 0,
        active_window: None,
    };

    /// Whether this cap is in force at `minute_of_day`.
    pub fn active_at(&self, minute_of_day: u16) -> bool {
        self.active_window
            .is_none_or(|window| window.contains(minute_of_day))
    }

    fn encode(&self, enc: &mut Enc) {
        enc.u64(self.up_bytes_per_sec).u64(self.down_bytes_per_sec);
        enc.option(self.active_window.as_ref(), |e, window| {
            e.u32(u32::from(window.start_minute))
                .u32(u32::from(window.end_minute));
        });
    }
}

/// A window within a day, in minutes from midnight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeOfDayWindow {
    /// Inclusive start minute, 0–1439.
    pub start_minute: u16,
    /// Exclusive end minute, 0–1439.
    pub end_minute: u16,
}

impl TimeOfDayWindow {
    /// Whether `minute` falls inside this window.
    ///
    /// Handles windows that wrap past midnight (e.g. 23:00–06:00), which is the
    /// common case for "contribute while I'm asleep" and would otherwise be
    /// silently empty.
    pub fn contains(&self, minute: u16) -> bool {
        if self.start_minute <= self.end_minute {
            minute >= self.start_minute && minute < self.end_minute
        } else {
            minute >= self.start_minute || minute < self.end_minute
        }
    }
}

/// A coarse hint about a node's compute capacity.
///
/// Deliberately coarse: published apps execute on the *visitor's* node (App
/// Hosting Spec §1.1), so this informs relay and storage duty cycling rather
/// than any form of app scheduling. Nothing in this protocol schedules work onto
/// someone else's machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ComputeClass {
    /// Constrained — a phone, or a machine the user needs responsive.
    Minimal,
    /// An ordinary desktop or laptop.
    Modest,
    /// A machine that can carry sustained background work.
    Substantial,
}

impl ComputeClass {
    fn discriminant(self) -> u8 {
        match self {
            Self::Minimal => 0,
            Self::Modest => 1,
            Self::Substantial => 2,
        }
    }
}

/// What one node advertises it will contribute, for one network.
///
/// # Why this is per-network and not global
///
/// A node's willingness is explicitly scoped per network: full participation in
/// a small trusted friend network, relay-only in a massive fandom network. The
/// entry is keyed `(per-network identity, network)`, which also keeps the
/// unlinkability guarantee intact — a node's contribution profile in one network
/// must not be derivable from its profile in another, and it would be if a
/// single global profile were advertised everywhere.
///
/// # `reliability_signal` is deliberately absent
///
/// It is local-only observation state that is never advertised or gossiped
/// (§4.6). See [`crate::reliability`] for where it does live, and
/// [`crate::placement`] for why keeping it out of this struct is what lets
/// replica placement stay deterministic across nodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityAdvertisement {
    /// The network this advertisement applies to.
    pub network: NetworkId,
    /// The advertising node's per-network identity.
    pub node: PerNetworkIdentityId,
    /// Bytes the node will allocate to replicated content for this network.
    pub storage_offered: u64,
    /// Declared throughput limits.
    pub bandwidth_cap: BandwidthCap,
    /// Whether the node will help NAT-traverse new peers.
    ///
    /// Short-lived, low continuous bandwidth: the node helps two peers
    /// establish a connection and then gets out of the way.
    pub relay_bootstrap_willing: bool,
    /// Whether the node will blind-relay real-time media.
    ///
    /// A materially different resource profile from bootstrap relaying —
    /// sustained bandwidth and latency demands for the duration of a call — and
    /// a distinct capability that must not be conflated with it (§4.4).
    pub relay_media_willing: bool,
    /// Coarse compute hint.
    pub compute_class: ComputeClass,
    /// When this advertisement was issued.
    pub issued_at: Timestamp,
    /// The advertising node's signature.
    pub signature: Signature,
}

impl CapabilityAdvertisement {
    /// Builds and signs an advertisement.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        node: &PerNetworkIdentity,
        storage_offered: u64,
        bandwidth_cap: BandwidthCap,
        relay_bootstrap_willing: bool,
        relay_media_willing: bool,
        compute_class: ComputeClass,
        issued_at: Timestamp,
    ) -> Self {
        let node_id = node.id();
        let payload = Self::payload(
            node.network(),
            &node_id,
            storage_offered,
            &bandwidth_cap,
            relay_bootstrap_willing,
            relay_media_willing,
            compute_class,
            issued_at,
        );
        Self {
            network: *node.network(),
            node: node_id,
            storage_offered,
            bandwidth_cap,
            relay_bootstrap_willing,
            relay_media_willing,
            compute_class,
            issued_at,
            signature: node.sign(&payload),
        }
    }

    /// A node offering nothing at all — the default posture.
    ///
    /// Contribution is opt-in and revocable per network, so declaring nothing is
    /// a valid, first-class state rather than a degenerate one.
    pub fn none(node: &PerNetworkIdentity, issued_at: Timestamp) -> Self {
        Self::create(
            node,
            0,
            BandwidthCap::NONE,
            false,
            false,
            ComputeClass::Minimal,
            issued_at,
        )
    }

    /// Verifies the advertisement's signature.
    pub fn verify(&self) -> Result<(), crate::LedgerError> {
        let payload = Self::payload(
            &self.network,
            &self.node,
            self.storage_offered,
            &self.bandwidth_cap,
            self.relay_bootstrap_willing,
            self.relay_media_willing,
            self.compute_class,
            self.issued_at,
        );
        self.node
            .verifying_key()
            .verify(&payload, &self.signature)
            .map_err(|_| crate::LedgerError::BadSignature)
    }

    /// Whether this advertisement has aged past `ttl_millis`.
    pub fn is_stale(&self, now: Timestamp, ttl_millis: i64) -> bool {
        now.millis_since(self.issued_at) > ttl_millis
    }

    #[allow(clippy::too_many_arguments)]
    fn payload(
        network: &NetworkId,
        node: &PerNetworkIdentityId,
        storage_offered: u64,
        bandwidth_cap: &BandwidthCap,
        relay_bootstrap_willing: bool,
        relay_media_willing: bool,
        compute_class: ComputeClass,
        issued_at: Timestamp,
    ) -> Enc {
        let mut e = Enc::domain(ADVERTISEMENT_DOMAIN);
        network.encode(&mut e);
        node.encode(&mut e);
        e.u64(storage_offered);
        bandwidth_cap.encode(&mut e);
        e.bool(relay_bootstrap_willing)
            .bool(relay_media_willing)
            .u8(compute_class.discriminant())
            .i64(issued_at.as_millis());
        e
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use intranet_identity::MasterSeed;

    fn node(seed: u8, network: &NetworkId) -> PerNetworkIdentity {
        MasterSeed::from_entropy([seed; 32])
            .identity_for(network)
            .unwrap()
    }

    #[test]
    fn advertisement_round_trips() {
        let network = NetworkId::from_bytes([1u8; 32]);
        let node = node(1, &network);
        let advertisement = CapabilityAdvertisement::create(
            &node,
            1_000_000,
            BandwidthCap {
                up_bytes_per_sec: 500_000,
                down_bytes_per_sec: 2_000_000,
                active_window: None,
            },
            true,
            false,
            ComputeClass::Modest,
            Timestamp::from_millis(100),
        );
        assert!(advertisement.verify().is_ok());
    }

    #[test]
    fn inflating_declared_capacity_breaks_the_signature() {
        let network = NetworkId::from_bytes([1u8; 32]);
        let node = node(1, &network);
        let mut advertisement =
            CapabilityAdvertisement::none(&node, Timestamp::from_millis(0));
        advertisement.storage_offered = u64::MAX;
        assert!(advertisement.verify().is_err());
    }

    #[test]
    fn advertisements_are_scoped_per_network() {
        // The same person in two networks produces unrelated advertisements,
        // signed by unrelated keys — a contribution profile in one network is
        // not derivable from the other.
        let seed = MasterSeed::from_entropy([5u8; 32]);
        let here = seed
            .identity_for(&NetworkId::from_bytes([1u8; 32]))
            .unwrap();
        let there = seed
            .identity_for(&NetworkId::from_bytes([2u8; 32]))
            .unwrap();

        let a = CapabilityAdvertisement::none(&here, Timestamp::from_millis(0));
        let b = CapabilityAdvertisement::none(&there, Timestamp::from_millis(0));
        assert_ne!(a.node, b.node);
        assert_ne!(a.network, b.network);
    }

    #[test]
    fn staleness_is_measured_against_issuance() {
        let network = NetworkId::from_bytes([1u8; 32]);
        let advertisement =
            CapabilityAdvertisement::none(&node(1, &network), Timestamp::from_millis(1_000));

        assert!(!advertisement.is_stale(Timestamp::from_millis(6_000), 5_000));
        assert!(advertisement.is_stale(Timestamp::from_millis(6_001), 5_000));
    }

    #[test]
    fn time_of_day_windows_handle_wrapping_past_midnight() {
        // 23:00 to 06:00 — the "contribute while I'm asleep" case, which a naive
        // start <= minute < end check would treat as an empty window.
        let overnight = TimeOfDayWindow {
            start_minute: 23 * 60,
            end_minute: 6 * 60,
        };
        assert!(overnight.contains(23 * 60));
        assert!(overnight.contains(2 * 60));
        assert!(!overnight.contains(12 * 60));

        let daytime = TimeOfDayWindow {
            start_minute: 9 * 60,
            end_minute: 17 * 60,
        };
        assert!(daytime.contains(12 * 60));
        assert!(!daytime.contains(20 * 60));
    }

    #[test]
    fn a_cap_with_no_window_is_always_active() {
        let cap = BandwidthCap::NONE;
        assert!(cap.active_at(0));
        assert!(cap.active_at(1_439));
    }
}
