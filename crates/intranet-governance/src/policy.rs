//! Network policy — Core Protocol Spec §2.4, §2.6, §2.8, §3.4, §2.7.1.
//!
//! Everything a network configures about itself lives in one struct, carried in
//! the genesis entry and changed thereafter only via `define-policy`. Keeping it
//! in a single replayed value means "what is this network's current
//! configuration" is answered the same way every other governance question is:
//! by replaying the log, not by consulting a separate store.

use crate::{GroupId, Tier};
use intranet_crypto::Enc;
use std::collections::{BTreeMap, BTreeSet};

/// A declared content type, e.g. `text` or `app-bundle`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContentType(String);

impl ContentType {
    /// Builds a content type tag.
    pub fn new(tag: impl Into<String>) -> Self {
        Self(tag.into())
    }

    /// Borrows the tag.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for ContentType {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for ContentType {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl std::fmt::Display for ContentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The starter content-type vocabulary (§2.8).
///
/// A shared baseline convention, in the spirit of MIME types — a network is not
/// limited to these and may register its own tags via the same policy mechanism.
pub fn starter_content_types() -> BTreeSet<ContentType> {
    ["text", "image", "video", "audio", "app-bundle"]
        .into_iter()
        .map(ContentType::new)
        .collect()
}

/// How a network admits new members — §2.4.
///
/// Deliberately a single network-wide setting rather than something an invite
/// encodes: mixing admission postures within one network would create
/// inconsistent onboarding and blur accountability for the network's admission
/// stance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionMode {
    /// Using a valid invite immediately grants `everyone` membership.
    AutoAdmit,
    /// Using a valid invite grants **no** group membership at all.
    ///
    /// The joiner enters a groupless waiting room: a valid, non-revoked identity
    /// holding no capabilities and no epoch key until an admin explicitly admits
    /// it. This is why content serving gates on `read-content` rather than on
    /// identity validity (Storage Spec §5.4) — a waiting-room identity is
    /// perfectly valid and must still be refused.
    ExplicitIntake,
}

/// How much history a brand-new member can read — §3.4.
///
/// This is about *new members*, not revoked ones. Revocation's guarantee is
/// unconditional and not configurable; §3.4 was explicitly renamed to stop
/// conflating the two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryAccess {
    /// New members can read from the current epoch forward only (default).
    CurrentEpochForward,
    /// New members also receive historical epoch keys.
    FullHistory,
}

/// How admission and other governance decisions are authorized — §2.6.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceModel {
    /// Only capability holders act, unilaterally.
    ///
    /// Covers both "sole authority" (only `Founders` holds `approve-node`) and
    /// "delegated moderation" (a Moderators group also holds it) — these differ
    /// only in who has been granted the capability, not in the decision
    /// procedure, so they need no separate variant.
    CapabilityHolders,
    /// Admission requires a quorum of a frozen electorate — §2.6.1.
    MemberVote {
        /// Whose membership forms the electorate.
        ///
        /// Defaults to `everyone` (direct democracy). Designating a smaller
        /// group is how representative voting is supported, with no separate
        /// mechanism: the same quorum process run against a smaller roster.
        electorate: GroupId,
        /// Yes-ballots required for a vote to pass.
        quorum: u32,
        /// How long a vote stays open, in milliseconds.
        window_millis: i64,
    },
}

/// Bounded-finality thresholds — §2.7.1, point 3.
///
/// A branch is final once it is buried under `k` capability-gated governance
/// actions **and** its tip is at least `t_millis` old. Both are required.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalityParams {
    /// Capability-gated actions that must bury an entry before it is final.
    pub k: u32,
    /// Milliseconds that must elapse before an entry is final.
    pub t_millis: i64,
}

impl FinalityParams {
    /// The starting defaults from §2.7.1: k = 10 actions, T = 30 minutes.
    ///
    /// Explicitly tunable rather than permanent constants — they are expected to
    /// be revised once the harness produces real gossip-propagation and
    /// partition-duration data. They are stated concretely because leaving them
    /// abstract blocked implementation: MLS secret retention needs a defined
    /// point at which discarding superseded secrets is safe.
    pub const DEFAULT: Self = Self {
        k: 10,
        t_millis: 30 * 60_000,
    };

    /// Whether an entry buried under `depth` capability-gated actions and aged
    /// `age_millis` has reached finality.
    ///
    /// Both conditions are required. Depth alone would let a fast burst of
    /// legitimate-looking capability-gated actions finalize a branch before
    /// enough real time passed for a genuine competing branch to surface, which
    /// is exactly the grinding protection this rule exists to provide. Time
    /// alone would let a quiet branch finalize without meaningful confirmation.
    pub fn is_final(&self, depth: u32, age_millis: i64) -> bool {
        depth >= self.k && age_millis >= self.t_millis
    }
}

impl Default for FinalityParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// A network's complete governance configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPolicy {
    /// How new members are admitted.
    pub admission_mode: AdmissionMode,
    /// How governance decisions are authorized.
    pub governance_model: GovernanceModel,
    /// How much history new members can read.
    pub history_access: HistoryAccess,
    /// What content types may exist on this network at all.
    ///
    /// One of the two independent gates on publishing; the other is the
    /// `publish:<content_type>` capability. A type being allowed here does not
    /// grant anyone permission to publish it.
    pub content_type_allowlist: BTreeSet<ContentType>,
    /// Tier declarations for capabilities defined by consuming specs.
    ///
    /// The registry that makes the class-based `everyone` invariant work for
    /// capabilities that did not exist when the base spec was written. An
    /// extension capability absent from this map cannot be evaluated and is
    /// refused rather than assumed ordinary.
    pub extension_capabilities: BTreeMap<String, Tier>,
    /// Bounded-finality thresholds.
    pub finality: FinalityParams,
    /// Durability replication target (Storage Spec §3.1).
    pub replication_factor: u16,
    /// Content-defined chunking target size in bytes (Storage Spec §1.3).
    ///
    /// Must be network-wide rather than per-publisher: deduplication depends on
    /// identical content producing identical chunk boundaries, so two publishers
    /// using different targets would silently lose it between otherwise
    /// identical content.
    pub target_chunk_size: u32,
}

impl NetworkPolicy {
    /// A conservative default policy for a new network.
    ///
    /// Chooses the more restrictive option wherever the spec names a default:
    /// explicit intake, current-epoch-forward history, and the starter content
    /// vocabulary with no extension capabilities registered.
    pub fn conservative_default() -> Self {
        Self {
            admission_mode: AdmissionMode::ExplicitIntake,
            governance_model: GovernanceModel::CapabilityHolders,
            history_access: HistoryAccess::CurrentEpochForward,
            content_type_allowlist: starter_content_types(),
            extension_capabilities: BTreeMap::new(),
            finality: FinalityParams::DEFAULT,
            replication_factor: 3,
            target_chunk_size: 32 * 1024,
        }
    }

    /// Whether `content_type` may be published on this network at all.
    pub fn allows_content_type(&self, content_type: &ContentType) -> bool {
        self.content_type_allowlist.contains(content_type)
    }

    /// Looks up a registered extension capability's tier.
    pub fn extension_tier(&self, name: &str) -> Option<Tier> {
        self.extension_capabilities.get(name).copied()
    }

    /// Appends this policy to a canonical encoding.
    pub fn encode(&self, enc: &mut Enc) {
        match self.admission_mode {
            AdmissionMode::AutoAdmit => enc.variant(0),
            AdmissionMode::ExplicitIntake => enc.variant(1),
        };
        match &self.governance_model {
            GovernanceModel::CapabilityHolders => {
                enc.variant(0);
            }
            GovernanceModel::MemberVote {
                electorate,
                quorum,
                window_millis,
            } => {
                enc.variant(1)
                    .str(electorate.as_str())
                    .u32(*quorum)
                    .i64(*window_millis);
            }
        }
        match self.history_access {
            HistoryAccess::CurrentEpochForward => enc.variant(0),
            HistoryAccess::FullHistory => enc.variant(1),
        };
        enc.seq(self.content_type_allowlist.iter(), |e, content_type| {
            e.str(content_type.as_str());
        });
        enc.seq(self.extension_capabilities.iter(), |e, (name, tier)| {
            e.str(name);
            e.u8(match tier {
                Tier::Ordinary => 0,
                Tier::Governance => 1,
            });
        });
        enc.u32(self.finality.k)
            .i64(self.finality.t_millis)
            .u32(u32::from(self.replication_factor))
            .u32(self.target_chunk_size);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use intranet_crypto::Timestamp;

    #[test]
    fn finality_requires_both_conditions() {
        let params = FinalityParams::DEFAULT;
        let t = params.t_millis;

        assert!(
            params.is_final(10, t),
            "meeting both thresholds must be final"
        );
        assert!(
            !params.is_final(10, t - 1),
            "deep but young must NOT be final \u{2014} this is the anti-grinding case"
        );
        assert!(
            !params.is_final(9, t * 10),
            "old but shallow must NOT be final"
        );
        assert!(!params.is_final(0, 0));
    }

    #[test]
    fn default_finality_matches_the_spec_values() {
        assert_eq!(FinalityParams::DEFAULT.k, 10);
        assert_eq!(
            FinalityParams::DEFAULT.t_millis,
            Timestamp::minutes(30),
            "T must be 30 minutes"
        );
    }

    #[test]
    fn negative_age_is_never_final() {
        // A future-dated entry (clock skew) must not be treated as aged.
        assert!(!FinalityParams::DEFAULT.is_final(100, -1_000));
    }

    #[test]
    fn conservative_default_picks_the_restrictive_options() {
        let policy = NetworkPolicy::conservative_default();
        assert_eq!(policy.admission_mode, AdmissionMode::ExplicitIntake);
        assert_eq!(policy.history_access, HistoryAccess::CurrentEpochForward);
        assert!(policy.extension_capabilities.is_empty());
    }

    #[test]
    fn content_type_allowlist_is_enforced_by_membership_not_convention() {
        let mut policy = NetworkPolicy::conservative_default();
        assert!(policy.allows_content_type(&ContentType::new("text")));

        // A chat-style network scoping itself away from app hosting entirely.
        policy.content_type_allowlist.remove(&ContentType::new("app-bundle"));
        assert!(!policy.allows_content_type(&ContentType::new("app-bundle")));
    }

    #[test]
    fn unregistered_extension_capability_has_no_tier() {
        let mut policy = NetworkPolicy::conservative_default();
        assert_eq!(policy.extension_tier("register-app-name"), None);

        policy
            .extension_capabilities
            .insert("register-app-name".into(), Tier::Ordinary);
        policy
            .extension_capabilities
            .insert("reclaim-app-name".into(), Tier::Governance);

        assert_eq!(
            policy.extension_tier("register-app-name"),
            Some(Tier::Ordinary)
        );
        assert_eq!(
            policy.extension_tier("reclaim-app-name"),
            Some(Tier::Governance)
        );
    }

    #[test]
    fn encoding_is_deterministic_and_sensitive_to_changes() {
        let encode = |p: &NetworkPolicy| {
            let mut e = Enc::new();
            p.encode(&mut e);
            e.finish()
        };
        let policy = NetworkPolicy::conservative_default();
        assert_eq!(encode(&policy), encode(&policy));

        let mut changed = policy.clone();
        changed.admission_mode = AdmissionMode::AutoAdmit;
        assert_ne!(encode(&policy), encode(&changed));
    }
}
