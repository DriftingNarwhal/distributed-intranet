//! Capabilities and their governance tier — Core Protocol Spec §2.1–2.2.

use crate::{ContentType, GroupId};
use intranet_crypto::Enc;
use std::collections::BTreeSet;

/// Whether a capability confers governance power.
///
/// This tag is what the `everyone` denylist (§2.4) actually keys off, rather
/// than a hardcoded list of capability names. That distinction is load-bearing:
/// a name list would silently fail to cover capabilities introduced later by
/// consuming specs, letting a new governance-tier capability escape the
/// invariant simply by not having existed when the list was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tier {
    /// Confers no governance power; may be granted to `everyone`.
    Ordinary,
    /// Confers governance power; may never be held by `everyone`.
    Governance,
}

/// A discrete, grantable capability.
///
/// Capabilities are only ever held by groups, never by individual identities
/// (§2.1, rule 1). There is deliberately no API anywhere in this crate for
/// granting a capability directly to an identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Capability {
    /// Can admit a new member to the network.
    ApproveNode,
    /// Can remove a member, which triggers epoch rotation.
    RevokeNode,
    /// Can create a group or change an existing group's capability set.
    DefineGroup,
    /// Can change the network's governance policy.
    DefinePolicy,
    /// Can change the network's content-type allowlist.
    DefineContentPolicy,
    /// Can flag or delist published content within network policy.
    ModerateContent,
    /// Can request a node's raw local reliability observations for oversight.
    AuditReputation,
    /// Can request and receive content bytes for this network.
    ///
    /// Ordinary rather than governance-tier, and typically granted broadly to
    /// `everyone` so that admission implies the ability to actually read — but
    /// genuinely network-configurable. This is the gate Storage Spec §5.4 uses
    /// for swarm-serving, which is what keeps a pre-admission waiting-room
    /// identity from being served ciphertext despite holding a valid identity.
    ReadContent,
    /// Can add or remove identities from one specific, named group.
    ///
    /// Tier is **dynamic**, not fixed: governance-tier exactly when the target
    /// group itself currently holds governance-tier power (§2.4). Managing a
    /// powerless group is a low-bar, delegable action; managing a powerful one
    /// is an indirect route to seizing that power, and is tiered accordingly.
    ManageMembership(GroupId),
    /// Can create new published content of one specific type.
    Publish(ContentType),
    /// A capability defined by a consuming spec.
    ///
    /// Its tier is not carried inline — it is looked up from the network's
    /// policy registry. Carrying the tier in the value itself would let an
    /// attacker declare a governance-tier capability as ordinary and slip it
    /// onto `everyone`, defeating the invariant the tier system exists to
    /// enforce. See [`Capability::extension`].
    Extension(String),
}

impl Capability {
    /// Builds an extension capability by name.
    ///
    /// The tier comes from the network's policy registry at evaluation time, not
    /// from the caller. An unregistered name is refused outright rather than
    /// defaulted to ordinary.
    pub fn extension(name: impl Into<String>) -> Self {
        Self::Extension(name.into())
    }

    /// Builds a `manage-membership:<group>` capability.
    pub fn manage_membership(group: impl Into<GroupId>) -> Self {
        Self::ManageMembership(group.into())
    }

    /// Builds a `publish:<content_type>` capability.
    pub fn publish(content_type: impl Into<ContentType>) -> Self {
        Self::Publish(content_type.into())
    }

    /// Returns the tier for capabilities whose tier is fixed at definition.
    ///
    /// Returns `None` for the two capabilities whose tier cannot be determined
    /// from the value alone: [`ManageMembership`](Self::ManageMembership), which
    /// depends on the target group's current capabilities, and
    /// [`Extension`](Self::Extension), which depends on the network's policy
    /// registry. Both are resolved by `GovernanceState::tier_of`.
    pub fn intrinsic_tier(&self) -> Option<Tier> {
        match self {
            Self::ApproveNode
            | Self::RevokeNode
            | Self::DefineGroup
            | Self::DefinePolicy
            | Self::DefineContentPolicy
            | Self::ModerateContent
            | Self::AuditReputation => Some(Tier::Governance),
            Self::ReadContent | Self::Publish(_) => Some(Tier::Ordinary),
            Self::ManageMembership(_) | Self::Extension(_) => None,
        }
    }

    /// Appends this capability to a canonical encoding.
    pub fn encode(&self, enc: &mut Enc) {
        match self {
            Self::ApproveNode => enc.variant(0),
            Self::RevokeNode => enc.variant(1),
            Self::DefineGroup => enc.variant(2),
            Self::DefinePolicy => enc.variant(3),
            Self::DefineContentPolicy => enc.variant(4),
            Self::ModerateContent => enc.variant(5),
            Self::AuditReputation => enc.variant(6),
            Self::ReadContent => enc.variant(7),
            Self::ManageMembership(group) => enc.variant(8).str(group.as_str()),
            Self::Publish(content_type) => enc.variant(9).str(content_type.as_str()),
            Self::Extension(name) => enc.variant(10).str(name),
        };
    }
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApproveNode => write!(f, "approve-node"),
            Self::RevokeNode => write!(f, "revoke-node"),
            Self::DefineGroup => write!(f, "define-group"),
            Self::DefinePolicy => write!(f, "define-policy"),
            Self::DefineContentPolicy => write!(f, "define-content-policy"),
            Self::ModerateContent => write!(f, "moderate-content"),
            Self::AuditReputation => write!(f, "audit-reputation"),
            Self::ReadContent => write!(f, "read-content"),
            Self::ManageMembership(group) => write!(f, "manage-membership:{group}"),
            Self::Publish(content_type) => write!(f, "publish:{content_type}"),
            Self::Extension(name) => write!(f, "{name}"),
        }
    }
}

/// The set of capabilities a group holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilitySet {
    /// Every capability, including ones defined later.
    ///
    /// This is how the implicit `Founders` group holds "every capability" (§2.3)
    /// without needing to enumerate parametrized capabilities like
    /// `manage-membership:<group>` for every group that will ever exist.
    ///
    /// It is not a special case in the authorization model: `Founders` is an
    /// ordinary group whose capability set happens to be unrestricted, and
    /// `define-group` can narrow it like any other group's.
    All,
    /// An explicit set of capabilities.
    Explicit(BTreeSet<Capability>),
}

impl CapabilitySet {
    /// Builds an explicit capability set.
    pub fn explicit(capabilities: impl IntoIterator<Item = Capability>) -> Self {
        Self::Explicit(capabilities.into_iter().collect())
    }

    /// An empty capability set.
    pub fn empty() -> Self {
        Self::Explicit(BTreeSet::new())
    }

    /// Whether this set confers `capability`.
    pub fn grants(&self, capability: &Capability) -> bool {
        match self {
            Self::All => true,
            Self::Explicit(set) => set.contains(capability),
        }
    }

    /// Iterates the explicitly held capabilities, if any.
    ///
    /// Returns an empty iterator for [`All`](Self::All), which cannot be
    /// enumerated — callers needing to reason about an unrestricted set must
    /// handle that variant explicitly rather than treating it as empty.
    pub fn iter(&self) -> impl Iterator<Item = &Capability> {
        match self {
            Self::All => None,
            Self::Explicit(set) => Some(set.iter()),
        }
        .into_iter()
        .flatten()
    }

    /// Appends this set to a canonical encoding.
    pub fn encode(&self, enc: &mut Enc) {
        match self {
            Self::All => {
                enc.variant(0);
            }
            Self::Explicit(set) => {
                enc.variant(1);
                enc.seq(set.iter(), |e, capability| capability.encode(e));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn governance_tier_capabilities_are_tagged_as_such() {
        for capability in [
            Capability::ApproveNode,
            Capability::RevokeNode,
            Capability::DefineGroup,
            Capability::DefinePolicy,
            Capability::DefineContentPolicy,
            Capability::ModerateContent,
            Capability::AuditReputation,
        ] {
            assert_eq!(
                capability.intrinsic_tier(),
                Some(Tier::Governance),
                "{capability} must be governance-tier"
            );
        }
    }

    #[test]
    fn ordinary_capabilities_are_tagged_as_such() {
        assert_eq!(
            Capability::ReadContent.intrinsic_tier(),
            Some(Tier::Ordinary)
        );
        assert_eq!(
            Capability::publish("text").intrinsic_tier(),
            Some(Tier::Ordinary)
        );
    }

    #[test]
    fn dynamically_tiered_capabilities_have_no_intrinsic_tier() {
        // These must be resolved against network state, never assumed.
        assert_eq!(Capability::manage_membership("mods").intrinsic_tier(), None);
        assert_eq!(Capability::extension("custom").intrinsic_tier(), None);
    }

    #[test]
    fn unrestricted_set_grants_everything_including_parametrized() {
        let all = CapabilitySet::All;
        assert!(all.grants(&Capability::DefineGroup));
        assert!(all.grants(&Capability::manage_membership("any-group-at-all")));
        assert!(all.grants(&Capability::extension("defined-much-later")));
    }

    #[test]
    fn explicit_set_grants_only_what_it_lists() {
        let set = CapabilitySet::explicit([Capability::ReadContent]);
        assert!(set.grants(&Capability::ReadContent));
        assert!(!set.grants(&Capability::DefineGroup));
    }

    #[test]
    fn parametrized_capabilities_are_distinct_per_parameter() {
        let set = CapabilitySet::explicit([Capability::manage_membership("mods")]);
        assert!(set.grants(&Capability::manage_membership("mods")));
        assert!(
            !set.grants(&Capability::manage_membership("founders")),
            "managing one group must not confer managing another"
        );

        let publish = CapabilitySet::explicit([Capability::publish("text")]);
        assert!(publish.grants(&Capability::publish("text")));
        assert!(!publish.grants(&Capability::publish("app-bundle")));
    }

    #[test]
    fn encoding_distinguishes_capabilities_and_is_deterministic() {
        let enc = |c: &Capability| {
            let mut e = Enc::new();
            c.encode(&mut e);
            e.finish()
        };
        assert_eq!(enc(&Capability::DefineGroup), enc(&Capability::DefineGroup));
        assert_ne!(enc(&Capability::DefineGroup), enc(&Capability::DefinePolicy));
        assert_ne!(
            enc(&Capability::manage_membership("a")),
            enc(&Capability::manage_membership("b"))
        );
        // A publish capability and an extension with the same string must differ.
        assert_ne!(
            enc(&Capability::publish("text")),
            enc(&Capability::extension("text"))
        );
    }
}
