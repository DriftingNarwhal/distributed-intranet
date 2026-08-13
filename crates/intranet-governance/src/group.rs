//! Groups and membership — Core Protocol Spec §2.1, §2.3–2.5.

use crate::{CapabilitySet, InviteProvenance};
use intranet_crypto::{Enc, Timestamp};
use intranet_identity::PerNetworkIdentityId;
use std::collections::BTreeMap;

/// The name of the implicit root group created at genesis.
pub const FOUNDERS: &str = "Founders";

/// The name of the implicit baseline group created at genesis.
pub const EVERYONE: &str = "everyone";

/// A group's name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GroupId(String);

impl GroupId {
    /// Builds a group identifier.
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// The implicit `Founders` group (§2.3).
    pub fn founders() -> Self {
        Self(FOUNDERS.to_string())
    }

    /// The implicit `everyone` group (§2.4).
    pub fn everyone() -> Self {
        Self(EVERYONE.to_string())
    }

    /// Whether this is the `everyone` group, which carries a hard invariant.
    pub fn is_everyone(&self) -> bool {
        self.0 == EVERYONE
    }

    /// Borrows the group name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for GroupId {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for GroupId {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl std::fmt::Display for GroupId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Provenance for one identity's membership in one group.
///
/// `added_by` and `added_at` exist to make the opt-in cascading revocation in
/// §2.5 computable: cascading removes everyone the revoked identity added,
/// recursively, optionally scoped to a time window. Without recording who added
/// whom, "cascade everything this account added in the last 48 hours" — the
/// compromised-account scenario the option exists for — could not be answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipRecord {
    /// Who added this identity, or `None` for genesis-time membership.
    pub added_by: Option<PerNetworkIdentityId>,
    /// When this identity was added.
    pub added_at: Timestamp,
    /// Which invite this membership came from, if any — §5.6.
    pub via_invite: Option<InviteProvenance>,
}

/// A flat collection of identities holding a shared capability set.
///
/// Groups are flat: a group contains identities directly and cannot contain
/// other groups (§2.1, rule 2). Nested hierarchies are the single most common
/// source of unmanageable permission sprawl in real RBAC deployments, and
/// nothing in this project needs them. There is deliberately no field here that
/// could hold a child group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    /// The group's name.
    pub id: GroupId,
    /// What this group's members are authorized to do.
    pub capabilities: CapabilitySet,
    /// Current members, and how each came to be one.
    pub members: BTreeMap<PerNetworkIdentityId, MembershipRecord>,
}

impl Group {
    /// Creates an empty group with the given capability set.
    pub fn new(id: impl Into<GroupId>, capabilities: CapabilitySet) -> Self {
        Self {
            id: id.into(),
            capabilities,
            members: BTreeMap::new(),
        }
    }

    /// Whether `identity` is currently a member.
    pub fn contains(&self, identity: &PerNetworkIdentityId) -> bool {
        self.members.contains_key(identity)
    }

    /// Appends this group to a canonical encoding.
    ///
    /// Members are encoded from a `BTreeMap`, so iteration order is by identity
    /// key rather than insertion order — which is what lets two nodes that
    /// applied the same entries in the same order produce byte-identical state
    /// encodings regardless of internal storage details.
    pub fn encode(&self, enc: &mut Enc) {
        enc.str(self.id.as_str());
        self.capabilities.encode(enc);
        enc.seq(self.members.iter(), |e, (identity, record)| {
            identity.encode(e);
            e.option(record.added_by.as_ref(), |e, adder| adder.encode(e));
            e.i64(record.added_at.as_millis());
            e.option(record.via_invite.as_ref(), |e, provenance| {
                provenance.encode(e);
            });
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Capability;

    #[test]
    fn implicit_group_names_are_stable() {
        assert_eq!(GroupId::founders().as_str(), "Founders");
        assert_eq!(GroupId::everyone().as_str(), "everyone");
        assert!(GroupId::everyone().is_everyone());
        assert!(!GroupId::founders().is_everyone());
    }

    #[test]
    fn everyone_detection_is_exact_not_fuzzy() {
        // The invariant keys off this check, so a near-miss name must not be
        // mistaken for the real `everyone` group in either direction.
        assert!(!GroupId::new("Everyone").is_everyone());
        assert!(!GroupId::new("everyone-else").is_everyone());
        assert!(!GroupId::new("everyone ").is_everyone());
    }

    #[test]
    fn membership_tracks_provenance_for_cascade() {
        let mut group = Group::new("mods", CapabilitySet::explicit([Capability::ReadContent]));
        let adder = PerNetworkIdentityId::from_verifying_key(
            intranet_crypto::SecretKey::from_bytes([1u8; 32]).verifying_key(),
        );
        let added = PerNetworkIdentityId::from_verifying_key(
            intranet_crypto::SecretKey::from_bytes([2u8; 32]).verifying_key(),
        );

        group.members.insert(
            added,
            MembershipRecord {
                added_by: Some(adder),
                added_at: Timestamp::from_millis(1_000),
                via_invite: None,
            },
        );

        assert!(group.contains(&added));
        assert!(!group.contains(&adder));
        assert_eq!(group.members[&added].added_by, Some(adder));
    }

    #[test]
    fn encoding_is_deterministic_regardless_of_insertion_order() {
        let ids: Vec<_> = (1u8..=3)
            .map(|i| {
                PerNetworkIdentityId::from_verifying_key(
                    intranet_crypto::SecretKey::from_bytes([i; 32]).verifying_key(),
                )
            })
            .collect();

        let build = |order: &[usize]| {
            let mut group = Group::new("g", CapabilitySet::explicit([Capability::ReadContent]));
            for &i in order {
                group.members.insert(
                    ids[i],
                    MembershipRecord {
                        added_by: None,
                        added_at: Timestamp::from_millis(i as i64),
                        via_invite: None,
                    },
                );
            }
            let mut e = Enc::new();
            group.encode(&mut e);
            e.finish()
        };

        assert_eq!(
            build(&[0, 1, 2]),
            build(&[2, 0, 1]),
            "state encoding must not depend on the order members happened to be inserted"
        );
    }
}
