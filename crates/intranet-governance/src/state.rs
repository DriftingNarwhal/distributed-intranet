//! Governance state and the replay engine — Core Protocol Spec §2.7.
//!
//! # Replay is the only way to know anything
//!
//! No node ever trusts another node's claim about "the current state". Every
//! authorization question in this protocol is answered by replaying the log from
//! genesis and checking each entry's signature against the rules that were in
//! effect *at that point in the chain* — a computation, not a query to a trusted
//! server. This module is that computation.
//!
//! Two consequences shape the code below. First, [`GovernanceState::apply`]
//! returns a new state rather than mutating in place: an entry that fails
//! validation must leave no trace, and the cleanest way to guarantee that is for
//! rejected entries to never have produced a state at all. Second, every
//! collection is ordered (`BTreeMap`/`BTreeSet`), so that two nodes replaying the
//! same entries produce byte-identical [`state_hash`](GovernanceState::state_hash)
//! values — which is what the harness asserts as a hard pass/fail rather than an
//! approximate check.

use crate::{
    Capability, CapabilitySet, ContentType, EntryBody, GovernanceError, Group, GroupId, LogEntry,
    MembershipAction, MembershipRecord, ModerationAction, NetworkPolicy, PointerId, RotationReason,
    Tier,
};
use intranet_crypto::{Enc, Hash, Timestamp, hash_bytes};
use intranet_identity::{
    DeviceCertificate, DevicePublicKey, NetworkId, PerNetworkIdentityId,
};
use std::collections::{BTreeMap, BTreeSet};

/// The authorization state produced by replaying a governance log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceState {
    /// The network this state describes.
    pub network: NetworkId,
    /// Current governance configuration.
    pub policy: NetworkPolicy,
    /// All groups, by name.
    pub groups: BTreeMap<GroupId, Group>,
    /// Currently valid device certificates, by device key.
    pub device_certificates: BTreeMap<DevicePublicKey, DeviceCertificate>,
    /// Device keys whose certificates have been revoked.
    ///
    /// Retained rather than merely removed from `device_certificates`, so that a
    /// revoked device cannot be silently re-enrolled by replaying its original
    /// certificate entry — the revocation is a permanent fact about that key.
    pub revoked_devices: BTreeSet<DevicePublicKey>,
    /// Pointers currently delisted by moderation.
    ///
    /// Populated by replaying `ModerationEntry` records: a pointer is delisted
    /// if the most recent entry targeting it was a `Delist`. A pointer absent
    /// from this set is not delisted.
    pub delisted: BTreeSet<PointerId>,
    /// How many epoch rotations have occurred.
    pub epoch: u64,
    /// Hash of the log entry that produced the current epoch.
    ///
    /// Storage Spec §5.3 requires DEK wrappings to reference this entry hash
    /// rather than a bare epoch counter, because two competing branches can each
    /// legitimately produce "the next epoch" with the same ordinal, and a
    /// counter cannot disambiguate which rotation a wrapping corresponds to.
    pub epoch_rotation_ref: Option<Hash>,
}

impl GovernanceState {
    /// Builds the initial state from a genesis entry — §2.3, §2.4.
    ///
    /// Creates both implicit groups: `Founders`, holding every capability with
    /// the network creator as its sole member, and `everyone`, holding whatever
    /// non-governance capabilities the creator configured.
    ///
    /// The creator is placed in `Founders` only, not in `everyone`. The spec does
    /// not say which, and it makes no authorization difference (`Founders` holds
    /// every capability regardless), so this takes the narrower reading.
    /// **Flagged as an implementation choice not covered by the specs.**
    pub fn genesis(entry: &LogEntry) -> Result<Self, GovernanceError> {
        entry.verify_signature()?;
        if entry.parent.is_some() {
            return Err(GovernanceError::UnexpectedGenesis);
        }

        let EntryBody::Genesis {
            network,
            policy,
            everyone_capabilities,
        } = &entry.body
        else {
            return Err(GovernanceError::ExpectedGenesis);
        };

        let mut founders = Group::new(GroupId::founders(), CapabilitySet::All);
        founders.members.insert(
            entry.author,
            MembershipRecord {
                added_by: None,
                added_at: entry.timestamp,
            },
        );

        let everyone = Group::new(
            GroupId::everyone(),
            CapabilitySet::Explicit(everyone_capabilities.clone()),
        );

        let state = Self {
            network: *network,
            policy: policy.clone(),
            groups: BTreeMap::from([
                (GroupId::founders(), founders),
                (GroupId::everyone(), everyone),
            ]),
            device_certificates: BTreeMap::new(),
            revoked_devices: BTreeSet::new(),
            delisted: BTreeSet::new(),
            epoch: 0,
            epoch_rotation_ref: None,
        };

        state.check_everyone_invariant()?;
        Ok(state)
    }

    /// Validates `entry` against this state and returns the resulting state.
    ///
    /// Returns a new state rather than mutating, so a rejected entry leaves the
    /// caller's state untouched by construction.
    pub fn apply(&self, entry: &LogEntry) -> Result<Self, GovernanceError> {
        entry.verify_signature()?;

        if matches!(entry.body, EntryBody::Genesis { .. }) {
            return Err(GovernanceError::UnexpectedGenesis);
        }
        if entry.parent.is_none() {
            return Err(GovernanceError::MissingParent);
        }

        self.authorize(entry)?;

        let mut next = self.clone();
        next.mutate(entry)?;
        next.check_everyone_invariant()?;
        Ok(next)
    }

    /// Replays an ordered chain of entries into a state.
    ///
    /// The first entry must be genesis. Each subsequent entry is validated
    /// against the state produced by its predecessors, which is what makes
    /// "was this action authorized" a question about the rules in effect at that
    /// point in the chain rather than the rules in effect now.
    pub fn replay<'a>(
        entries: impl IntoIterator<Item = &'a LogEntry>,
    ) -> Result<Self, GovernanceError> {
        let mut iter = entries.into_iter();
        let genesis = iter.next().ok_or(GovernanceError::ExpectedGenesis)?;
        let mut state = Self::genesis(genesis)?;
        for entry in iter {
            state = state.apply(entry)?;
        }
        Ok(state)
    }

    /// Resolves a capability's governance tier against current state — §2.2, §2.4.
    ///
    /// Most capabilities carry a fixed tier. Two do not:
    ///
    /// - `manage-membership:<group>` is governance-tier exactly when the target
    ///   group currently holds governance-tier power, so its tier changes as that
    ///   group's capability set changes.
    /// - An extension capability's tier comes from the network's policy registry.
    ///   An unregistered one is an error, never assumed ordinary — assuming
    ///   ordinary is precisely the hole the class-based invariant exists to close.
    ///
    /// # Cycles
    ///
    /// Group A managing B while B manages A would recurse forever. Such a cycle
    /// resolves to `Ordinary` for the re-entrant path rather than erroring,
    /// which computes the least fixed point and is the correct answer: a
    /// management cycle containing no governance-tier capability confers no
    /// governance power, so refusing it would reject a legitimate (if unusual)
    /// configuration. If any group in the cycle *does* hold real power, that
    /// capability is found on its own path and the result is `Governance`.
    pub fn tier_of(&self, capability: &Capability) -> Result<Tier, GovernanceError> {
        self.tier_of_inner(capability, &mut BTreeSet::new())
    }

    fn tier_of_inner(
        &self,
        capability: &Capability,
        visiting: &mut BTreeSet<GroupId>,
    ) -> Result<Tier, GovernanceError> {
        if let Some(tier) = capability.intrinsic_tier() {
            return Ok(tier);
        }

        match capability {
            Capability::Extension(name) => self
                .policy
                .extension_tier(name)
                .ok_or_else(|| GovernanceError::UnregisteredExtensionCapability(name.clone())),

            Capability::ManageMembership(group) => {
                if !visiting.insert(group.clone()) {
                    return Ok(Tier::Ordinary);
                }
                let target = self
                    .groups
                    .get(group)
                    .ok_or_else(|| GovernanceError::UnknownGroup(group.clone()))?;

                let tier = match &target.capabilities {
                    // An unrestricted group holds every governance-tier
                    // capability there is, so managing it is governance-tier.
                    CapabilitySet::All => Tier::Governance,
                    CapabilitySet::Explicit(set) => {
                        let mut tier = Tier::Ordinary;
                        for held in set {
                            if self.tier_of_inner(held, visiting)? == Tier::Governance {
                                tier = Tier::Governance;
                                break;
                            }
                        }
                        tier
                    }
                };

                visiting.remove(group);
                Ok(tier)
            }

            _ => unreachable!("every other capability has an intrinsic tier"),
        }
    }

    /// Whether `identity` holds `capability` through any group it belongs to.
    ///
    /// An identity's effective permissions are the union of the capabilities
    /// held by every group it belongs to (§2.1). There is deliberately no path
    /// here that consults a per-identity grant, because none exists.
    pub fn identity_holds(&self, identity: &PerNetworkIdentityId, capability: &Capability) -> bool {
        self.groups
            .values()
            .any(|group| group.contains(identity) && group.capabilities.grants(capability))
    }

    /// Whether `identity` belongs to any group in this network.
    ///
    /// Under explicit intake a joiner is a valid, non-revoked identity holding
    /// *no* group membership at all, so this is deliberately not the same
    /// question as "is this identity valid".
    pub fn is_member(&self, identity: &PerNetworkIdentityId) -> bool {
        self.groups.values().any(|group| group.contains(identity))
    }

    /// Whether `pointer` is currently delisted by moderation.
    ///
    /// This is the concrete answer to the check that Storage Spec §2.5, Search
    /// Spec §3.1/§6.1, and App Hosting Spec §3.4 all require: resolved by log
    /// replay, not by consulting any separate store.
    pub fn is_delisted(&self, pointer: &PointerId) -> bool {
        self.delisted.contains(pointer)
    }

    /// Whether `device` currently has valid signing authority for `identity`.
    ///
    /// An action signed by a linked device carries whatever authority its
    /// identity holds; the device itself has no independent standing beyond what
    /// its certificate grants (§1.3, point 4).
    pub fn device_is_authorized(
        &self,
        device: &DevicePublicKey,
        identity: &PerNetworkIdentityId,
    ) -> bool {
        if self.revoked_devices.contains(device) {
            return false;
        }
        self.device_certificates
            .get(device)
            .is_some_and(|cert| cert.identity == *identity)
    }

    /// Whether `content_type` may be published on this network at all.
    ///
    /// Only the first of publishing's two independent gates. The second, the
    /// `publish:<content_type>` capability, is checked with [`identity_holds`].
    ///
    /// [`identity_holds`]: Self::identity_holds
    pub fn allows_content_type(&self, content_type: &ContentType) -> bool {
        self.policy.allows_content_type(content_type)
    }

    /// A hash over the complete state, for cross-node replay comparison.
    ///
    /// Two nodes that replayed the same canonical chain must produce the same
    /// value. The harness asserts this as an exact match rather than an
    /// approximate check, because a mismatch is a real conformance bug.
    pub fn state_hash(&self) -> Hash {
        let mut e = Enc::domain("intranet.governance-state.v1");
        self.network.encode(&mut e);
        self.policy.encode(&mut e);
        e.seq(self.groups.values(), |e, group| group.encode(e));
        e.seq(self.device_certificates.keys(), |e, device| {
            device.encode(e);
        });
        e.seq(self.revoked_devices.iter(), |e, device| device.encode(e));
        e.seq(self.delisted.iter(), |e, pointer| {
            e.fixed(pointer.as_bytes());
        });
        e.u64(self.epoch);
        e.option(self.epoch_rotation_ref.as_ref(), |e, hash| {
            e.fixed(hash.as_bytes());
        });
        hash_bytes(&e.finish())
    }

    /// Checks that the acting identity is authorized to produce `entry`.
    fn authorize(&self, entry: &LogEntry) -> Result<(), GovernanceError> {
        let author = &entry.author;

        let required = match &entry.body {
            EntryBody::Genesis { .. } => return Err(GovernanceError::UnexpectedGenesis),

            EntryBody::DefineGroup { .. } => Capability::DefineGroup,
            EntryBody::PolicyChange { .. } => Capability::DefinePolicy,
            EntryBody::ContentTypePolicy { .. } => Capability::DefineContentPolicy,
            EntryBody::Moderation(_) => Capability::ModerateContent,
            EntryBody::MembershipChange { group, .. } => {
                // The target group must exist before its membership can be
                // managed, and refusing an unknown group here is what stops a
                // capability being demanded for a group whose tier cannot be
                // resolved.
                if !self.groups.contains_key(group) {
                    return Err(GovernanceError::UnknownGroup(group.clone()));
                }
                Capability::ManageMembership(group.clone())
            }

            EntryBody::EpochRotation { reason } => match reason {
                RotationReason::MembershipChange => Capability::RevokeNode,
                // §1.3, point 6: any identity may request this, without holding
                // any capability, so that reporting a device compromise is never
                // discouraged. Current membership is still required — a
                // non-member has no standing to rotate the network's keys.
                RotationReason::SelfInitiated => {
                    return if self.is_member(author) {
                        Ok(())
                    } else {
                        Err(GovernanceError::not_a_member(author))
                    };
                }
            },

            // Device records are capability-free (§1.3, point 5): authority comes
            // from master-seed possession, proven by the certificate's own
            // signature, not from any group capability.
            EntryBody::DeviceEnrollment(cert) => {
                cert.verify_for_network(&self.network).map_err(|e| {
                    GovernanceError::BadDeviceRecord {
                        reason: e.to_string(),
                    }
                })?;
                return self.authorize_device_record(author, &cert.identity);
            }
            EntryBody::DeviceRevocation(revocation) => {
                revocation
                    .verify()
                    .map_err(|e| GovernanceError::BadDeviceRecord {
                        reason: e.to_string(),
                    })?;
                if revocation.network != self.network {
                    return Err(GovernanceError::NetworkMismatch {
                        entry_network: revocation.network.short(),
                        log_network: self.network.short(),
                    });
                }
                return self.authorize_device_record(author, &revocation.identity);
            }
        };

        if self.identity_holds(author, &required) {
            Ok(())
        } else {
            Err(GovernanceError::unauthorized(author, required))
        }
    }

    /// A device record must be submitted by the identity it concerns.
    ///
    /// Nobody may enroll or revoke devices on another identity's behalf, even
    /// holding every governance capability — this is master-seed authority, not
    /// group authority, and conflating them would let an admin attach their own
    /// device to someone else's identity.
    ///
    /// Current membership is also required, to keep non-members from appending
    /// unbounded capability-free entries. **Flagged: the specs do not state
    /// whether a pre-admission waiting-room identity may enroll a device; this
    /// takes the fail-closed reading.**
    fn authorize_device_record(
        &self,
        author: &PerNetworkIdentityId,
        subject: &PerNetworkIdentityId,
    ) -> Result<(), GovernanceError> {
        if author != subject {
            return Err(GovernanceError::DeviceRecordAuthorMismatch {
                subject: subject.short(),
                author: author.short(),
            });
        }
        if !self.is_member(author) {
            return Err(GovernanceError::not_a_member(author));
        }
        Ok(())
    }

    /// Applies an already-authorized entry's effects.
    fn mutate(&mut self, entry: &LogEntry) -> Result<(), GovernanceError> {
        match &entry.body {
            EntryBody::Genesis { .. } => return Err(GovernanceError::UnexpectedGenesis),

            EntryBody::DefineGroup {
                group,
                capabilities,
            } => {
                self.groups
                    .entry(group.clone())
                    .and_modify(|existing| existing.capabilities = capabilities.clone())
                    .or_insert_with(|| Group::new(group.clone(), capabilities.clone()));
            }

            EntryBody::MembershipChange {
                group,
                identity,
                action,
            } => match action {
                MembershipAction::Add => {
                    let target = self
                        .groups
                        .get_mut(group)
                        .ok_or_else(|| GovernanceError::UnknownGroup(group.clone()))?;
                    target.members.insert(
                        *identity,
                        MembershipRecord {
                            added_by: Some(entry.author),
                            added_at: entry.timestamp,
                        },
                    );
                }
                MembershipAction::Remove { cascade } => {
                    self.remove_membership(group, identity, *cascade, entry.timestamp)?;
                }
            },

            EntryBody::PolicyChange { policy } => {
                self.policy = policy.clone();
            }

            EntryBody::ContentTypePolicy { allowlist } => {
                self.policy.content_type_allowlist = allowlist.clone();
            }

            EntryBody::EpochRotation { .. } => {
                self.epoch += 1;
                self.epoch_rotation_ref = Some(entry.hash());
            }

            EntryBody::DeviceEnrollment(cert) => {
                // A revoked device key cannot be re-enrolled by replaying its
                // original certificate; revocation is permanent for that key.
                if !self.revoked_devices.contains(&cert.device) {
                    self.device_certificates.insert(cert.device, cert.clone());
                }
            }

            EntryBody::DeviceRevocation(revocation) => {
                self.device_certificates.remove(&revocation.device);
                self.revoked_devices.insert(revocation.device);
            }

            EntryBody::Moderation(moderation) => match moderation.action {
                ModerationAction::Delist => {
                    self.delisted.insert(moderation.target_pointer_id);
                }
                ModerationAction::Relist => {
                    self.delisted.remove(&moderation.target_pointer_id);
                }
            },
        }

        Ok(())
    }

    /// Removes a membership, optionally cascading — §2.5.
    fn remove_membership(
        &mut self,
        group_id: &GroupId,
        identity: &PerNetworkIdentityId,
        cascade: Option<crate::Cascade>,
        removed_at: Timestamp,
    ) -> Result<(), GovernanceError> {
        let group = self
            .groups
            .get_mut(group_id)
            .ok_or_else(|| GovernanceError::UnknownGroup(group_id.clone()))?;

        if group.members.remove(identity).is_none() {
            return Err(GovernanceError::NotInGroup {
                identity: identity.short(),
                group: group_id.clone(),
            });
        }

        let Some(cascade) = cascade else {
            // Default, non-cascading: anyone this identity added stays, since
            // their membership was validly granted at the time. Routine
            // membership cleanup should not silently strip everyone a departing
            // moderator ever onboarded.
            return Ok(());
        };

        // Cascading is recursive: someone removed by the cascade may themselves
        // have added others, and those go too.
        let cutoff = cascade
            .window_millis
            .map(|window| removed_at.plus_millis(-window));

        let mut pending = vec![*identity];
        while let Some(remover) = pending.pop() {
            let doomed: Vec<PerNetworkIdentityId> = group
                .members
                .iter()
                .filter(|(_, record)| record.added_by == Some(remover))
                .filter(|(_, record)| cutoff.is_none_or(|cutoff| record.added_at >= cutoff))
                .map(|(id, _)| *id)
                .collect();

            for id in doomed {
                group.members.remove(&id);
                pending.push(id);
            }
        }

        Ok(())
    }

    /// Enforces the `everyone` ceiling — §2.4.
    ///
    /// Checked against the *candidate* state after every entry, which is what
    /// makes it catch both directions of the invariant with one rule:
    ///
    /// 1. Granting `everyone` a governance-tier capability directly.
    /// 2. Later granting a governance-tier capability to some group X while
    ///    `everyone` already holds `manage-membership:X` — because X's new power
    ///    retroactively makes `everyone`'s existing grant governance-tier.
    ///
    /// The second case is the subtle one, and it is why this is a whole-state
    /// check rather than a check on the entry being applied.
    fn check_everyone_invariant(&self) -> Result<(), GovernanceError> {
        let Some(everyone) = self.groups.get(&GroupId::everyone()) else {
            return Ok(());
        };

        match &everyone.capabilities {
            CapabilitySet::All => Err(GovernanceError::EveryoneUnrestricted),
            CapabilitySet::Explicit(held) => {
                for capability in held {
                    if self.tier_of(capability)? == Tier::Governance {
                        return Err(GovernanceError::EveryoneGovernanceTier {
                            capability: capability.clone(),
                        });
                    }
                }
                Ok(())
            }
        }
    }
}
