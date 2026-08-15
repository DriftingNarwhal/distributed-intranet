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
    AppName, Capability, CapabilitySet, ContentType, EntryBody, GovernanceError, Group, GroupId,
    LogEntry, MembershipAction, MembershipRecord, ModerationAction, NetworkPolicy, PointerId,
    RECLAIM_APP_NAME, REGISTER_APP_NAME, RotationReason, Tier,
};
use intranet_crypto::{Enc, Hash, Timestamp, hash_bytes};
use intranet_identity::{
    DeviceCertificate, DevicePublicKey, NetworkId, PerNetworkIdentityId,
};
use std::collections::{BTreeMap, BTreeSet};

/// Who owns an application name, and what it resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppNameRecord {
    /// The app this name resolves to.
    pub app_id: PointerId,
    /// The identity that registered or last reclaimed it.
    pub owner: PerNetworkIdentityId,
    /// When the current registration was made.
    ///
    /// Taken from the governance entry, so it is ordered by the log rather than
    /// self-attested. A submitter cannot backdate this to claim priority — the
    /// attack that made a discovery-index-only registry unsafe.
    pub registered_at: Timestamp,
}

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
    /// Authoritative application name ownership — App Hosting Spec §4.3.
    ///
    /// Lives in replayed governance state rather than a discovery index,
    /// because ownership needs a trustworthy total order and permanent
    /// durability. A discovery index has neither: its ordering is
    /// self-attested and its entries lapse without refresh.
    pub app_names: BTreeMap<AppName, AppNameRecord>,
    /// Votes currently open, by `vote_id` — §2.6.1, point 1.
    ///
    /// Recorded when a vote opens, at which point its frozen roster was checked
    /// against the membership the log actually held. A certificate is verified
    /// against the proposal *here*, never against one travelling beside it, so a
    /// forged roster cannot arrive with the certificate that relies on it.
    pub open_votes: BTreeMap<Hash, crate::VoteProposal>,
    /// Action hashes a vote has authorized — §2.6.1.
    ///
    /// A vote's outcome is certificate *existence*, and this is where existence
    /// becomes a replayable fact rather than a question each node answers from
    /// whatever ballots it happened to collect. Keyed by the subject the
    /// certificate settles, which is the hash of the entry body the vote
    /// authorizes — so a certificate authorizes that action and nothing else.
    pub passed_votes: BTreeSet<Hash>,
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
                via_invite: None,
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
            open_votes: BTreeMap::new(),
            passed_votes: BTreeSet::new(),
            app_names: BTreeMap::new(),
            epoch: 0,
            epoch_rotation_ref: None,
        };

        state.check_everyone_invariant()?;
        state.check_policy_coherence()?;
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
        next.check_policy_coherence()?;
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

    /// How many memberships were granted using a given invite — §5.6.
    ///
    /// Invites are use-count-limited, and this is what makes that limit
    /// checkable rather than aspirational: because every membership records the
    /// invite that produced it, the count is a computation over replayed state
    /// that every node reaches the same answer for. A per-node private tally
    /// could never be reconciled between nodes and would let a multi-use invite
    /// be spent once against each node separately.
    ///
    /// Counts across all groups, since a single admission may place an identity
    /// in more than one group; callers checking a use limit should count
    /// distinct identities rather than raw records, which is what this returns.
    pub fn invite_use_count(&self, invite_id: &Hash) -> usize {
        let mut used_by: BTreeSet<PerNetworkIdentityId> = BTreeSet::new();
        for group in self.groups.values() {
            for (identity, record) in &group.members {
                if record
                    .via_invite
                    .is_some_and(|provenance| provenance.invite_id == *invite_id)
                {
                    used_by.insert(*identity);
                }
            }
        }
        used_by.len()
    }

    /// Resolves an application name to its current owner and target — §4.3.
    ///
    /// Answered by replay, so it is deterministic and cannot be influenced by a
    /// backdated claim or by whether anyone is currently re-announcing a
    /// discovery entry. A name absent here is unclaimed.
    pub fn resolve_app_name(&self, name: &AppName) -> Option<&AppNameRecord> {
        self.app_names.get(name)
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
        // Invite use counts are derivable from membership provenance, so they
        // need no separate state: see `invite_use_count`.
        e.seq(self.device_certificates.keys(), |e, device| {
            device.encode(e);
        });
        e.seq(self.revoked_devices.iter(), |e, device| device.encode(e));
        e.seq(self.delisted.iter(), |e, pointer| {
            e.fixed(pointer.as_bytes());
        });
        e.seq(self.app_names.iter(), |e, (name, record)| {
            e.str(name.as_str()).fixed(record.app_id.as_bytes());
            record.owner.encode(e);
            e.i64(record.registered_at.as_millis());
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

            // Which capability is required depends on current state, the same
            // pattern `manage-membership` uses: claiming a free name is a
            // low-bar ordinary action, while taking one somebody already holds
            // is governance-tier. Deciding this from replayed state is what
            // stops a broad grant of the former from also conferring the latter.
            EntryBody::AppNameRegistration { name, .. } => {
                if self.app_names.contains_key(name) {
                    Capability::extension(RECLAIM_APP_NAME)
                } else {
                    Capability::extension(REGISTER_APP_NAME)
                }
            }
            EntryBody::MembershipChange { group, action, .. } => {
                // The target group must exist before its membership can be
                // managed, and refusing an unknown group here is what stops a
                // capability being demanded for a group whose tier cannot be
                // resolved.
                if !self.groups.contains_key(group) {
                    return Err(GovernanceError::UnknownGroup(group.clone()));
                }

                // Under member-vote policy, admission is decided by the
                // electorate rather than by a capability holder (§2.6, §2.6.1).
                // The check is that a certificate settling *this exact action*
                // has been recorded — bound by the action hash, so a passing
                // vote authorizes the admission it was held for and no other.
                //
                // Removal is deliberately left on the capability path. §2.6
                // frames the vote as governing *admission* ("admission requires
                // a quorum of existing members"), and routing removal through a
                // vote would mean a compromised account could only be ejected at
                // the speed of a quorum — the opposite of what a network needs
                // in that moment.
                if let crate::GovernanceModel::MemberVote { .. } = self.policy.governance_model
                    && matches!(action, MembershipAction::Add { .. })
                {
                    return if self.passed_votes.contains(&entry.body.action_hash()) {
                        // Somebody still has to append it, and a non-member has
                        // no standing to act on the network's behalf even
                        // holding a valid certificate.
                        if self.is_member(author) {
                            Ok(())
                        } else {
                            Err(GovernanceError::not_a_member(author))
                        }
                    } else {
                        Err(GovernanceError::InvalidQuorumCertificate {
                            reason: "no passing vote authorizes this admission".into(),
                        })
                    };
                }

                Capability::ManageMembership(group.clone())
            }

            // Neither proposing nor recording an outcome needs a capability —
            // that is the point of §2.6.1's no-central-tallying design. What
            // they need is a roster and a certificate that actually verify,
            // which `mutate` checks. An author who is not a member has no
            // standing to put the network's electorate to work either way.
            //
            // **Flagged: §2.6.1 does not say who may propose a vote.** Current
            // membership is the natural floor, since proposing decides nothing
            // — the electorate settles it — and requiring more would put the
            // one procedure meant to bypass capability holders back behind one.
            EntryBody::VoteProposed { .. } | EntryBody::VoteOutcome { .. } => {
                return if self.is_member(author) {
                    Ok(())
                } else {
                    Err(GovernanceError::not_a_member(author))
                };
            }

            EntryBody::EpochRotation { reason, .. } => match reason {
                // The rotation carries the same authority as the membership
                // change that caused it: admitting keys a member in, revoking
                // keys them out, and §2.2 keeps those two deliberately separate.
                RotationReason::MemberAdmitted => Capability::ApproveNode,
                RotationReason::MemberRevoked => Capability::RevokeNode,
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
                MembershipAction::Add { via_invite } => {
                    let target = self
                        .groups
                        .get_mut(group)
                        .ok_or_else(|| GovernanceError::UnknownGroup(group.clone()))?;
                    target.members.insert(
                        *identity,
                        MembershipRecord {
                            added_by: Some(entry.author),
                            added_at: entry.timestamp,
                            via_invite: *via_invite,
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

            EntryBody::VoteProposed { proposal } => {
                // The check the whole design turns on. A proposal asserts its
                // frozen roster; replay is the only thing that knows what the
                // roster actually was. Without this a proposer could freeze a
                // roster of keypairs they control, cast every ballot, and
                // present a certificate that verifies perfectly against the
                // roster it came with.
                let group = self
                    .groups
                    .get(&proposal.electorate)
                    .ok_or_else(|| GovernanceError::UnknownGroup(proposal.electorate.clone()))?;
                let actual: BTreeSet<PerNetworkIdentityId> =
                    group.members.keys().copied().collect();
                if proposal.electorate_snapshot != actual {
                    return Err(GovernanceError::InvalidQuorumCertificate {
                        reason: "proposal's electorate does not match the membership at this \
                                 point in the log"
                            .into(),
                    });
                }
                self.open_votes.insert(proposal.vote_id(), proposal.clone());
            }

            EntryBody::VoteOutcome { certificate } => {
                // Looked up rather than trusted from the entry: the roster this
                // verifies against is the one the log validated when the vote
                // opened.
                let proposal = self.open_votes.get(&certificate.vote_id).ok_or_else(|| {
                    GovernanceError::InvalidQuorumCertificate {
                        reason: "no open vote matches this certificate".into(),
                    }
                })?;
                // Verified here rather than trusted: the entry's signature only
                // says its author appended it, and an author can append a
                // certificate they assembled badly or made up. Every node
                // re-verifies against the frozen electorate and the ballots'
                // own timestamps, which is what makes "a vote passed" a fact
                // every node computes identically.
                if certificate.verify(proposal)? != crate::VoteOutcome::Passed {
                    return Err(GovernanceError::InvalidQuorumCertificate {
                        reason: "certificate does not reach quorum".into(),
                    });
                }
                let subject = proposal.subject;
                // The vote is settled, so it stops being open — which also makes
                // a second, competing certificate for the same vote a no-op
                // rather than something to reconcile.
                self.open_votes.remove(&certificate.vote_id);
                self.passed_votes.insert(subject);
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

            EntryBody::AppNameRegistration { name, app_id } => {
                self.app_names.insert(
                    name.clone(),
                    AppNameRecord {
                        app_id: *app_id,
                        owner: entry.author,
                        registered_at: entry.timestamp,
                    },
                );
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
    /// Refuses policy combinations that require opposite things — §2.4, §2.6.
    ///
    /// Only one pairing is contradictory today, and it is contradictory in a way
    /// that has no sensible resolution. **Auto-admit** (§2.4) says a valid invite
    /// immediately places the joiner in `everyone`; **member-vote** (§2.6) says
    /// admission requires a quorum of the electorate. A network configured for
    /// both is asking for admission to be simultaneously automatic and
    /// deliberated.
    ///
    /// Checked at genesis and on every policy change — the two moments policy
    /// can be set — rather than at the moment a joiner is refused. Discovering
    /// it then would mean the operator learns their network cannot admit anyone
    /// from a confused joiner rather than from the action that broke it.
    ///
    /// **Flagged: the specs define both settings independently and never address
    /// the pairing.** Refusing is the fail-closed reading: the alternative is
    /// silently privileging one setting, which makes the other a lie.
    fn check_policy_coherence(&self) -> Result<(), GovernanceError> {
        if matches!(self.policy.governance_model, crate::GovernanceModel::MemberVote { .. })
            && self.policy.admission_mode == crate::AdmissionMode::AutoAdmit
        {
            return Err(GovernanceError::IncoherentPolicy {
                reason: "auto-admit grants membership on a valid invite, but member-vote \
                         requires a quorum to approve admission — a network cannot do both, \
                         so pair member-vote with explicit intake"
                    .into(),
            });
        }
        Ok(())
    }

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
