//! Governance conformance tests — Core Protocol Spec §2, Reference Test Harness Spec §3.
//!
//! These exercise the public API the way the CLI harness eventually will, and
//! they assert exact matches wherever the protocol is specified as deterministic
//! (replay, fork choice, finality, quorum outcomes) rather than approximate
//! checks — a mismatch in any of those is a real conformance bug, not noise.

use intranet_crypto::{Hash, Timestamp, hash_bytes};
use intranet_governance::*;
use intranet_identity::{
    DeviceCertificate, DevicePublicKey, DeviceSeed, MasterSeed, NetworkId, PerNetworkIdentity,
};
use std::collections::BTreeSet;

const NETWORK: NetworkId = NetworkId::from_bytes([42u8; 32]);

/// A deterministic identity, so tests can name participants by number.
fn identity(n: u8) -> PerNetworkIdentity {
    MasterSeed::from_entropy([n; 32]).identity_for(&NETWORK).unwrap()
}

fn at(millis: i64) -> Timestamp {
    Timestamp::from_millis(millis)
}

fn policy() -> NetworkPolicy {
    NetworkPolicy::conservative_default()
}

fn genesis_with(
    founder: &PerNetworkIdentity,
    policy: NetworkPolicy,
    everyone_capabilities: impl IntoIterator<Item = Capability>,
) -> LogEntry {
    LogEntry::create(
        founder,
        None,
        at(0),
        EntryBody::Genesis {
            network: NETWORK,
            policy,
            everyone_capabilities: everyone_capabilities.into_iter().collect(),
        },
    )
}

fn genesis(founder: &PerNetworkIdentity) -> LogEntry {
    genesis_with(founder, policy(), [Capability::ReadContent])
}

/// Appends an entry to a chain, chaining it onto the previous entry's hash.
fn append(
    chain: &mut Vec<LogEntry>,
    author: &PerNetworkIdentity,
    timestamp: Timestamp,
    body: EntryBody,
) -> Hash {
    let parent = chain.last().map(LogEntry::hash);
    let entry = LogEntry::create(author, parent, timestamp, body);
    let hash = entry.hash();
    chain.push(entry);
    hash
}

fn define_group(group: &str, capabilities: impl IntoIterator<Item = Capability>) -> EntryBody {
    EntryBody::DefineGroup {
        group: GroupId::new(group),
        capabilities: CapabilitySet::explicit(capabilities),
    }
}

fn add_to(group: &str, who: &PerNetworkIdentity) -> EntryBody {
    add_to_via(group, who, None)
}

fn add_to_via(
    group: &str,
    who: &PerNetworkIdentity,
    via_invite: Option<InviteProvenance>,
) -> EntryBody {
    EntryBody::MembershipChange {
        group: GroupId::new(group),
        identity: who.id(),
        action: MembershipAction::Add { via_invite },
    }
}

fn remove_from(group: &str, who: &PerNetworkIdentity, cascade: Option<Cascade>) -> EntryBody {
    EntryBody::MembershipChange {
        group: GroupId::new(group),
        identity: who.id(),
        action: MembershipAction::Remove { cascade },
    }
}

// ---------------------------------------------------------------------------
// Genesis and the implicit groups (§2.3, §2.4)
// ---------------------------------------------------------------------------

#[test]
fn genesis_creates_both_implicit_groups() {
    let founder = identity(1);
    let state = GovernanceState::genesis(&genesis(&founder)).unwrap();

    let founders = &state.groups[&GroupId::founders()];
    assert_eq!(founders.capabilities, CapabilitySet::All);
    assert!(founders.contains(&founder.id()));

    let everyone = &state.groups[&GroupId::everyone()];
    assert!(everyone.capabilities.grants(&Capability::ReadContent));
    assert!(everyone.members.is_empty());
}

#[test]
fn founders_holds_every_capability_including_ones_defined_later() {
    let founder = identity(1);
    let state = GovernanceState::genesis(&genesis(&founder)).unwrap();

    assert!(state.identity_holds(&founder.id(), &Capability::DefineGroup));
    assert!(state.identity_holds(&founder.id(), &Capability::RevokeNode));
    assert!(state.identity_holds(
        &founder.id(),
        &Capability::manage_membership("a-group-invented-later")
    ));
    assert!(state.identity_holds(&founder.id(), &Capability::extension("defined-by-a-later-spec")));
}

#[test]
fn a_non_founder_is_not_a_member_and_holds_nothing() {
    let state = GovernanceState::genesis(&genesis(&identity(1))).unwrap();
    let stranger = identity(9);
    assert!(!state.is_member(&stranger.id()));
    assert!(!state.identity_holds(&stranger.id(), &Capability::ReadContent));
}

// ---------------------------------------------------------------------------
// The `everyone` ceiling as a class, not a name list (§2.2, §2.4)
// ---------------------------------------------------------------------------

#[test]
fn everyone_may_not_hold_a_governance_tier_capability_at_genesis() {
    let founder = identity(1);
    let entry = genesis_with(
        &founder,
        policy(),
        [Capability::ReadContent, Capability::DefineGroup],
    );

    assert!(matches!(
        GovernanceState::genesis(&entry),
        Err(GovernanceError::EveryoneGovernanceTier {
            capability: Capability::DefineGroup
        })
    ));
}

#[test]
fn everyone_may_not_be_granted_governance_tier_capability_later() {
    let founder = identity(1);
    let mut chain = vec![genesis(&founder)];
    append(
        &mut chain,
        &founder,
        at(10),
        define_group(EVERYONE, [Capability::ReadContent, Capability::ModerateContent]),
    );

    assert!(matches!(
        GovernanceState::replay(&chain),
        Err(GovernanceError::EveryoneGovernanceTier { .. })
    ));
}

#[test]
fn everyone_ceiling_covers_capabilities_defined_after_the_base_spec() {
    // Harness Spec §3: a capability defined and tagged governance-tier *after*
    // the base spec must still be rejected for `everyone`. This is the whole
    // reason the ceiling keys off a tier class rather than a hardcoded list of
    // names — a list written today cannot mention a capability invented later.
    let founder = identity(1);
    let mut policy = policy();
    policy
        .extension_capabilities
        .insert("approve-app-publish".into(), Tier::Governance);
    policy
        .extension_capabilities
        .insert("register-app-name".into(), Tier::Ordinary);

    let mut chain = vec![genesis_with(&founder, policy, [Capability::ReadContent])];

    // The ordinary extension capability is fine for `everyone`.
    append(
        &mut chain,
        &founder,
        at(10),
        define_group(
            EVERYONE,
            [
                Capability::ReadContent,
                Capability::extension("register-app-name"),
            ],
        ),
    );
    assert!(GovernanceState::replay(&chain).is_ok());

    // The governance-tier one is not, despite never appearing in this crate.
    append(
        &mut chain,
        &founder,
        at(20),
        define_group(
            EVERYONE,
            [
                Capability::ReadContent,
                Capability::extension("approve-app-publish"),
            ],
        ),
    );
    assert!(matches!(
        GovernanceState::replay(&chain),
        Err(GovernanceError::EveryoneGovernanceTier { .. })
    ));
}

#[test]
fn an_unregistered_extension_capability_is_refused_not_assumed_ordinary() {
    // Fail-closed: assuming ordinary is exactly the hole the tier class closes.
    let founder = identity(1);
    let mut chain = vec![genesis(&founder)];
    append(
        &mut chain,
        &founder,
        at(10),
        define_group(EVERYONE, [Capability::extension("never-declared")]),
    );

    assert!(matches!(
        GovernanceState::replay(&chain),
        Err(GovernanceError::UnregisteredExtensionCapability(name)) if name == "never-declared"
    ));
}

#[test]
fn everyone_may_never_hold_the_unrestricted_set() {
    let founder = identity(1);
    let mut chain = vec![genesis(&founder)];
    append(
        &mut chain,
        &founder,
        at(10),
        EntryBody::DefineGroup {
            group: GroupId::everyone(),
            capabilities: CapabilitySet::All,
        },
    );
    assert_eq!(
        GovernanceState::replay(&chain),
        Err(GovernanceError::EveryoneUnrestricted)
    );
}

// ---------------------------------------------------------------------------
// manage-membership's dynamic tier (§2.4)
// ---------------------------------------------------------------------------

#[test]
fn everyone_may_manage_membership_of_a_powerless_group() {
    let founder = identity(1);
    let mut chain = vec![genesis(&founder)];
    append(&mut chain, &founder, at(10), define_group("readers", [Capability::ReadContent]));
    append(
        &mut chain,
        &founder,
        at(20),
        define_group(
            EVERYONE,
            [
                Capability::ReadContent,
                Capability::manage_membership("readers"),
            ],
        ),
    );

    let state = GovernanceState::replay(&chain).unwrap();
    assert_eq!(
        state
            .tier_of(&Capability::manage_membership("readers"))
            .unwrap(),
        Tier::Ordinary
    );
}

#[test]
fn everyone_may_not_manage_membership_of_a_powerful_group() {
    let founder = identity(1);
    let mut chain = vec![genesis(&founder)];
    append(&mut chain, &founder, at(10), define_group("mods", [Capability::ModerateContent]));
    append(
        &mut chain,
        &founder,
        at(20),
        define_group(EVERYONE, [Capability::manage_membership("mods")]),
    );

    assert!(matches!(
        GovernanceState::replay(&chain),
        Err(GovernanceError::EveryoneGovernanceTier { .. })
    ));
}

#[test]
fn everyone_may_not_manage_membership_of_founders() {
    let founder = identity(1);
    let mut chain = vec![genesis(&founder)];
    append(
        &mut chain,
        &founder,
        at(10),
        define_group(EVERYONE, [Capability::manage_membership(FOUNDERS)]),
    );
    assert!(matches!(
        GovernanceState::replay(&chain),
        Err(GovernanceError::EveryoneGovernanceTier { .. })
    ));
}

#[test]
fn empowering_a_group_everyone_already_manages_is_rejected_retroactively() {
    // The subtle direction of the invariant: `everyone` legitimately holds
    // manage-membership over a powerless group, and a *later* grant would make
    // that group powerful. The later grant must be refused, because it would
    // hand `everyone` indirect governance power without ever touching
    // `everyone`'s own capability set.
    let founder = identity(1);
    let mut chain = vec![genesis(&founder)];
    append(&mut chain, &founder, at(10), define_group("helpers", [Capability::ReadContent]));
    append(
        &mut chain,
        &founder,
        at(20),
        define_group(
            EVERYONE,
            [
                Capability::ReadContent,
                Capability::manage_membership("helpers"),
            ],
        ),
    );
    assert!(GovernanceState::replay(&chain).is_ok(), "setup must be legal");

    append(
        &mut chain,
        &founder,
        at(30),
        define_group("helpers", [Capability::ReadContent, Capability::RevokeNode]),
    );

    assert!(
        matches!(
            GovernanceState::replay(&chain),
            Err(GovernanceError::EveryoneGovernanceTier { .. })
        ),
        "empowering a group that `everyone` manages must be refused"
    );
}

#[test]
fn a_management_cycle_without_governance_power_resolves_rather_than_hanging() {
    // Group A manages B while B manages A. Neither holds governance power, so
    // the cycle confers none and must resolve to Ordinary — not recurse forever,
    // and not be refused as if it were dangerous.
    let founder = identity(1);
    let mut chain = vec![genesis(&founder)];
    append(&mut chain, &founder, at(10), define_group("a", [Capability::ReadContent]));
    append(
        &mut chain,
        &founder,
        at(20),
        define_group("b", [Capability::manage_membership("a")]),
    );
    append(
        &mut chain,
        &founder,
        at(30),
        define_group("a", [Capability::manage_membership("b")]),
    );

    let state = GovernanceState::replay(&chain).unwrap();
    assert_eq!(state.tier_of(&Capability::manage_membership("a")).unwrap(), Tier::Ordinary);
    assert_eq!(state.tier_of(&Capability::manage_membership("b")).unwrap(), Tier::Ordinary);
}

#[test]
fn a_management_cycle_containing_governance_power_is_governance_tier() {
    let founder = identity(1);
    let mut chain = vec![genesis(&founder)];
    append(&mut chain, &founder, at(10), define_group("a", [Capability::ReadContent]));
    append(
        &mut chain,
        &founder,
        at(20),
        define_group("b", [Capability::manage_membership("a")]),
    );
    append(
        &mut chain,
        &founder,
        at(30),
        define_group(
            "a",
            [Capability::manage_membership("b"), Capability::RevokeNode],
        ),
    );

    let state = GovernanceState::replay(&chain).unwrap();
    assert_eq!(
        state.tier_of(&Capability::manage_membership("a")).unwrap(),
        Tier::Governance
    );
    assert_eq!(
        state.tier_of(&Capability::manage_membership("b")).unwrap(),
        Tier::Governance,
        "power reachable through the cycle must still be seen"
    );
}

// ---------------------------------------------------------------------------
// Authorization (§2.1, §2.2)
// ---------------------------------------------------------------------------

#[test]
fn an_unauthorized_identity_cannot_define_groups() {
    let founder = identity(1);
    let outsider = identity(2);
    let mut chain = vec![genesis(&founder)];
    append(&mut chain, &outsider, at(10), define_group("mine", [Capability::ReadContent]));

    assert!(matches!(
        GovernanceState::replay(&chain),
        Err(GovernanceError::Unauthorized { .. })
    ));
}

#[test]
fn managing_one_group_does_not_confer_managing_another() {
    let founder = identity(1);
    let delegate = identity(2);
    let newcomer = identity(3);

    let mut chain = vec![genesis(&founder)];
    append(&mut chain, &founder, at(10), define_group("alpha", [Capability::ReadContent]));
    append(&mut chain, &founder, at(11), define_group("beta", [Capability::ReadContent]));
    append(
        &mut chain,
        &founder,
        at(12),
        define_group("alpha-admins", [Capability::manage_membership("alpha")]),
    );
    append(&mut chain, &founder, at(13), add_to("alpha-admins", &delegate));

    // Permitted: the delegate manages alpha.
    let mut ok = chain.clone();
    append(&mut ok, &delegate, at(20), add_to("alpha", &newcomer));
    assert!(GovernanceState::replay(&ok).is_ok());

    // Refused: the same delegate has no standing over beta.
    let mut bad = chain;
    append(&mut bad, &delegate, at(20), add_to("beta", &newcomer));
    assert!(matches!(
        GovernanceState::replay(&bad),
        Err(GovernanceError::Unauthorized { .. })
    ));
}

#[test]
fn membership_changes_to_an_unknown_group_are_refused() {
    let founder = identity(1);
    let mut chain = vec![genesis(&founder)];
    append(&mut chain, &founder, at(10), add_to("no-such-group", &identity(2)));
    assert!(matches!(
        GovernanceState::replay(&chain),
        Err(GovernanceError::UnknownGroup(_))
    ));
}

// ---------------------------------------------------------------------------
// Revocation cascade (§2.5)
// ---------------------------------------------------------------------------

/// Builds an onboarding tree under `recruiter`, deliberately spanning a wide
/// time range so the windowed-cascade case has something to discriminate on:
///
/// ```text
/// recruiter ──@1_000──▶ early ──@500_100──▶ early_downstream
///           └─@500_000─▶ late  ──@500_200──▶ late_downstream
/// ```
fn cascade_fixture() -> (Vec<LogEntry>, PerNetworkIdentity, [PerNetworkIdentity; 4]) {
    let founder = identity(1);
    let recruiter = identity(2);
    let early = identity(3);
    let late = identity(4);
    let early_downstream = identity(5);
    let late_downstream = identity(6);

    let mut chain = vec![genesis(&founder)];
    append(&mut chain, &founder, at(10), define_group("crew", [Capability::ReadContent]));
    append(
        &mut chain,
        &founder,
        at(11),
        define_group("crew-admins", [Capability::manage_membership("crew")]),
    );
    for (i, admin) in [&recruiter, &early, &late].into_iter().enumerate() {
        append(&mut chain, &founder, at(12 + i as i64), add_to("crew-admins", admin));
    }
    // The recruiter is itself a member of the group it manages, so that
    // removing it from `crew` is a real removal rather than a no-op.
    append(&mut chain, &founder, at(20), add_to("crew", &recruiter));

    // Two onboardings by the recruiter, far apart in time.
    append(&mut chain, &recruiter, at(1_000), add_to("crew", &early));
    append(&mut chain, &recruiter, at(500_000), add_to("crew", &late));
    // Each of those onboards someone else, so recursion has somewhere to go.
    append(&mut chain, &early, at(500_100), add_to("crew", &early_downstream));
    append(&mut chain, &late, at(500_200), add_to("crew", &late_downstream));

    (
        chain,
        recruiter,
        [early, late, early_downstream, late_downstream],
    )
}

#[test]
fn removal_does_not_cascade_by_default() {
    let (mut chain, recruiter, [early, late, early_downstream, late_downstream]) =
        cascade_fixture();
    let founder = identity(1);
    append(&mut chain, &founder, at(600_000), remove_from("crew", &recruiter, None));

    let state = GovernanceState::replay(&chain).unwrap();
    let crew = &state.groups[&GroupId::new("crew")];
    assert!(!crew.contains(&recruiter.id()));
    for survivor in [&early, &late, &early_downstream, &late_downstream] {
        assert!(
            crew.contains(&survivor.id()),
            "routine cleanup must not silently strip everyone the departing member onboarded"
        );
    }
}

#[test]
fn opt_in_cascade_removes_downstream_memberships_recursively() {
    let (mut chain, recruiter, [early, late, early_downstream, late_downstream]) =
        cascade_fixture();
    let founder = identity(1);
    append(
        &mut chain,
        &founder,
        at(600_000),
        remove_from("crew", &recruiter, Some(Cascade { window_millis: None })),
    );

    let state = GovernanceState::replay(&chain).unwrap();
    let crew = &state.groups[&GroupId::new("crew")];
    assert!(!crew.contains(&recruiter.id()));
    for removed in [&early, &late, &early_downstream, &late_downstream] {
        assert!(
            !crew.contains(&removed.id()),
            "cascade must recurse into memberships added by those it removes"
        );
    }
}

#[test]
fn windowed_cascade_only_unwinds_recent_additions() {
    // The compromised-account case: undo what the attacker did in the last N
    // hours without unwinding years of legitimate onboarding by the same
    // account. Note the recursion follows only members the cascade *actually*
    // removed — someone onboarded by a survivor is not swept up, even if their
    // own membership falls inside the window.
    let (mut chain, recruiter, [early, late, early_downstream, late_downstream]) =
        cascade_fixture();
    let founder = identity(1);
    append(
        &mut chain,
        &founder,
        at(600_000),
        remove_from(
            "crew",
            &recruiter,
            Some(Cascade {
                window_millis: Some(200_000),
            }),
        ),
    );

    let state = GovernanceState::replay(&chain).unwrap();
    let crew = &state.groups[&GroupId::new("crew")];

    assert!(!crew.contains(&recruiter.id()));
    assert!(
        crew.contains(&early.id()),
        "an addition long before the window must survive"
    );
    assert!(
        crew.contains(&early_downstream.id()),
        "and so must someone onboarded by that survivor, even though their own \
         membership falls inside the window \u{2014} the cascade never reached them"
    );
    assert!(
        !crew.contains(&late.id()),
        "an addition inside the window must go"
    );
    assert!(
        !crew.contains(&late_downstream.id()),
        "and recursion must follow into what that removed member went on to add"
    );
}

#[test]
fn removing_a_non_member_is_an_error_not_a_silent_no_op() {
    let founder = identity(1);
    let mut chain = vec![genesis(&founder)];
    append(&mut chain, &founder, at(10), define_group("crew", [Capability::ReadContent]));
    append(&mut chain, &founder, at(20), remove_from("crew", &identity(7), None));

    assert!(matches!(
        GovernanceState::replay(&chain),
        Err(GovernanceError::NotInGroup { .. })
    ));
}

// ---------------------------------------------------------------------------
// Deterministic replay (§2.7, Harness §3)
// ---------------------------------------------------------------------------

#[test]
fn independent_nodes_replay_to_an_identical_state() {
    let (chain, ..) = cascade_fixture();

    let node_a = GovernanceState::replay(&chain).unwrap();
    let node_b = GovernanceState::replay(&chain).unwrap();

    assert_eq!(
        node_a.state_hash(),
        node_b.state_hash(),
        "replay must be deterministic \u{2014} exact match, not approximate"
    );
    assert_eq!(node_a, node_b);
}

#[test]
fn state_hash_is_sensitive_to_every_material_difference() {
    let founder = identity(1);
    let base = vec![genesis(&founder)];

    let mut with_group = base.clone();
    append(&mut with_group, &founder, at(10), define_group("x", [Capability::ReadContent]));

    let mut with_other_group = base.clone();
    append(&mut with_other_group, &founder, at(10), define_group("y", [Capability::ReadContent]));

    let a = GovernanceState::replay(&base).unwrap().state_hash();
    let b = GovernanceState::replay(&with_group).unwrap().state_hash();
    let c = GovernanceState::replay(&with_other_group).unwrap().state_hash();

    assert_ne!(a, b);
    assert_ne!(b, c);
}

#[test]
fn a_tampered_entry_breaks_replay_rather_than_producing_a_plausible_state() {
    let founder = identity(1);
    let mut chain = vec![genesis(&founder)];
    append(&mut chain, &founder, at(10), define_group("crew", [Capability::ReadContent]));

    // Rewrite the group's capabilities without re-signing.
    chain[1].body = define_group("crew", [Capability::RevokeNode]);

    assert_eq!(
        GovernanceState::replay(&chain),
        Err(GovernanceError::BadSignature)
    );
}

// ---------------------------------------------------------------------------
// Moderation entries (§2.7)
// ---------------------------------------------------------------------------

fn delist(pointer: PointerId) -> EntryBody {
    EntryBody::Moderation(ModerationEntry {
        action: ModerationAction::Delist,
        target_pointer_id: pointer,
    })
}

fn relist(pointer: PointerId) -> EntryBody {
    EntryBody::Moderation(ModerationEntry {
        action: ModerationAction::Relist,
        target_pointer_id: pointer,
    })
}

#[test]
fn delisting_is_resolved_by_replay_and_is_reversible() {
    let founder = identity(1);
    let pointer = PointerId::from_bytes([77u8; 32]);
    let mut chain = vec![genesis(&founder)];

    assert!(!GovernanceState::replay(&chain).unwrap().is_delisted(&pointer));

    append(&mut chain, &founder, at(10), delist(pointer));
    assert!(GovernanceState::replay(&chain).unwrap().is_delisted(&pointer));

    append(&mut chain, &founder, at(20), relist(pointer));
    assert!(
        !GovernanceState::replay(&chain).unwrap().is_delisted(&pointer),
        "moderation is corrected by appending, never by rewriting history"
    );
}

#[test]
fn only_moderate_content_holders_may_delist() {
    let founder = identity(1);
    let member = identity(2);
    let pointer = PointerId::from_bytes([77u8; 32]);

    let mut chain = vec![genesis(&founder)];
    append(&mut chain, &founder, at(10), add_to(EVERYONE, &member));
    append(&mut chain, &member, at(20), delist(pointer));

    assert!(
        matches!(
            GovernanceState::replay(&chain),
            Err(GovernanceError::Unauthorized {
                capability: Capability::ModerateContent,
                ..
            })
        ),
        "an ordinary member must not be able to delist"
    );
}

#[test]
fn moderation_state_is_per_pointer() {
    let founder = identity(1);
    let one = PointerId::from_bytes([1u8; 32]);
    let two = PointerId::from_bytes([2u8; 32]);

    let mut chain = vec![genesis(&founder)];
    append(&mut chain, &founder, at(10), delist(one));

    let state = GovernanceState::replay(&chain).unwrap();
    assert!(state.is_delisted(&one));
    assert!(!state.is_delisted(&two));
}

// ---------------------------------------------------------------------------
// Device records (§1.3)
// ---------------------------------------------------------------------------

fn device_for(owner: &PerNetworkIdentity, seed: u8) -> (DevicePublicKey, DeviceCertificate) {
    let key = DeviceSeed::from_entropy([seed; 32]).key_for(&NETWORK).unwrap();
    let public = DevicePublicKey::from_verifying_key(*key.id().verifying_key());
    let cert = DeviceCertificate::issue(owner, public, "laptop", at(5));
    (public, cert)
}

#[test]
fn a_member_may_enroll_and_revoke_its_own_device_without_any_capability() {
    let founder = identity(1);
    let member = identity(2);
    let (device, cert) = device_for(&member, 50);

    let mut chain = vec![genesis(&founder)];
    append(&mut chain, &founder, at(10), add_to(EVERYONE, &member));
    append(&mut chain, &member, at(20), EntryBody::DeviceEnrollment(cert));

    let state = GovernanceState::replay(&chain).unwrap();
    assert!(state.device_is_authorized(&device, &member.id()));

    let revocation = intranet_identity::DeviceCertificateRevocation::issue(&member, device, at(30));
    append(&mut chain, &member, at(30), EntryBody::DeviceRevocation(revocation));

    let state = GovernanceState::replay(&chain).unwrap();
    assert!(
        !state.device_is_authorized(&device, &member.id()),
        "revocation must cut off signing authority with no identity rotation"
    );
}

#[test]
fn nobody_may_enroll_a_device_on_another_identitys_behalf() {
    // Not even a founder holding every capability: this is master-seed
    // authority, not group authority, and conflating them would let an admin
    // attach their own device to someone else's identity.
    let founder = identity(1);
    let member = identity(2);
    let (_, cert) = device_for(&member, 50);

    let mut chain = vec![genesis(&founder)];
    append(&mut chain, &founder, at(10), add_to(EVERYONE, &member));
    append(&mut chain, &founder, at(20), EntryBody::DeviceEnrollment(cert));

    assert!(matches!(
        GovernanceState::replay(&chain),
        Err(GovernanceError::DeviceRecordAuthorMismatch { .. })
    ));
}

#[test]
fn a_revoked_device_cannot_be_re_enrolled_by_replaying_its_certificate() {
    let founder = identity(1);
    let member = identity(2);
    let (device, cert) = device_for(&member, 50);

    let mut chain = vec![genesis(&founder)];
    append(&mut chain, &founder, at(10), add_to(EVERYONE, &member));
    append(
        &mut chain,
        &member,
        at(20),
        EntryBody::DeviceEnrollment(cert.clone()),
    );
    let revocation = intranet_identity::DeviceCertificateRevocation::issue(&member, device, at(30));
    append(&mut chain, &member, at(30), EntryBody::DeviceRevocation(revocation));
    append(&mut chain, &member, at(40), EntryBody::DeviceEnrollment(cert));

    let state = GovernanceState::replay(&chain).unwrap();
    assert!(
        !state.device_is_authorized(&device, &member.id()),
        "revocation is permanent for that key"
    );
}

// ---------------------------------------------------------------------------
// Fork choice and bounded finality (§2.7.1)
// ---------------------------------------------------------------------------

/// A log seeded with genesis, plus the founder identity and genesis hash.
fn forked_log() -> (GovernanceLog, PerNetworkIdentity, Hash) {
    let founder = identity(1);
    let mut log = GovernanceLog::new();
    let root = log.insert(genesis(&founder)).unwrap();
    (log, founder, root)
}

#[test]
fn a_single_entry_fork_is_broken_by_the_lower_entry_hash() {
    let (mut log, founder, root) = forked_log();

    let left = LogEntry::create(&founder, Some(root), at(10), define_group("left", [Capability::ReadContent]));
    let right = LogEntry::create(&founder, Some(root), at(11), define_group("right", [Capability::ReadContent]));
    let expected = left.hash().min(right.hash());

    log.insert(left).unwrap();
    log.insert(right).unwrap();

    assert_eq!(*log.canonical_chain().last().unwrap(), expected);
}

#[test]
fn fork_choice_does_not_depend_on_insertion_order() {
    let (_, founder, root) = forked_log();
    let left = LogEntry::create(&founder, Some(root), at(10), define_group("left", [Capability::ReadContent]));
    let right = LogEntry::create(&founder, Some(root), at(11), define_group("right", [Capability::ReadContent]));

    let build = |first: LogEntry, second: LogEntry| {
        let mut log = GovernanceLog::new();
        log.insert(genesis(&founder)).unwrap();
        log.insert(first).unwrap();
        log.insert(second).unwrap();
        log.canonical_chain()
    };

    assert_eq!(
        build(left.clone(), right.clone()),
        build(right, left),
        "every node must converge on the same branch regardless of arrival order"
    );
}

#[test]
fn the_branch_with_more_capability_gated_actions_wins() {
    let (mut log, founder, root) = forked_log();

    let short = LogEntry::create(&founder, Some(root), at(10), define_group("short", [Capability::ReadContent]));
    let short_hash = short.hash();
    log.insert(short).unwrap();

    let mut parent = root;
    let mut deep_tip = root;
    for i in 0..3 {
        let entry = LogEntry::create(
            &founder,
            Some(parent),
            at(20 + i),
            define_group(&format!("deep{i}"), [Capability::ReadContent]),
        );
        parent = entry.hash();
        deep_tip = parent;
        log.insert(entry).unwrap();
    }

    let canonical = log.canonical_chain();
    assert_eq!(*canonical.last().unwrap(), deep_tip);
    assert!(!canonical.contains(&short_hash));
}

#[test]
fn padding_a_branch_with_capability_free_entries_does_not_win_it() {
    // The grinding attack a second review pass identified. Device certificates
    // require no capability at all, so an attacker can mint arbitrarily many
    // during a partition. Counting raw entries would let that branch win and
    // void an unfavourable revocation; counting only capability-gated actions
    // is what closes it.
    let founder = identity(1);
    let attacker = identity(2);

    let mut log = GovernanceLog::new();
    let root = log.insert(genesis(&founder)).unwrap();

    // Shared prefix: the attacker becomes a member so it can mint device records.
    let setup = LogEntry::create(&founder, Some(root), at(5), add_to(EVERYONE, &attacker));
    let fork_point = setup.hash();
    log.insert(setup).unwrap();

    // Honest branch: two genuine capability-gated governance actions.
    let mut parent = fork_point;
    let mut honest_tip = fork_point;
    for i in 0..2 {
        let entry = LogEntry::create(
            &founder,
            Some(parent),
            at(10 + i),
            define_group(&format!("honest{i}"), [Capability::ReadContent]),
        );
        parent = entry.hash();
        honest_tip = parent;
        log.insert(entry).unwrap();
    }

    // Attacker branch: twenty capability-free device enrollments.
    let mut parent = fork_point;
    let mut attacker_tip = fork_point;
    for i in 0..20u8 {
        let key = DeviceSeed::from_entropy([100 + i; 32]).key_for(&NETWORK).unwrap();
        let public = DevicePublicKey::from_verifying_key(*key.id().verifying_key());
        let cert = DeviceCertificate::issue(&attacker, public, "grind", at(100 + i64::from(i)));
        let entry = LogEntry::create(
            &attacker,
            Some(parent),
            at(100 + i64::from(i)),
            EntryBody::DeviceEnrollment(cert),
        );
        parent = entry.hash();
        attacker_tip = parent;
        log.insert(entry).unwrap();
    }

    let canonical = log.canonical_chain();
    assert_eq!(
        *canonical.last().unwrap(),
        honest_tip,
        "2 capability-gated actions must beat 20 capability-free ones"
    );
    assert!(!canonical.contains(&attacker_tip));
}

#[test]
fn a_self_initiated_rotation_also_cannot_grind_a_branch() {
    // The generalized form of the same hole: a self-initiated epoch rekey needs
    // no capability either, so it must not count toward branch length.
    let founder = identity(1);
    let member = identity(2);

    let mut log = GovernanceLog::new();
    let root = log.insert(genesis(&founder)).unwrap();
    let setup = LogEntry::create(&founder, Some(root), at(5), add_to(EVERYONE, &member));
    let fork_point = setup.hash();
    log.insert(setup).unwrap();

    let honest = LogEntry::create(
        &founder,
        Some(fork_point),
        at(10),
        define_group("honest", [Capability::ReadContent]),
    );
    let honest_tip = honest.hash();
    log.insert(honest).unwrap();

    let mut parent = fork_point;
    for i in 0..10 {
        let entry = LogEntry::create(
            &member,
            Some(parent),
            at(100 + i),
            EntryBody::EpochRotation {
                reason: RotationReason::SelfInitiated,
                commit: Vec::new(),
            },
        );
        parent = entry.hash();
        log.insert(entry).unwrap();
    }

    assert_eq!(*log.canonical_chain().last().unwrap(), honest_tip);
}

/// Builds a canonical chain of `count` capability-gated actions after genesis.
fn chain_of_gated_actions(count: usize) -> (GovernanceLog, PerNetworkIdentity, Hash, Hash) {
    let founder = identity(1);
    let mut log = GovernanceLog::new();
    let root = log.insert(genesis(&founder)).unwrap();

    let mut parent = root;
    let mut tip = root;
    for i in 0..count {
        let entry = LogEntry::create(
            &founder,
            Some(parent),
            at(10 + i as i64),
            define_group(&format!("g{i}"), [Capability::ReadContent]),
        );
        parent = entry.hash();
        tip = parent;
        log.insert(entry).unwrap();
    }
    (log, founder, root, tip)
}

#[test]
fn finality_requires_depth_and_age_together_not_either_alone() {
    let t = Timestamp::minutes(30);

    // Deep but young: 10 capability-gated actions bury genesis, but only
    // moments have passed. Must NOT be final — this is the anti-grinding case,
    // where an attacker emitting actions rapidly must not buy finality.
    let (mut log, ..) = chain_of_gated_actions(10);
    let reconciliation = log.reconcile(at(t - 1));
    assert_eq!(
        reconciliation.finalized, None,
        "depth alone must not confer finality"
    );

    // Old but shallow: plenty of time has passed, but only 3 actions bury it.
    let (mut log, ..) = chain_of_gated_actions(3);
    let reconciliation = log.reconcile(at(t * 100));
    assert_eq!(
        reconciliation.finalized, None,
        "age alone must not confer finality"
    );

    // Both: final.
    let (mut log, _, root, _) = chain_of_gated_actions(10);
    let reconciliation = log.reconcile(at(t + 1_000));
    assert_eq!(
        reconciliation.finalized,
        Some(root),
        "meeting both thresholds must finalize"
    );
    assert!(log.is_final(&root));
}

#[test]
fn only_entries_buried_deeply_enough_are_finalized() {
    // Worth pinning explicitly, because it is easy to assume "the chain is
    // final" when in fact finality creeps forward one entry at a time: with 10
    // capability-gated actions after genesis, only genesis itself is buried
    // deeply enough. Everything after it is still displaceable.
    let (mut log, _, root, tip) = chain_of_gated_actions(10);
    let reconciliation = log.reconcile(at(Timestamp::minutes(30) + 1_000));

    assert_eq!(reconciliation.finalized, Some(root));
    assert!(log.is_final(&root));
    assert!(
        !log.is_final(&tip),
        "the tip cannot be final \u{2014} nothing is buried behind it yet"
    );
}

#[test]
fn a_finalized_entry_cannot_be_displaced_by_a_longer_branch_presented_later() {
    let t = Timestamp::minutes(30);
    // 15 actions, so that finality reaches a real entry rather than only genesis.
    let (mut log, founder, root, original_tip) = chain_of_gated_actions(15);

    let finalized = log.reconcile(at(t * 2)).finalized.expect("should finalize");
    assert_ne!(
        finalized, root,
        "this test is only meaningful once a non-genesis entry is final"
    );

    // A competing branch rooted at genesis — before the finalized entry — and
    // far longer than everything currently canonical.
    let mut parent = root;
    let mut attacker_tip = root;
    for i in 0..50 {
        let entry = LogEntry::create(
            &founder,
            Some(parent),
            at(200 + i),
            define_group(&format!("late{i}"), [Capability::ReadContent]),
        );
        parent = entry.hash();
        attacker_tip = parent;
        log.insert(entry).unwrap();
    }

    let canonical = log.canonical_chain();
    assert!(
        canonical.contains(&finalized),
        "a finalized entry must survive a longer competing branch"
    );
    assert!(
        canonical.contains(&original_tip),
        "and so must the branch that was canonical through it"
    );
    assert!(
        !canonical.contains(&attacker_tip),
        "50 capability-gated actions must not undo a finalized entry"
    );
}

#[test]
fn finality_only_ever_moves_forward() {
    let t = Timestamp::minutes(30);
    let (mut log, ..) = chain_of_gated_actions(12);

    let far = log.reconcile(at(t * 10)).finalized;
    assert!(far.is_some());

    // Reconciling again with an earlier clock must not un-finalize anything.
    let earlier = log.reconcile(at(t)).finalized;
    assert_eq!(far, earlier, "finality is a commitment, not a recomputation");
}

#[test]
fn reconciliation_reports_voided_entries_and_flags_lost_revocations() {
    // §2.7.1, point 5: without an explicit report, a person legitimately
    // revoked on the losing branch is a full member again on the winning one,
    // simply because nobody was assigned the job of noticing.
    let founder = identity(1);
    let doomed = identity(2);

    let mut log = GovernanceLog::new();
    let root = log.insert(genesis(&founder)).unwrap();
    let setup = LogEntry::create(&founder, Some(root), at(5), add_to(EVERYONE, &doomed));
    let fork_point = setup.hash();
    log.insert(setup).unwrap();

    // Losing branch: a single revocation.
    let revocation = LogEntry::create(
        &founder,
        Some(fork_point),
        at(10),
        remove_from(EVERYONE, &doomed, None),
    );
    let revocation_hash = revocation.hash();
    log.insert(revocation).unwrap();

    // Winning branch: two unrelated governance actions.
    let mut parent = fork_point;
    for i in 0..2 {
        let entry = LogEntry::create(
            &founder,
            Some(parent),
            at(20 + i),
            define_group(&format!("w{i}"), [Capability::ReadContent]),
        );
        parent = entry.hash();
        log.insert(entry).unwrap();
    }

    let reconciliation = log.reconcile(at(1_000));
    let voided: Vec<_> = reconciliation
        .voided
        .iter()
        .filter(|v| v.hash == revocation_hash)
        .collect();

    assert_eq!(voided.len(), 1, "the voided revocation must appear in the report");
    assert_eq!(voided[0].kind, "membership-remove");
    assert!(
        voided[0].security_relevant,
        "a voided revocation must be flagged for resubmission, not merely listed"
    );

    // And the consequence the report exists to surface: they are a member again.
    let state = log.replay_canonical().unwrap();
    assert!(
        state.groups[&GroupId::everyone()].contains(&doomed.id()),
        "the revoked identity is genuinely current again until resubmission"
    );
}

#[test]
fn entries_on_the_canonical_chain_are_not_reported_as_voided() {
    let (mut log, ..) = chain_of_gated_actions(3);
    let reconciliation = log.reconcile(at(1_000));
    assert!(reconciliation.voided.is_empty());
    assert_eq!(reconciliation.canonical.len(), 4);
}

#[test]
fn member_vote_cannot_be_paired_with_auto_admit() {
    // §2.4 and §2.6 define these independently and never address the pairing.
    // Auto-admit says a valid invite admits immediately; member-vote says
    // admission needs a quorum. A network cannot do both, and refusing is the
    // fail-closed reading — the alternative silently privileges one setting and
    // makes the other a lie.
    let founder = identity(1);
    let mut policy = NetworkPolicy::conservative_default();
    policy.governance_model = GovernanceModel::MemberVote {
        electorate: GroupId::everyone(),
        quorum: 3,
        window_millis: 72_000,
    };
    policy.admission_mode = AdmissionMode::AutoAdmit;

    // Refused at genesis, the first moment policy can be set.
    let bad_genesis = LogEntry::create(
        &founder,
        None,
        at(0),
        EntryBody::Genesis {
            network: NETWORK,
            policy: policy.clone(),
            everyone_capabilities: [Capability::ReadContent].into_iter().collect(),
        },
    );
    assert!(matches!(
        GovernanceState::genesis(&bad_genesis),
        Err(GovernanceError::IncoherentPolicy { .. })
    ));

    // And refused on a policy change, the other moment — which is the one that
    // matters in practice, since a network reaches member-vote by switching to
    // it rather than opening under it.
    let mut chain = vec![genesis(&founder)];
    let state = GovernanceState::replay(&chain).unwrap();
    let bad_change = LogEntry::create(
        &founder,
        Some(chain.last().unwrap().hash()),
        at(100),
        EntryBody::PolicyChange { policy },
    );
    assert!(matches!(
        state.apply(&bad_change),
        Err(GovernanceError::IncoherentPolicy { .. })
    ));

    // The coherent pairing is accepted, so the guard is about the combination
    // rather than about member-vote itself.
    let mut good = NetworkPolicy::conservative_default();
    good.governance_model = GovernanceModel::MemberVote {
        electorate: GroupId::everyone(),
        quorum: 3,
        window_millis: 72_000,
    };
    good.admission_mode = AdmissionMode::ExplicitIntake;
    append(&mut chain, &founder, at(110), EntryBody::PolicyChange { policy: good });
    assert!(GovernanceState::replay(&chain).is_ok());
}

#[test]
fn auto_admit_stays_available_under_capability_holders() {
    // The guard must not make auto-admit harder to use in the ordinary case.
    // Capability-holder networks — the default — are untouched by any of this.
    let founder = identity(1);
    let mut policy = NetworkPolicy::conservative_default();
    policy.admission_mode = AdmissionMode::AutoAdmit;
    assert_eq!(policy.governance_model, GovernanceModel::CapabilityHolders);

    let entry = LogEntry::create(
        &founder,
        None,
        at(0),
        EntryBody::Genesis {
            network: NETWORK,
            policy,
            everyone_capabilities: [Capability::ReadContent].into_iter().collect(),
        },
    );
    assert!(GovernanceState::genesis(&entry).is_ok());
}

// ---------------------------------------------------------------------------
// A vote actually deciding something (§2.6, §2.6.1)
// ---------------------------------------------------------------------------

/// A member-vote network with `voters` members of `everyone`, plus the founder.
///
/// Built by admitting under capability rules and *then* switching to
/// member-vote, which is not a convenience — it is the only order that works. A
/// network that opened under member-vote could never admit anybody: admission
/// would need a quorum of an electorate that has no members yet. Switching once
/// a founding electorate exists is the bootstrap path, and it is worth a test
/// fixture demonstrating it rather than a comment asserting it.
fn voting_network(voters: usize) -> (Vec<LogEntry>, Vec<PerNetworkIdentity>) {
    let founder = identity(1);
    let mut chain = vec![genesis(&founder)];
    let mut members = Vec::new();
    for i in 0..voters {
        let member = identity(10 + i as u8);
        append(&mut chain, &founder, at(10 + i as i64), add_to(EVERYONE, &member));
        members.push(member);
    }

    let mut policy = NetworkPolicy::conservative_default();
    policy.governance_model = GovernanceModel::MemberVote {
        electorate: GroupId::everyone(),
        quorum: 3,
        window_millis: 72_000,
    };
    append(&mut chain, &founder, at(50), EntryBody::PolicyChange { policy });
    (chain, members)
}

/// The admission a vote is held about.
fn admission_of(newcomer: &PerNetworkIdentity) -> EntryBody {
    EntryBody::MembershipChange {
        group: GroupId::everyone(),
        identity: newcomer.id(),
        action: MembershipAction::Add { via_invite: None },
    }
}

#[test]
fn under_member_vote_an_admission_needs_a_passing_certificate() {
    // The whole point of the policy: with MemberVote configured, holding
    // `manage-membership:everyone` is no longer enough on its own.
    let founder = identity(1);
    let newcomer = identity(200);
    let (mut chain, voters) = voting_network(5);

    let unauthorized = LogEntry::create(
        &founder,
        Some(chain.last().unwrap().hash()),
        at(100),
        admission_of(&newcomer),
    );
    let state = GovernanceState::replay(&chain).unwrap();
    assert!(
        state.apply(&unauthorized).is_err(),
        "a capability holder must not admit unilaterally under member-vote policy"
    );

    // Open the vote, on the exact action it authorizes.
    let proposal = VoteProposal::open(
        admission_of(&newcomer).action_hash(),
        GroupId::everyone(),
        &state,
        chain.last().unwrap().hash(),
        at(72_000),
        3,
    )
    .unwrap();
    append(
        &mut chain,
        &founder,
        at(110),
        EntryBody::VoteProposed {
            proposal: proposal.clone(),
        },
    );

    // Three voters approve, and anyone may assemble and append the outcome.
    let vote_id = proposal.vote_id();
    let ballots: Vec<Ballot> = voters
        .iter()
        .take(3)
        .map(|voter| Ballot::cast(voter, vote_id, true, at(1_000)))
        .collect();
    let certificate = QuorumCertificate::assemble(&proposal, ballots);
    append(
        &mut chain,
        &voters[0],
        at(120),
        EntryBody::VoteOutcome { certificate },
    );

    // Now the same admission is authorized — and by a member with no capability.
    let state = GovernanceState::replay(&chain).unwrap();
    assert!(state.passed_votes.contains(&admission_of(&newcomer).action_hash()));
    let admission = LogEntry::create(
        &voters[1],
        Some(chain.last().unwrap().hash()),
        at(130),
        admission_of(&newcomer),
    );
    let after = state
        .apply(&admission)
        .expect("a passing vote authorizes the admission it was held for");
    assert!(after.is_member(&newcomer.id()));
}

#[test]
fn a_certificate_authorizes_only_the_action_it_was_held_for() {
    // The action-hash binding. A passing vote is not a general licence to admit:
    // it settles one specific body, so a second admission cannot ride on it.
    let founder = identity(1);
    let voted_on = identity(200);
    let smuggled = identity(201);
    let (mut chain, voters) = voting_network(5);
    let state = GovernanceState::replay(&chain).unwrap();

    let proposal = VoteProposal::open(
        admission_of(&voted_on).action_hash(),
        GroupId::everyone(),
        &state,
        chain.last().unwrap().hash(),
        at(72_000),
        3,
    )
    .unwrap();
    append(
        &mut chain,
        &founder,
        at(110),
        EntryBody::VoteProposed {
            proposal: proposal.clone(),
        },
    );
    let vote_id = proposal.vote_id();
    let certificate = QuorumCertificate::assemble(
        &proposal,
        voters
            .iter()
            .take(3)
            .map(|voter| Ballot::cast(voter, vote_id, true, at(1_000)))
            .collect::<Vec<_>>(),
    );
    append(
        &mut chain,
        &voters[0],
        at(120),
        EntryBody::VoteOutcome { certificate },
    );

    let state = GovernanceState::replay(&chain).unwrap();
    let smuggled_entry = LogEntry::create(
        &voters[1],
        Some(chain.last().unwrap().hash()),
        at(130),
        admission_of(&smuggled),
    );
    assert!(
        state.apply(&smuggled_entry).is_err(),
        "a certificate for one admission must not authorize a different one"
    );
}

#[test]
fn a_proposal_cannot_freeze_an_electorate_the_log_never_had() {
    // The attack that makes opening-as-an-entry necessary. A proposal asserts
    // its roster; if nothing checked it, a proposer could freeze a roster of
    // keypairs they control, cast every ballot themselves, and present a
    // certificate that verifies perfectly against the roster it arrived with.
    let founder = identity(1);
    let newcomer = identity(200);
    let (mut chain, _) = voting_network(5);
    let state = GovernanceState::replay(&chain).unwrap();

    // Sock puppets: never admitted to anything.
    let puppets: Vec<PerNetworkIdentity> = (0..3).map(|i| identity(150 + i)).collect();
    let mut forged = VoteProposal::open(
        admission_of(&newcomer).action_hash(),
        GroupId::everyone(),
        &state,
        chain.last().unwrap().hash(),
        at(72_000),
        3,
    )
    .unwrap();
    forged.electorate_snapshot = puppets.iter().map(|p| p.id()).collect();

    // The certificate itself is internally perfect — it verifies against the
    // roster it came with, which is exactly why the roster cannot be taken on
    // trust.
    let vote_id = forged.vote_id();
    let certificate = QuorumCertificate::assemble(
        &forged,
        puppets
            .iter()
            .map(|p| Ballot::cast(p, vote_id, true, at(1_000)))
            .collect::<Vec<_>>(),
    );
    assert_eq!(certificate.verify(&forged).unwrap(), VoteOutcome::Passed);

    // But the log refuses to open it, because replay knows what the membership
    // actually was at this point in the chain.
    let opening = LogEntry::create(
        &founder,
        Some(chain.last().unwrap().hash()),
        at(110),
        EntryBody::VoteProposed { proposal: forged },
    );
    assert!(
        state.apply(&opening).is_err(),
        "a proposal whose roster disagrees with replayed membership must be refused"
    );

    // And with no open vote, the outcome has nothing to attach to.
    append(
        &mut chain,
        &founder,
        at(120),
        EntryBody::VoteOutcome { certificate },
    );
    assert!(
        GovernanceState::replay(&chain).is_err(),
        "an outcome for a vote that was never opened must be refused"
    );
}

#[test]
fn an_outcome_below_quorum_authorizes_nothing() {
    let founder = identity(1);
    let newcomer = identity(200);
    let (mut chain, voters) = voting_network(5);
    let state = GovernanceState::replay(&chain).unwrap();

    let proposal = VoteProposal::open(
        admission_of(&newcomer).action_hash(),
        GroupId::everyone(),
        &state,
        chain.last().unwrap().hash(),
        at(72_000),
        3,
    )
    .unwrap();
    append(
        &mut chain,
        &founder,
        at(110),
        EntryBody::VoteProposed {
            proposal: proposal.clone(),
        },
    );

    // Two approvals against a quorum of three.
    let vote_id = proposal.vote_id();
    let certificate = QuorumCertificate::assemble(
        &proposal,
        voters
            .iter()
            .take(2)
            .map(|voter| Ballot::cast(voter, vote_id, true, at(1_000)))
            .collect::<Vec<_>>(),
    );
    let outcome = LogEntry::create(
        &voters[0],
        Some(chain.last().unwrap().hash()),
        at(120),
        EntryBody::VoteOutcome { certificate },
    );
    let state = GovernanceState::replay(&chain).unwrap();
    assert!(
        state.apply(&outcome).is_err(),
        "a certificate short of quorum must not be recorded as a passing vote"
    );
}

// ---------------------------------------------------------------------------
// Member-vote quorum (§2.6.1)
// ---------------------------------------------------------------------------

/// A network with `voters` members of `everyone`, plus the founder.
fn electorate_fixture(voters: usize) -> (Vec<LogEntry>, Vec<PerNetworkIdentity>) {
    let founder = identity(1);
    let mut chain = vec![genesis(&founder)];
    let mut members = Vec::new();
    for i in 0..voters {
        let member = identity(10 + i as u8);
        append(&mut chain, &founder, at(10 + i as i64), add_to(EVERYONE, &member));
        members.push(member);
    }
    (chain, members)
}

fn proposal_for(chain: &[LogEntry], quorum: u32) -> VoteProposal {
    let state = GovernanceState::replay(chain).unwrap();
    VoteProposal::open(
        hash_bytes(b"admit-newcomer"),
        GroupId::everyone(),
        &state,
        chain.last().unwrap().hash(),
        at(72_000),
        quorum,
    )
    .unwrap()
}

#[test]
fn a_certificate_meeting_quorum_passes() {
    let (chain, voters) = electorate_fixture(5);
    let proposal = proposal_for(&chain, 3);
    let vote_id = proposal.vote_id();

    let ballots: Vec<Ballot> = voters
        .iter()
        .take(3)
        .map(|voter| Ballot::cast(voter, vote_id, true, at(1_000)))
        .collect();

    let certificate = QuorumCertificate::assemble(&proposal, ballots);
    assert_eq!(certificate.verify(&proposal).unwrap(), VoteOutcome::Passed);
}

#[test]
fn a_certificate_below_quorum_fails_without_being_malformed() {
    let (chain, voters) = electorate_fixture(5);
    let proposal = proposal_for(&chain, 4);
    let vote_id = proposal.vote_id();

    let ballots: Vec<Ballot> = voters
        .iter()
        .take(2)
        .map(|voter| Ballot::cast(voter, vote_id, true, at(1_000)))
        .collect();

    let certificate = QuorumCertificate::assemble(&proposal, ballots);
    assert_eq!(certificate.verify(&proposal).unwrap(), VoteOutcome::Failed);
}

#[test]
fn a_certificate_assembled_long_after_close_is_still_valid() {
    // The regression test for the assembly-time-vs-ballot-timestamp ambiguity:
    // only the referenced ballots' own timestamps matter, never when the
    // certificate happened to be put together or observed.
    let (chain, voters) = electorate_fixture(5);
    let proposal = proposal_for(&chain, 3);
    let vote_id = proposal.vote_id();

    let ballots: Vec<Ballot> = voters
        .iter()
        .take(3)
        .map(|voter| Ballot::cast(voter, vote_id, true, at(71_999)))
        .collect();

    // Assembled a week after close.
    let certificate = QuorumCertificate::assemble(&proposal, ballots);
    assert_eq!(
        certificate.verify(&proposal).unwrap(),
        VoteOutcome::Passed,
        "certificate assembly time must not affect validity"
    );
}

#[test]
fn ballots_cast_after_close_are_refused() {
    let (chain, voters) = electorate_fixture(5);
    let proposal = proposal_for(&chain, 1);
    let vote_id = proposal.vote_id();

    let late = Ballot::cast(&voters[0], vote_id, true, at(72_001));
    let certificate = QuorumCertificate::assemble(&proposal, [late]);

    assert!(matches!(
        certificate.verify(&proposal),
        Err(GovernanceError::InvalidQuorumCertificate { .. })
    ));
}

#[test]
fn clock_skew_near_the_boundary_does_not_change_the_outcome_across_nodes() {
    // Nodes with skewed clocks observe different things, but the outcome is
    // defined by certificate contents, so every node checking the same
    // certificate reaches the same answer.
    let (chain, voters) = electorate_fixture(5);
    let proposal = proposal_for(&chain, 3);
    let vote_id = proposal.vote_id();

    let ballots: Vec<Ballot> = voters
        .iter()
        .take(3)
        .enumerate()
        .map(|(i, voter)| Ballot::cast(voter, vote_id, true, at(72_000 - i as i64)))
        .collect();

    let certificate = QuorumCertificate::assemble(&proposal, ballots);

    // Three "nodes" evaluating at wildly different local times.
    for local_now in [at(0), at(72_000), at(999_999)] {
        let _ = local_now;
        assert_eq!(certificate.verify(&proposal).unwrap(), VoteOutcome::Passed);
    }
}

#[test]
fn a_non_elector_cannot_be_counted() {
    let (chain, _) = electorate_fixture(5);
    let proposal = proposal_for(&chain, 1);
    let outsider = identity(200);

    let ballot = Ballot::cast(&outsider, proposal.vote_id(), true, at(1_000));
    let certificate = QuorumCertificate::assemble(&proposal, [ballot]);

    assert!(matches!(
        certificate.verify(&proposal),
        Err(GovernanceError::InvalidQuorumCertificate { .. })
    ));
}

#[test]
fn the_electorate_is_frozen_against_mid_vote_additions() {
    let (chain, _) = electorate_fixture(3);
    let proposal = proposal_for(&chain, 1);

    // Someone joins after the snapshot.
    let founder = identity(1);
    let latecomer = identity(99);
    let mut extended = chain;
    append(&mut extended, &founder, at(5_000), add_to(EVERYONE, &latecomer));
    let state = GovernanceState::replay(&extended).unwrap();
    assert!(state.groups[&GroupId::everyone()].contains(&latecomer.id()));

    let ballot = Ballot::cast(&latecomer, proposal.vote_id(), true, at(6_000));
    let certificate = QuorumCertificate::assemble(&proposal, [ballot]);

    assert!(
        matches!(
            certificate.verify(&proposal),
            Err(GovernanceError::InvalidQuorumCertificate { .. })
        ),
        "nobody may be added to the electorate mid-vote to influence the outcome"
    );
}

#[test]
fn double_voting_is_collapsed_to_one_ballot() {
    let (chain, voters) = electorate_fixture(5);
    let proposal = proposal_for(&chain, 2);
    let vote_id = proposal.vote_id();

    let ballots = vec![
        Ballot::cast(&voters[0], vote_id, true, at(1_000)),
        Ballot::cast(&voters[0], vote_id, true, at(2_000)),
        Ballot::cast(&voters[0], vote_id, true, at(3_000)),
    ];

    let certificate = QuorumCertificate::assemble(&proposal, ballots);
    assert_eq!(certificate.ballots.len(), 1);
    assert_eq!(
        certificate.verify(&proposal).unwrap(),
        VoteOutcome::Failed,
        "one voter cannot reach a quorum of two by voting repeatedly"
    );
}

#[test]
fn an_empty_certificate_is_rejected_so_absence_means_failure() {
    let (chain, _) = electorate_fixture(3);
    let proposal = proposal_for(&chain, 1);
    let certificate = QuorumCertificate::assemble(&proposal, []);

    assert!(
        matches!(
            certificate.verify(&proposal),
            Err(GovernanceError::InvalidQuorumCertificate { .. })
        ),
        "no valid certificate means the vote failed, fail-closed"
    );
}

#[test]
fn a_certificate_cannot_be_replayed_against_a_different_proposal() {
    let (chain, voters) = electorate_fixture(5);
    let strict = proposal_for(&chain, 4);
    let lenient = proposal_for(&chain, 1);

    let ballots: Vec<Ballot> = voters
        .iter()
        .take(2)
        .map(|voter| Ballot::cast(voter, strict.vote_id(), true, at(1_000)))
        .collect();
    let certificate = QuorumCertificate::assemble(&strict, ballots);

    assert!(
        matches!(
            certificate.verify(&lenient),
            Err(GovernanceError::InvalidQuorumCertificate { .. })
        ),
        "ballots bind to the exact quorum and electorate they were cast under"
    );
}

#[test]
fn tampering_with_a_certificates_ballots_breaks_the_merkle_root() {
    let (chain, voters) = electorate_fixture(5);
    let proposal = proposal_for(&chain, 1);
    let vote_id = proposal.vote_id();

    let mut certificate = QuorumCertificate::assemble(
        &proposal,
        [Ballot::cast(&voters[0], vote_id, true, at(1_000))],
    );
    certificate
        .ballots
        .push(Ballot::cast(&voters[1], vote_id, true, at(1_000)));

    assert!(matches!(
        certificate.verify(&proposal),
        Err(GovernanceError::InvalidQuorumCertificate { .. })
    ));
}

#[test]
fn certificates_assembled_independently_are_byte_identical() {
    let (chain, voters) = electorate_fixture(5);
    let proposal = proposal_for(&chain, 3);
    let vote_id = proposal.vote_id();

    let ballots: Vec<Ballot> = voters
        .iter()
        .take(3)
        .map(|voter| Ballot::cast(voter, vote_id, true, at(1_000)))
        .collect();

    let mut reversed = ballots.clone();
    reversed.reverse();

    assert_eq!(
        QuorumCertificate::assemble(&proposal, ballots),
        QuorumCertificate::assemble(&proposal, reversed),
        "two nodes assembling from the same ballots must produce the same certificate"
    );
}

// ---------------------------------------------------------------------------
// Content-type policy (§2.8)
// ---------------------------------------------------------------------------

#[test]
fn the_content_type_allowlist_is_governance_controlled() {
    let founder = identity(1);
    let mut chain = vec![genesis(&founder)];

    let state = GovernanceState::replay(&chain).unwrap();
    assert!(state.allows_content_type(&ContentType::new("app-bundle")));

    let mut chat_only: BTreeSet<ContentType> = starter_content_types();
    chat_only.remove(&ContentType::new("app-bundle"));
    append(
        &mut chain,
        &founder,
        at(10),
        EntryBody::ContentTypePolicy {
            allowlist: chat_only,
        },
    );

    let state = GovernanceState::replay(&chain).unwrap();
    assert!(
        !state.allows_content_type(&ContentType::new("app-bundle")),
        "a network must be able to scope itself away from app hosting entirely"
    );
    assert!(state.allows_content_type(&ContentType::new("text")));
}

#[test]
fn allowlisting_a_type_does_not_grant_permission_to_publish_it() {
    // The two gates are independent: a network can allow `app-bundle` while
    // keeping publish rights to a small maintainers group.
    let founder = identity(1);
    let member = identity(2);
    let mut chain = vec![genesis(&founder)];
    append(&mut chain, &founder, at(10), add_to(EVERYONE, &member));

    let state = GovernanceState::replay(&chain).unwrap();
    assert!(state.allows_content_type(&ContentType::new("app-bundle")));
    assert!(
        !state.identity_holds(&member.id(), &Capability::publish("app-bundle")),
        "an allowlisted type must not be publishable by default"
    );
}

#[test]
fn only_define_content_policy_holders_may_change_the_allowlist() {
    let founder = identity(1);
    let member = identity(2);
    let mut chain = vec![genesis(&founder)];
    append(&mut chain, &founder, at(10), add_to(EVERYONE, &member));
    append(
        &mut chain,
        &member,
        at(20),
        EntryBody::ContentTypePolicy {
            allowlist: starter_content_types(),
        },
    );

    assert!(matches!(
        GovernanceState::replay(&chain),
        Err(GovernanceError::Unauthorized {
            capability: Capability::DefineContentPolicy,
            ..
        })
    ));
}

// ---------------------------------------------------------------------------
// Epoch rotation (§3.3, §1.3)
// ---------------------------------------------------------------------------

#[test]
fn a_revocation_driven_rotation_requires_revoke_node() {
    let founder = identity(1);
    let member = identity(2);
    let mut chain = vec![genesis(&founder)];
    append(&mut chain, &founder, at(10), add_to(EVERYONE, &member));
    append(
        &mut chain,
        &member,
        at(20),
        EntryBody::EpochRotation {
            reason: RotationReason::MemberRevoked,
            commit: Vec::new(),
        },
    );

    assert!(matches!(
        GovernanceState::replay(&chain),
        Err(GovernanceError::Unauthorized {
            capability: Capability::RevokeNode,
            ..
        })
    ));
}

#[test]
fn any_member_may_request_a_self_initiated_rekey() {
    // §1.3, point 6: gating this behind approval would discourage reporting a
    // device compromise, which is the wrong incentive to create.
    let founder = identity(1);
    let member = identity(2);
    let mut chain = vec![genesis(&founder)];
    append(&mut chain, &founder, at(10), add_to(EVERYONE, &member));
    append(
        &mut chain,
        &member,
        at(20),
        EntryBody::EpochRotation {
            reason: RotationReason::SelfInitiated,
            commit: Vec::new(),
        },
    );

    let state = GovernanceState::replay(&chain).unwrap();
    assert_eq!(state.epoch, 1);
    assert!(state.epoch_rotation_ref.is_some());
}

#[test]
fn a_non_member_may_not_request_a_rekey() {
    let founder = identity(1);
    let mut chain = vec![genesis(&founder)];
    append(
        &mut chain,
        &identity(2),
        at(20),
        EntryBody::EpochRotation {
            reason: RotationReason::SelfInitiated,
            commit: Vec::new(),
        },
    );

    assert!(matches!(
        GovernanceState::replay(&chain),
        Err(GovernanceError::NotAMember { .. })
    ));
}

#[test]
fn rotation_ref_tracks_the_entry_hash_not_a_bare_counter() {
    // Storage Spec §5.3: two competing branches can each legitimately produce
    // "the next epoch" with the same ordinal, so wrappings must reference the
    // entry hash to disambiguate which rotation they belong to.
    let founder = identity(1);
    let mut chain = vec![genesis(&founder)];
    append(
        &mut chain,
        &founder,
        at(10),
        EntryBody::EpochRotation {
            reason: RotationReason::MemberRevoked,
            commit: Vec::new(),
        },
    );

    let state = GovernanceState::replay(&chain).unwrap();
    assert_eq!(state.epoch_rotation_ref, Some(chain.last().unwrap().hash()));
}

// ---------------------------------------------------------------------------
// Sync queries (§2.7, §5.1)
// ---------------------------------------------------------------------------

#[test]
fn heads_reports_every_branch_tip_not_just_the_canonical_one() {
    // A sync that offered only the canonical tip would be useless during exactly
    // the situation it exists for: while partitioned, the entries the other side
    // needs are on a branch this node does not consider canonical, so offering
    // only the canonical tip would never hand it over and the two sides would
    // never reconcile.
    let founder = identity(1);
    let mut log = GovernanceLog::new();
    let root = log.insert(genesis(&founder)).unwrap();

    let left = LogEntry::create(
        &founder,
        Some(root),
        Timestamp::from_millis(10),
        define_group("left", [Capability::ReadContent]),
    );
    let right = LogEntry::create(
        &founder,
        Some(root),
        Timestamp::from_millis(11),
        define_group("right", [Capability::ReadContent]),
    );
    let left_hash = log.insert(left).unwrap();
    let right_hash = log.insert(right).unwrap();

    let heads = log.heads();
    assert_eq!(heads.len(), 2, "both branch tips should be offered");
    assert!(heads.contains(&left_hash) && heads.contains(&right_hash));
    assert!(
        !heads.contains(&root),
        "an entry with children is not a tip"
    );
}

#[test]
fn ancestors_first_orders_parents_before_children() {
    // The ordering `GovernanceLog::insert` requires. A receiver handed a child
    // before its parent drops the child, and a dropped entry is indistinguishable
    // from one that was never sent — so this ordering is the difference between
    // a sync that converges and one that silently stalls.
    let founder = identity(1);
    let mut log = GovernanceLog::new();
    let mut parent = log.insert(genesis(&founder)).unwrap();
    for i in 0..6 {
        let entry = LogEntry::create(
            &founder,
            Some(parent),
            Timestamp::from_millis(10 + i),
            define_group(&format!("g{i}"), [Capability::ReadContent]),
        );
        parent = log.insert(entry).unwrap();
    }

    let (entries, truncated) = log.ancestors_first(&[parent], &[], 100);
    assert!(!truncated);
    assert_eq!(entries.len(), 7);

    // Replaying into an empty log is the real test of the order: `insert` is
    // what enforces it, so a wrongly ordered response fails here rather than
    // merely looking odd.
    let mut fresh = GovernanceLog::new();
    for entry in entries {
        fresh.insert(entry).expect("entries must arrive insertable");
    }
    assert_eq!(fresh.len(), 7);
}

#[test]
fn ancestors_first_skips_what_the_requester_already_holds() {
    // Without this, every partition heal would re-send the entire log. It is an
    // optimization rather than a correctness property — re-inserting a known
    // entry is idempotent — which is exactly why it needs its own test: if it
    // silently stopped trimming, nothing else would fail.
    let founder = identity(1);
    let mut log = GovernanceLog::new();
    let mut parent = log.insert(genesis(&founder)).unwrap();
    let mut midpoint = parent;
    for i in 0..6 {
        let entry = LogEntry::create(
            &founder,
            Some(parent),
            Timestamp::from_millis(10 + i),
            define_group(&format!("g{i}"), [Capability::ReadContent]),
        );
        parent = log.insert(entry).unwrap();
        if i == 2 {
            midpoint = parent;
        }
    }

    let (all, _) = log.ancestors_first(&[parent], &[], 100);
    let (trimmed, _) = log.ancestors_first(&[parent], &[midpoint], 100);

    assert_eq!(all.len(), 7);
    assert_eq!(
        trimmed.len(),
        3,
        "everything up to and including the requester's tip should be skipped"
    );
    assert!(
        trimmed.iter().all(|entry| entry.timestamp.as_millis() > 12),
        "the trimmed entries should be the ones after the requester's tip"
    );
}

#[test]
fn a_truncated_response_is_still_a_valid_prefix() {
    // Truncation must leave the receiver better off, not merely leave it with
    // fewer entries: a depth-ordered prefix is insertable, so a capped response
    // advances the log and the requester asks again. A response truncated in
    // some other order would be entirely wasted.
    let founder = identity(1);
    let mut log = GovernanceLog::new();
    let mut parent = log.insert(genesis(&founder)).unwrap();
    for i in 0..9 {
        let entry = LogEntry::create(
            &founder,
            Some(parent),
            Timestamp::from_millis(10 + i),
            define_group(&format!("g{i}"), [Capability::ReadContent]),
        );
        parent = log.insert(entry).unwrap();
    }

    let (entries, truncated) = log.ancestors_first(&[parent], &[], 4);
    assert!(truncated, "a cap of 4 against 10 entries should truncate");
    assert_eq!(entries.len(), 4);

    let mut fresh = GovernanceLog::new();
    for entry in entries {
        fresh
            .insert(entry)
            .expect("a truncated response must still be insertable in order");
    }
    assert_eq!(fresh.len(), 4);
}

// ---------------------------------------------------------------------------
// App-layer policy — Chat Application Spec §7 (E9)
// ---------------------------------------------------------------------------

/// A policy carrying values the protocol does not interpret.
fn policy_with_app_values() -> NetworkPolicy {
    let mut policy = NetworkPolicy::conservative_default();
    policy.app_policy.extend([
        ("chat:message-rate-per-minute".to_owned(), PolicyValue::Int(30)),
        ("chat:network-profile".to_owned(), PolicyValue::Text("conversation".to_owned())),
        ("chat:vod-retention".to_owned(), PolicyValue::Flag(true)),
    ]);
    policy
}

#[test]
fn app_policy_values_survive_a_round_trip() {
    let founder = identity(1);
    let entry = LogEntry::create(
        &founder,
        None,
        at(0),
        EntryBody::Genesis {
            network: NETWORK,
            policy: policy_with_app_values(),
            everyone_capabilities: BTreeSet::new(),
        },
    );

    let decoded = decode_entry(&encode_entry(&entry)).expect("decodes");
    assert_eq!(decoded, entry);

    let EntryBody::Genesis { policy, .. } = &decoded.body else {
        panic!("genesis");
    };
    assert_eq!(policy.app_policy_int("chat:message-rate-per-minute", 0), 30);
    assert_eq!(
        policy.app_policy_text("chat:network-profile", "server"),
        "conversation"
    );
}

#[test]
fn an_unknown_app_policy_key_round_trips_unchanged() {
    // The property that lets a network run a newer client beside an older one:
    // a key this build has never heard of must survive, not be dropped.
    let mut policy = NetworkPolicy::conservative_default();
    policy.app_policy.insert(
        "somefutureapp:setting-nobody-here-knows".to_owned(),
        PolicyValue::Int(7),
    );
    let founder = identity(1);
    let entry = LogEntry::create(
        &founder,
        None,
        at(0),
        EntryBody::Genesis {
            network: NETWORK,
            policy,
            everyone_capabilities: BTreeSet::new(),
        },
    );

    let decoded = decode_entry(&encode_entry(&entry)).expect("decodes");
    let EntryBody::Genesis { policy, .. } = &decoded.body else {
        panic!("genesis");
    };
    assert_eq!(
        policy.app_policy("somefutureapp:setting-nobody-here-knows"),
        Some(&PolicyValue::Int(7))
    );
}

#[test]
fn app_policy_encoding_is_order_independent() {
    // Two nodes building the same logical policy must produce identical bytes,
    // or their genesis entries hash differently and the network forks at birth.
    let mut one = NetworkPolicy::conservative_default();
    let mut other = NetworkPolicy::conservative_default();
    for (key, value) in [
        ("chat:a", PolicyValue::Int(1)),
        ("chat:b", PolicyValue::Text("two".to_owned())),
        ("chat:c", PolicyValue::Flag(false)),
    ] {
        one.app_policy.insert(key.to_owned(), value);
    }
    for (key, value) in [
        ("chat:c", PolicyValue::Flag(false)),
        ("chat:a", PolicyValue::Int(1)),
        ("chat:b", PolicyValue::Text("two".to_owned())),
    ] {
        other.app_policy.insert(key.to_owned(), value);
    }

    let mut a = intranet_crypto::Enc::new();
    one.encode(&mut a);
    let mut b = intranet_crypto::Enc::new();
    other.encode(&mut b);
    assert_eq!(a.finish(), b.finish());
}

#[test]
fn an_unnamespaced_app_policy_key_is_refused_on_the_wire() {
    let mut policy = NetworkPolicy::conservative_default();
    policy
        .app_policy
        .insert("nonamespace".to_owned(), PolicyValue::Int(1));
    let founder = identity(1);
    let entry = LogEntry::create(
        &founder,
        None,
        at(0),
        EntryBody::Genesis {
            network: NETWORK,
            policy,
            everyone_capabilities: BTreeSet::new(),
        },
    );

    // Namespacing keeps two applications on one network from colliding, so a
    // key without one is refused rather than admitted to a namespace it lacks.
    assert!(matches!(
        decode_entry(&encode_entry(&entry)),
        Err(WireError::UnnamespacedPolicyKey { .. })
    ));
}

#[test]
fn app_policy_is_part_of_the_entry_hash() {
    // It must be: policy is what a PolicyChange entry carries, and a change
    // that did not alter the hash would be a change no node could detect.
    let founder = identity(1);
    let base = LogEntry::create(
        &founder,
        None,
        at(0),
        EntryBody::Genesis {
            network: NETWORK,
            policy: NetworkPolicy::conservative_default(),
            everyone_capabilities: BTreeSet::new(),
        },
    );
    let with_values = LogEntry::create(
        &founder,
        None,
        at(0),
        EntryBody::Genesis {
            network: NETWORK,
            policy: policy_with_app_values(),
            everyone_capabilities: BTreeSet::new(),
        },
    );
    assert_ne!(base.hash(), with_values.hash());
}

#[test]
fn changing_app_policy_requires_define_policy() {
    // No new capability: app-layer settings ride the existing gate, so a
    // consuming spec gets governance for free rather than inventing its own.
    let founder = identity(1);
    let member = identity(2);
    let mut chain = vec![LogEntry::create(
        &founder,
        None,
        at(0),
        EntryBody::Genesis {
            network: NETWORK,
            policy: NetworkPolicy::conservative_default(),
            everyone_capabilities: [Capability::ReadContent].into_iter().collect(),
        },
    )];
    let parent = chain[0].hash();
    chain.push(LogEntry::create(
        &founder,
        Some(parent),
        at(5),
        EntryBody::MembershipChange {
            group: GroupId::everyone(),
            identity: member.id(),
            action: MembershipAction::Add { via_invite: None },
        },
    ));

    let parent = chain.last().unwrap().hash();
    let by_member = LogEntry::create(
        &member,
        Some(parent),
        at(10),
        EntryBody::PolicyChange {
            policy: policy_with_app_values(),
        },
    );
    let mut attempted = chain.clone();
    attempted.push(by_member);
    assert!(
        GovernanceState::replay(&attempted).is_err(),
        "an ordinary member must not be able to change app policy"
    );

    let by_founder = LogEntry::create(
        &founder,
        Some(parent),
        at(10),
        EntryBody::PolicyChange {
            policy: policy_with_app_values(),
        },
    );
    chain.push(by_founder);
    let state = GovernanceState::replay(&chain).expect("a founder may");
    assert_eq!(state.policy.app_policy_int("chat:message-rate-per-minute", 0), 30);
}

// ---------------------------------------------------------------------------
// App-layer entries — Chat Application Spec §7 (E2)
// ---------------------------------------------------------------------------

fn app_entry(required: Capability, payload: &[u8]) -> EntryBody {
    EntryBody::AppEntry {
        namespace: "chat".to_owned(),
        kind: "channel-definition".to_owned(),
        required,
        payload: payload.to_vec(),
    }
}

/// A network where `everyone` may post but only Founders may manage channels.
fn app_entry_chain(founder: &PerNetworkIdentity, member: &PerNetworkIdentity) -> Vec<LogEntry> {
    let mut policy = NetworkPolicy::conservative_default();
    policy.extension_capabilities.extend([
        ("chat:post:*".to_owned(), Tier::Ordinary),
        ("chat:manage-channel:*".to_owned(), Tier::Governance),
    ]);

    let mut chain = vec![LogEntry::create(
        &founder.clone(),
        None,
        at(0),
        EntryBody::Genesis {
            network: NETWORK,
            policy,
            everyone_capabilities: [Capability::extension("chat:post:*")]
                .into_iter()
                .collect(),
        },
    )];
    let parent = chain[0].hash();
    chain.push(LogEntry::create(
        founder,
        Some(parent),
        at(5),
        EntryBody::MembershipChange {
            group: GroupId::everyone(),
            identity: member.id(),
            action: MembershipAction::Add { via_invite: None },
        },
    ));
    chain
}

#[test]
fn an_app_entry_requires_the_capability_it_declares() {
    let founder = identity(1);
    let member = identity(2);
    let mut chain = app_entry_chain(&founder, &member);
    let parent = chain.last().unwrap().hash();

    // The member holds chat:post:* but not chat:manage-channel:*.
    let refused = LogEntry::create(
        &member,
        Some(parent),
        at(10),
        app_entry(Capability::extension("chat:manage-channel:*"), b"payload"),
    );
    let mut attempted = chain.clone();
    attempted.push(refused);
    assert!(
        GovernanceState::replay(&attempted).is_err(),
        "an app entry must be refused when its author lacks the declared capability"
    );

    // A Founder holds everything.
    chain.push(LogEntry::create(
        &founder,
        Some(parent),
        at(10),
        app_entry(Capability::extension("chat:manage-channel:*"), b"payload"),
    ));
    assert!(GovernanceState::replay(&chain).is_ok());
}

#[test]
fn the_protocol_does_not_interpret_an_app_payload() {
    // Arbitrary bytes, including ones that are not valid UTF-8 and would not
    // decode as anything this crate knows.
    let founder = identity(1);
    let member = identity(2);
    let mut chain = app_entry_chain(&founder, &member);
    let parent = chain.last().unwrap().hash();
    chain.push(LogEntry::create(
        &founder,
        Some(parent),
        at(10),
        app_entry(Capability::extension("chat:manage-channel:*"), &[0xFF, 0x00, 0xFE]),
    ));

    let state = GovernanceState::replay(&chain).expect("replays");
    // Replay authorized it and changed nothing else: the payload is a consuming
    // spec's business, and this crate keeps no state derived from it.
    assert!(state.is_member(&member.id()));
}

#[test]
fn an_app_entry_does_not_count_toward_branch_length() {
    // The grinding property. If app entries counted, an attacker holding any
    // broadly-granted capability could mint a long branch during a partition
    // and void an unfavourable revocation — which is exactly what §2.7.1
    // point 2's metric exists to prevent.
    let body = app_entry(Capability::extension("chat:post:*"), b"x");
    assert!(!body.is_capability_gated());

    // Contrast: the core actions that must survive a partition still count.
    assert!(
        EntryBody::MembershipChange {
            group: GroupId::everyone(),
            identity: identity(2).id(),
            action: MembershipAction::Remove { cascade: None },
        }
        .is_capability_gated()
    );
}

#[test]
fn app_entries_round_trip_on_the_wire() {
    let founder = identity(1);
    let entry = LogEntry::create(
        &founder,
        None,
        at(0),
        app_entry(Capability::extension("chat:manage-channel:*"), b"opaque bytes"),
    );
    let decoded = decode_entry(&encode_entry(&entry)).expect("decodes");
    assert_eq!(decoded, entry);
}

#[test]
fn a_malformed_app_entry_name_is_refused_on_the_wire() {
    let founder = identity(1);
    for (namespace, kind) in [("", "k"), ("chat", ""), ("has:colon", "k")] {
        let entry = LogEntry::create(
            &founder,
            None,
            at(0),
            EntryBody::AppEntry {
                namespace: namespace.to_owned(),
                kind: kind.to_owned(),
                required: Capability::ReadContent,
                payload: Vec::new(),
            },
        );
        assert!(
            matches!(
                decode_entry(&encode_entry(&entry)),
                Err(WireError::MalformedAppEntry { .. })
            ),
            "{namespace:?}/{kind:?} should be refused"
        );
    }
}

#[test]
fn an_oversized_app_payload_is_refused_on_the_wire() {
    // The log is replayed in full by every joiner and never shrinks, so one
    // application must not be able to make a network permanently expensive to
    // join. Content belongs in storage behind a CID; this carries structure.
    let founder = identity(1);
    let entry = LogEntry::create(
        &founder,
        None,
        at(0),
        app_entry(
            Capability::ReadContent,
            &vec![0u8; MAX_APP_ENTRY_PAYLOAD_BYTES + 1],
        ),
    );
    assert!(matches!(
        decode_entry(&encode_entry(&entry)),
        Err(WireError::AppPayloadTooLarge { .. })
    ));
}

/// Every entry body must round-trip, which is also what catches a discriminant
/// collision between the two encodings.
///
/// There are two of them — the signing/hashing encoding in `entry.rs` and the
/// wire encoding in `wire.rs` — and they number their variants independently.
/// Adding a variant means picking a free number in each, and picking a taken
/// one produced exactly one symptom during E2: a decode that read a `str` where
/// a payload was, and reported an implausible length.
///
/// The wire collision is merely a bug. The *signing* collision is worse: two
/// different bodies sharing a discriminant weakens the domain separation that
/// keeps one signed action from being reinterpreted as another. This test fails
/// on either.
#[test]
fn every_entry_body_round_trips() {
    let founder = identity(1);
    let member = identity(2);

    let bodies = vec![
        EntryBody::Genesis {
            network: NETWORK,
            policy: NetworkPolicy::conservative_default(),
            everyone_capabilities: BTreeSet::new(),
        },
        EntryBody::DefineGroup {
            group: GroupId::new("moderators"),
            capabilities: CapabilitySet::explicit([Capability::ModerateContent]),
        },
        EntryBody::MembershipChange {
            group: GroupId::everyone(),
            identity: member.id(),
            action: MembershipAction::Add { via_invite: None },
        },
        EntryBody::PolicyChange {
            policy: NetworkPolicy::conservative_default(),
        },
        EntryBody::ContentTypePolicy {
            allowlist: [ContentType::new("text")].into_iter().collect(),
        },
        EntryBody::Moderation(ModerationEntry {
            action: ModerationAction::Delist,
            target_pointer_id: PointerId::from_bytes([3u8; 32]),
        }),
        EntryBody::AppNameRegistration {
            name: AppName::new("wiki"),
            app_id: PointerId::from_bytes([4u8; 32]),
        },
        EntryBody::AppEntry {
            namespace: "chat".to_owned(),
            kind: "channel-definition".to_owned(),
            required: Capability::extension("chat:manage-channel:*"),
            payload: b"opaque".to_vec(),
        },
    ];

    let mut action_hashes = BTreeSet::new();
    for body in bodies {
        let entry = LogEntry::create(&founder, None, at(0), body.clone());
        let decoded = decode_entry(&encode_entry(&entry))
            .unwrap_or_else(|err| panic!("{} did not decode: {err}", body.kind()));
        assert_eq!(decoded, entry, "{} did not round-trip", body.kind());

        // Distinct bodies must hash distinctly under the signing encoding, which
        // a shared discriminant would undermine.
        assert!(
            action_hashes.insert(body.action_hash()),
            "{} shares an action hash with another body",
            body.kind()
        );
    }
}
