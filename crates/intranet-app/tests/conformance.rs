//! App hosting conformance tests — App Hosting Spec §2, §3.5, §4.3–4.4, Harness §5.

use intranet_crypto::{Hash, Timestamp};
use intranet_app::{
    AppManifest, DirectoryListing, PendingPublish, PublishingPolicy, RequestedCapability,
    ReviewQueue, browse, directory_collection, is_available, name_registration_entry,
    register_capabilities, resolve, supports_app_hosting,
};
use intranet_governance::{
    APPROVE_APP_PUBLISH, AppName, Capability, CapabilitySet, EVERYONE, EntryBody, GovernanceError,
    GovernanceState, GroupId, LogEntry, MembershipAction, ModerationAction, ModerationEntry,
    NetworkPolicy, PointerId, RECLAIM_APP_NAME, REGISTER_APP_NAME, starter_content_types,
};
use intranet_identity::{MasterSeed, NetworkId, PerNetworkIdentity};
use intranet_storage::AppendSetView;

const NETWORK: NetworkId = NetworkId::from_bytes([42u8; 32]);

fn identity(n: u8) -> PerNetworkIdentity {
    MasterSeed::from_entropy([n; 32]).identity_for(&NETWORK).unwrap()
}

fn at(millis: i64) -> Timestamp {
    Timestamp::from_millis(millis)
}

fn app(n: u8) -> PointerId {
    PointerId::from_bytes([n; 32])
}

fn push(chain: &mut Vec<LogEntry>, author: &PerNetworkIdentity, time: i64, body: EntryBody) {
    let parent = chain.last().unwrap().hash();
    chain.push(LogEntry::create(author, Some(parent), at(time), body));
}

/// A network configured for app hosting, with `members` admitted to `everyone`.
///
/// `everyone` holds `register-app-name` — the broad, open-sandbox posture that
/// makes the hijack tests meaningful.
fn app_network(members: &[&PerNetworkIdentity]) -> Vec<LogEntry> {
    let founder = identity(1);
    let mut policy = NetworkPolicy::conservative_default();
    register_capabilities(&mut policy);

    let mut chain = vec![LogEntry::create(
        &founder,
        None,
        at(0),
        EntryBody::Genesis {
            network: NETWORK,
            policy,
            everyone_capabilities: [
                Capability::ReadContent,
                Capability::publish("app-bundle"),
                Capability::extension(REGISTER_APP_NAME),
            ]
            .into_iter()
            .collect(),
        },
    )];
    for (i, member) in members.iter().enumerate() {
        push(
            &mut chain,
            &founder,
            10 + i as i64,
            EntryBody::MembershipChange {
                group: GroupId::everyone(),
                identity: member.id(),
                action: MembershipAction::Add { via_invite: None },
            },
        );
    }
    chain
}

fn state_of(chain: &[LogEntry]) -> GovernanceState {
    GovernanceState::replay(chain).unwrap()
}

/// Appends a name registration by `registrant`.
fn register(
    chain: &mut Vec<LogEntry>,
    registrant: &PerNetworkIdentity,
    time: i64,
    name: &str,
    app_id: PointerId,
) {
    let parent = chain.last().unwrap().hash();
    chain.push(name_registration_entry(
        registrant,
        parent,
        at(time),
        AppName::new(name),
        app_id,
    ));
}

// ---------------------------------------------------------------------------
// Network configuration (§2.1)
// ---------------------------------------------------------------------------

#[test]
fn a_configured_network_supports_app_hosting() {
    let state = state_of(&app_network(&[]));
    assert!(supports_app_hosting(&state).is_ok());
}

#[test]
fn a_network_excluding_app_bundle_cannot_host_apps() {
    // The mechanism for scoping a network away from app hosting entirely: no
    // capability configuration can reopen it.
    let founder = identity(1);
    let mut chain = app_network(&[]);
    let mut chat_only = starter_content_types();
    chat_only.remove(&intranet_governance::ContentType::new("app-bundle"));
    push(
        &mut chain,
        &founder,
        50,
        EntryBody::ContentTypePolicy {
            allowlist: chat_only,
        },
    );

    assert!(supports_app_hosting(&state_of(&chain)).is_err());
}

#[test]
fn a_network_that_never_registered_the_capabilities_cannot_host_apps() {
    // An unregistered extension capability has no resolvable tier, so it is
    // refused rather than assumed harmless.
    let founder = identity(1);
    let chain = vec![LogEntry::create(
        &founder,
        None,
        at(0),
        EntryBody::Genesis {
            network: NETWORK,
            policy: NetworkPolicy::conservative_default(),
            everyone_capabilities: [Capability::ReadContent].into_iter().collect(),
        },
    )];
    assert!(supports_app_hosting(&state_of(&chain)).is_err());
}

#[test]
fn registering_capabilities_assigns_the_split_tiers() {
    let mut policy = NetworkPolicy::conservative_default();
    register_capabilities(&mut policy);

    use intranet_governance::Tier;
    assert_eq!(policy.extension_tier(REGISTER_APP_NAME), Some(Tier::Ordinary));
    assert_eq!(policy.extension_tier(RECLAIM_APP_NAME), Some(Tier::Governance));
    assert_eq!(
        policy.extension_tier(APPROVE_APP_PUBLISH),
        Some(Tier::Governance)
    );
}

#[test]
fn everyone_may_hold_register_but_never_reclaim() {
    // The `everyone` ceiling covering a capability defined by a consuming spec,
    // resolved purely from the tier registry.
    let founder = identity(1);
    let mut chain = app_network(&[]);
    assert!(GovernanceState::replay(&chain).is_ok(), "register is ordinary");

    push(
        &mut chain,
        &founder,
        60,
        EntryBody::DefineGroup {
            group: GroupId::everyone(),
            capabilities: CapabilitySet::explicit([
                Capability::ReadContent,
                Capability::extension(RECLAIM_APP_NAME),
            ]),
        },
    );

    assert!(
        matches!(
            GovernanceState::replay(&chain),
            Err(GovernanceError::EveryoneGovernanceTier { .. })
        ),
        "reclaim is governance-tier and must never reach `everyone`"
    );
}

// ---------------------------------------------------------------------------
// Claiming and resolving (§4.3)
// ---------------------------------------------------------------------------

#[test]
fn an_unclaimed_name_can_be_claimed_and_resolves() {
    let developer = identity(2);
    let mut chain = app_network(&[&developer]);
    assert!(is_available(&AppName::new("wiki"), &state_of(&chain)));

    register(&mut chain, &developer, 100, "wiki", app(7));
    let state = state_of(&chain);

    let resolved = resolve(&AppName::new("wiki"), &state).expect("should resolve");
    assert_eq!(resolved.record.app_id, app(7));
    assert_eq!(resolved.record.owner, developer.id());
    assert!(!resolved.delisted);
    assert!(!is_available(&AppName::new("wiki"), &state));
}

#[test]
fn an_unregistered_name_resolves_to_nothing() {
    let state = state_of(&app_network(&[]));
    assert!(resolve(&AppName::new("never-claimed"), &state).is_none());
}

#[test]
fn the_owner_may_repoint_their_own_name_to_a_new_version() {
    // Repointing a name you already own is a reclaim, so it needs the
    // governance-tier capability. The founder holds everything; an ordinary
    // member repointing their own name is covered by the next test.
    let founder = identity(1);
    let mut chain = app_network(&[]);
    register(&mut chain, &founder, 100, "wiki", app(7));
    register(&mut chain, &founder, 200, "wiki", app(8));

    let state = state_of(&chain);
    assert_eq!(
        resolve(&AppName::new("wiki"), &state).unwrap().record.app_id,
        app(8)
    );
}

#[test]
fn holding_register_does_not_let_you_repoint_a_name_you_own() {
    // A consequence worth pinning: reassignment is governance-tier regardless of
    // who currently holds the name, including yourself. The alternative — making
    // reassignment ordinary when you are the incumbent — would require trusting
    // the claimed incumbency before the capability check, which is exactly the
    // ordering a hijacker would attack.
    let developer = identity(2);
    let mut chain = app_network(&[&developer]);
    register(&mut chain, &developer, 100, "wiki", app(7));
    assert!(GovernanceState::replay(&chain).is_ok());

    register(&mut chain, &developer, 200, "wiki", app(8));
    assert!(matches!(
        GovernanceState::replay(&chain),
        Err(GovernanceError::Unauthorized { .. })
    ));
}

// ---------------------------------------------------------------------------
// The two attacks a review pass identified (§4.3)
// ---------------------------------------------------------------------------

#[test]
fn a_backdated_claim_does_not_gain_priority() {
    // Attack one: with self-attested ordering, a squatter backdates a claim to
    // appear earlier than the genuine registrant. Ordering here comes from the
    // log, so a later entry is later no matter what timestamp it carries.
    let genuine = identity(2);
    let squatter = identity(3);
    let mut chain = app_network(&[&genuine, &squatter]);

    register(&mut chain, &genuine, 5_000, "popular", app(7));

    // The squatter claims the same name with a far earlier timestamp.
    let parent = chain.last().unwrap().hash();
    chain.push(name_registration_entry(
        &squatter,
        parent,
        at(1),
        AppName::new("popular"),
        app(9),
    ));

    assert!(
        matches!(
            GovernanceState::replay(&chain),
            Err(GovernanceError::Unauthorized { .. })
        ),
        "the backdated claim is a reassignment and needs governance-tier authority, \
         regardless of the timestamp it carries"
    );

    // And the genuine registration is untouched.
    chain.pop();
    let state = state_of(&chain);
    assert_eq!(
        resolve(&AppName::new("popular"), &state).unwrap().record.owner,
        genuine.id()
    );
}

#[test]
fn a_registration_does_not_lapse_when_its_discovery_entry_goes_unrefreshed() {
    // Attack two: under TTL-based liveness, a legitimate registrant whose node
    // is merely offline loses their name to a squatter keeping a competing
    // entry announced. Ownership lives in the log, which never expires.
    let genuine = identity(2);
    let squatter = identity(3);
    let mut chain = app_network(&[&genuine, &squatter]);
    register(&mut chain, &genuine, 100, "popular", app(7));

    // The discovery index is emptied entirely — the worst case for a stale index.
    let empty_index = AppendSetView::new(directory_collection(&NETWORK));
    let state = state_of(&chain);
    let (listings, _) = browse(&empty_index, &state);
    assert!(listings.is_empty(), "the index knows nothing");

    // Ownership is unaffected, and the squatter still cannot take the name.
    let resolved = resolve(&AppName::new("popular"), &state).expect("still owned");
    assert_eq!(resolved.record.owner, genuine.id());

    register(&mut chain, &squatter, 9_999_999, "popular", app(9));
    assert!(
        matches!(
            GovernanceState::replay(&chain),
            Err(GovernanceError::Unauthorized { .. })
        ),
        "an absent discovery entry must not make a name reclaimable"
    );
}

#[test]
fn a_broad_grant_of_register_does_not_permit_hijacking() {
    // The specific configuration the split exists for: an open sandbox network
    // where everyone can claim names. Claiming must stay easy; stealing must not
    // come along with it.
    let squatter = identity(3);
    let owner = identity(2);
    let mut chain = app_network(&[&owner, &squatter]);

    let state = state_of(&chain);
    assert!(
        state.identity_holds(&squatter.id(), &Capability::extension(REGISTER_APP_NAME)),
        "everyone really does hold register in this network"
    );
    assert!(!state.identity_holds(&squatter.id(), &Capability::extension(RECLAIM_APP_NAME)));

    register(&mut chain, &owner, 100, "wiki", app(7));
    // The squatter can freely claim a *different* name.
    register(&mut chain, &squatter, 200, "squatters-own", app(9));
    assert!(GovernanceState::replay(&chain).is_ok());

    // But not take the one already held.
    register(&mut chain, &squatter, 300, "wiki", app(9));
    assert!(matches!(
        GovernanceState::replay(&chain),
        Err(GovernanceError::Unauthorized { .. })
    ));
}

#[test]
fn a_reclaim_holder_can_reassign_a_claimed_name() {
    // The legitimate counterpart: someone deliberately granted the
    // governance-tier capability can reassign.
    let owner = identity(2);
    let arbiter = identity(4);
    let founder = identity(1);
    let mut chain = app_network(&[&owner, &arbiter]);

    push(
        &mut chain,
        &founder,
        50,
        EntryBody::DefineGroup {
            group: GroupId::new("registrars"),
            capabilities: CapabilitySet::explicit([
                Capability::extension(REGISTER_APP_NAME),
                Capability::extension(RECLAIM_APP_NAME),
            ]),
        },
    );
    push(
        &mut chain,
        &founder,
        51,
        EntryBody::MembershipChange {
            group: GroupId::new("registrars"),
            identity: arbiter.id(),
            action: MembershipAction::Add { via_invite: None },
        },
    );

    register(&mut chain, &owner, 100, "disputed", app(7));
    register(&mut chain, &arbiter, 200, "disputed", app(9));

    let state = state_of(&chain);
    let resolved = resolve(&AppName::new("disputed"), &state).unwrap();
    assert_eq!(resolved.record.app_id, app(9));
    assert_eq!(resolved.record.owner, arbiter.id());
}

// ---------------------------------------------------------------------------
// The discovery index (§4.4)
// ---------------------------------------------------------------------------

fn listing(name: &str, app_id: PointerId) -> DirectoryListing {
    DirectoryListing {
        name: AppName::new(name),
        app_id,
        title: format!("{name} title"),
        description: format!("{name} description"),
    }
}

#[test]
fn a_listing_round_trips_through_its_payload() {
    let original = listing("wiki", app(7));
    let parsed = intranet_app::registry::parse_listing(&original.to_payload()).unwrap();
    assert_eq!(parsed, original);
}

#[test]
fn a_malformed_or_padded_listing_is_rejected() {
    assert!(intranet_app::registry::parse_listing(b"nonsense").is_none());

    let mut padded = listing("wiki", app(7)).to_payload();
    padded.push(0);
    assert!(
        intranet_app::registry::parse_listing(&padded).is_none(),
        "trailing bytes must not slip past a listing that otherwise looks valid"
    );
}

#[test]
fn browsing_returns_registered_apps() {
    let developer = identity(2);
    let mut chain = app_network(&[&developer]);
    register(&mut chain, &developer, 100, "wiki", app(7));
    register(&mut chain, &developer, 110, "notes", app(8));
    let state = state_of(&chain);

    let mut index = AppendSetView::new(directory_collection(&NETWORK));
    for (name, id) in [("wiki", app(7)), ("notes", app(8))] {
        index
            .insert(listing(name, id).announce(&developer, &NETWORK), &state)
            .unwrap();
    }

    let (listings, truncated) = browse(&index, &state);
    assert_eq!(listings.len(), 2);
    assert!(!truncated);
    // Sorted by name, so browsing is stable.
    assert_eq!(listings[0].0.name.as_str(), "notes");
    assert_eq!(listings[1].0.name.as_str(), "wiki");
}

#[test]
fn an_index_entry_contradicting_the_log_is_discarded() {
    // The index can omit apps, but must never be able to misdirect: a listing
    // pointing somewhere other than the authoritative record is an attempted
    // misdirection and the log settles it.
    let owner = identity(2);
    let liar = identity(3);
    let mut chain = app_network(&[&owner, &liar]);
    register(&mut chain, &owner, 100, "wiki", app(7));
    let state = state_of(&chain);

    let mut index = AppendSetView::new(directory_collection(&NETWORK));
    // A valid, correctly-signed entry from a current member — that simply lies
    // about where the name points.
    index
        .insert(listing("wiki", app(99)).announce(&liar, &NETWORK), &state)
        .unwrap();

    let (listings, _) = browse(&index, &state);
    assert!(
        listings.is_empty(),
        "a listing disagreeing with the log must not be shown"
    );
    assert_eq!(
        resolve(&AppName::new("wiki"), &state).unwrap().record.app_id,
        app(7),
        "and ownership is unaffected"
    );
}

#[test]
fn an_index_entry_for_an_unregistered_name_is_ignored() {
    let developer = identity(2);
    let chain = app_network(&[&developer]);
    let state = state_of(&chain);

    let mut index = AppendSetView::new(directory_collection(&NETWORK));
    index
        .insert(
            listing("never-registered", app(7)).announce(&developer, &NETWORK),
            &state,
        )
        .unwrap();

    assert!(browse(&index, &state).0.is_empty());
}

#[test]
fn delisting_an_app_is_surfaced_without_changing_name_ownership() {
    let developer = identity(2);
    let founder = identity(1);
    let mut chain = app_network(&[&developer]);
    register(&mut chain, &developer, 100, "wiki", app(7));

    push(
        &mut chain,
        &founder,
        200,
        EntryBody::Moderation(ModerationEntry {
            action: ModerationAction::Delist,
            target_pointer_id: app(7),
        }),
    );
    let state = state_of(&chain);

    let resolved = resolve(&AppName::new("wiki"), &state).unwrap();
    assert!(resolved.delisted, "the app is delisted");
    assert_eq!(
        resolved.record.owner,
        developer.id(),
        "but the name is still theirs \u{2014} servability and ownership are separate"
    );
}

#[test]
fn a_delisted_apps_listing_stops_being_honoured_by_the_index() {
    // Inherited from the append-set's three-part validation: the listing
    // references the app's pointer, so delisting invalidates it without anyone
    // withdrawing it.
    let developer = identity(2);
    let founder = identity(1);
    let mut chain = app_network(&[&developer]);
    register(&mut chain, &developer, 100, "wiki", app(7));
    let state = state_of(&chain);

    let mut index = AppendSetView::new(directory_collection(&NETWORK));
    index
        .insert(listing("wiki", app(7)).announce(&developer, &NETWORK), &state)
        .unwrap();
    assert_eq!(browse(&index, &state).0.len(), 1);

    push(
        &mut chain,
        &founder,
        200,
        EntryBody::Moderation(ModerationEntry {
            action: ModerationAction::Delist,
            target_pointer_id: app(7),
        }),
    );

    assert_eq!(index.revalidate(&state_of(&chain)), 1);
    assert!(browse(&index, &state_of(&chain)).0.is_empty());
}

// ---------------------------------------------------------------------------
// Manifests and publishing policy (§2.1, §3.5)
// ---------------------------------------------------------------------------

fn manifest(publisher: &PerNetworkIdentity, version: u64) -> AppManifest {
    AppManifest::create(
        publisher,
        app(7),
        "Wiki",
        "A shared wiki",
        version,
        "index.html",
        vec![
            RequestedCapability::NetworkStorageRead,
            RequestedCapability::NetworkStorageWrite,
            RequestedCapability::RealtimeMedia,
        ],
    )
}

#[test]
fn a_manifest_round_trips_and_tampering_breaks_it() {
    let developer = identity(2);
    let mut m = manifest(&developer, 0);
    assert!(m.verify().is_ok());

    m.entry_point = "attacker.html".into();
    assert_eq!(m.verify(), Err(intranet_app::AppError::BadSignature));
}

#[test]
fn only_enforceable_capabilities_are_reported_as_enforceable() {
    // A visitor must never be told an app was granted something the platform
    // cannot actually contain.
    let developer = identity(2);
    let enforceable = manifest(&developer, 0).enforceable_capabilities();

    assert!(enforceable.contains(&RequestedCapability::NetworkStorageRead));
    assert!(enforceable.contains(&RequestedCapability::NetworkStorageWrite));
    assert!(!enforceable.contains(&RequestedCapability::RealtimeMedia));
}

#[test]
fn open_policy_serves_everything_immediately() {
    let queue = ReviewQueue::new();
    assert!(queue.is_servable(app(7), 0, PublishingPolicy::Open));
    assert!(queue.is_servable(app(7), 99, PublishingPolicy::Open));
}

#[test]
fn reviewed_policy_withholds_until_approved() {
    let founder = identity(1);
    let developer = identity(2);
    let mut chain = app_network(&[&developer]);
    push(
        &mut chain,
        &founder,
        50,
        EntryBody::DefineGroup {
            group: GroupId::new("reviewers"),
            capabilities: CapabilitySet::explicit([Capability::extension(APPROVE_APP_PUBLISH)]),
        },
    );
    push(
        &mut chain,
        &founder,
        51,
        EntryBody::MembershipChange {
            group: GroupId::new("reviewers"),
            identity: developer.id(),
            action: MembershipAction::Add { via_invite: None },
        },
    );
    let state = state_of(&chain);

    let mut queue = ReviewQueue::new();
    queue.submit(PendingPublish {
        app_id: app(7),
        version: 0,
        publisher: developer.id(),
    });

    assert!(!queue.is_servable(app(7), 0, PublishingPolicy::Reviewed));
    assert_eq!(queue.pending().count(), 1);

    queue.approve(app(7), 0, &developer.id(), &state).unwrap();
    assert!(queue.is_servable(app(7), 0, PublishingPolicy::Reviewed));
    assert_eq!(queue.pending().count(), 0);
}

#[test]
fn approving_one_version_does_not_approve_the_next() {
    // The bypass this closes: get an innocuous first version approved, then push
    // a malicious update that skips review entirely.
    let founder = identity(1);
    let developer = identity(2);
    let mut chain = app_network(&[&developer]);
    push(
        &mut chain,
        &founder,
        50,
        EntryBody::DefineGroup {
            group: GroupId::new("reviewers"),
            capabilities: CapabilitySet::explicit([Capability::extension(APPROVE_APP_PUBLISH)]),
        },
    );
    push(
        &mut chain,
        &founder,
        51,
        EntryBody::MembershipChange {
            group: GroupId::new("reviewers"),
            identity: developer.id(),
            action: MembershipAction::Add { via_invite: None },
        },
    );
    let state = state_of(&chain);

    let mut queue = ReviewQueue::new();
    queue.approve(app(7), 0, &developer.id(), &state).unwrap();
    assert!(queue.is_servable(app(7), 0, PublishingPolicy::Reviewed));

    queue.submit(PendingPublish {
        app_id: app(7),
        version: 1,
        publisher: developer.id(),
    });
    assert!(
        !queue.is_servable(app(7), 1, PublishingPolicy::Reviewed),
        "a new version is unapproved by construction, not by inheritance"
    );
}

#[test]
fn an_ordinary_member_cannot_approve_a_publish() {
    let developer = identity(2);
    let state = state_of(&app_network(&[&developer]));

    let mut queue = ReviewQueue::new();
    assert!(matches!(
        queue.approve(app(7), 0, &developer.id(), &state),
        Err(intranet_app::AppError::NotAuthorizedToApprove { .. })
    ));
    assert!(!queue.is_servable(app(7), 0, PublishingPolicy::Reviewed));
}

#[test]
fn names_are_compared_exactly_not_case_folded() {
    // Folding would be a security decision dressed as a convenience: collapsing
    // distinct names creates homograph confusion where a lookalike resolves to
    // somebody else's app.
    let developer = identity(2);
    let mut chain = app_network(&[&developer]);
    register(&mut chain, &developer, 100, "Wiki", app(7));
    let state = state_of(&chain);

    assert!(resolve(&AppName::new("Wiki"), &state).is_some());
    assert!(resolve(&AppName::new("wiki"), &state).is_none());
    assert!(is_available(&AppName::new("wiki"), &state));
}

#[test]
fn a_name_registration_is_capability_gated_so_it_counts_toward_branch_length() {
    // Unlike device certificates, registrations require a capability, so they
    // legitimately count in fork choice and cannot be minted freely to grind.
    let developer = identity(2);
    let chain = app_network(&[&developer]);
    let parent = chain.last().unwrap().hash();
    let entry = name_registration_entry(
        &developer,
        parent,
        at(100),
        AppName::new("wiki"),
        app(7),
    );
    assert!(entry.is_capability_gated());
}

#[test]
fn independent_nodes_replay_name_ownership_identically() {
    let developer = identity(2);
    let mut chain = app_network(&[&developer]);
    register(&mut chain, &developer, 100, "wiki", app(7));

    let a = GovernanceState::replay(&chain).unwrap();
    let b = GovernanceState::replay(&chain).unwrap();
    assert_eq!(a.state_hash(), b.state_hash());
    assert_eq!(a.app_names, b.app_names);
}

#[test]
fn the_default_app_name_resolves_like_any_other() {
    // How "joining a network shows its app" works with no special mechanism: a
    // reserved name is an ordinary lookup, and a network without one simply has
    // nothing for it to resolve to.
    let developer = identity(2);
    let mut chain = app_network(&[&developer]);
    let state = state_of(&chain);
    assert!(
        resolve(&AppName::new("index"), &state).is_none(),
        "a network with no default app has nothing to resolve"
    );

    register(&mut chain, &developer, 100, "index", app(7));
    assert!(resolve(&AppName::new("index"), &state_of(&chain)).is_some());
}

#[test]
fn directory_collections_are_scoped_per_network() {
    let other = NetworkId::from_bytes([43u8; 32]);
    assert_ne!(directory_collection(&NETWORK), directory_collection(&other));
    let _ = Hash::ZERO;
    let _ = EVERYONE;
}
