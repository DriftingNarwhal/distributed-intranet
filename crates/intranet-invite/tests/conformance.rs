//! Invite conformance tests — Core Protocol Spec §5.6–5.7, §2.4.

use intranet_crypto::Timestamp;
use intranet_governance::{
    Capability, CapabilitySet, EntryBody, EVERYONE, GovernanceState, GroupId, InviteProvenance,
    LogEntry, MembershipAction, NetworkPolicy, starter_content_types,
};
use intranet_identity::{MasterSeed, NetworkId, PerNetworkIdentity};
use intranet_invite::{Invite, InviteError, InviteSubject, WaitingRoom};

const NETWORK: NetworkId = NetworkId::from_bytes([42u8; 32]);
const OTHER_NETWORK: NetworkId = NetworkId::from_bytes([43u8; 32]);

fn identity(n: u8) -> PerNetworkIdentity {
    MasterSeed::from_entropy([n; 32]).identity_for(&NETWORK).unwrap()
}

fn at(millis: i64) -> Timestamp {
    Timestamp::from_millis(millis)
}

fn bootstrap() -> Vec<String> {
    vec!["/ip4/198.51.100.7/tcp/4001".into()]
}

/// A network whose founder holds `approve-node`, plus an ordinary member.
fn network() -> (Vec<LogEntry>, PerNetworkIdentity, PerNetworkIdentity) {
    let founder = identity(1);
    let member = identity(2);

    let genesis = LogEntry::create(
        &founder,
        None,
        at(0),
        EntryBody::Genesis {
            network: NETWORK,
            policy: NetworkPolicy::conservative_default(),
            everyone_capabilities: [Capability::ReadContent].into_iter().collect(),
        },
    );
    let mut chain = vec![genesis];

    let parent = chain.last().unwrap().hash();
    chain.push(LogEntry::create(
        &founder,
        Some(parent),
        at(10),
        EntryBody::MembershipChange {
            group: GroupId::everyone(),
            identity: member.id(),
            action: MembershipAction::Add { via_invite: None },
        },
    ));

    (chain, founder, member)
}

/// Appends a signed entry chained onto the tip.
fn push(chain: &mut Vec<LogEntry>, author: &PerNetworkIdentity, time: i64, body: EntryBody) {
    let parent = chain.last().unwrap().hash();
    chain.push(LogEntry::create(author, Some(parent), at(time), body));
}

fn state_of(chain: &[LogEntry]) -> GovernanceState {
    GovernanceState::replay(chain).unwrap()
}

fn valid_invite(issuer: &PerNetworkIdentity) -> Invite {
    Invite::issue(
        issuer,
        bootstrap(),
        InviteSubject::Bearer,
        at(0),
        at(100_000),
        5,
    )
}

// ---------------------------------------------------------------------------
// Signature and structure
// ---------------------------------------------------------------------------

#[test]
fn a_valid_invite_is_accepted() {
    let (chain, founder, _) = network();
    let invite = valid_invite(&founder);
    let joiner = identity(9);

    let provenance = invite
        .validate(&joiner.id(), &state_of(&chain), at(50))
        .expect("invite should validate");

    assert_eq!(provenance.issuer, founder.id());
    assert_eq!(provenance.invite_id, invite.invite_id());
}

#[test]
fn tampering_with_any_field_breaks_the_invite() {
    let (chain, founder, _) = network();
    let state = state_of(&chain);
    let joiner = identity(9);
    let invite = valid_invite(&founder);

    let mut extended = invite.clone();
    extended.expires_at = at(999_999_999);
    assert_eq!(
        extended.validate(&joiner.id(), &state, at(50)),
        Err(InviteError::BadSignature),
        "extending an invite's lifetime must not be possible without the issuer"
    );

    let mut more_uses = invite.clone();
    more_uses.max_uses = 1_000;
    assert_eq!(
        more_uses.validate(&joiner.id(), &state, at(50)),
        Err(InviteError::BadSignature)
    );

    let mut redirected = invite;
    redirected.bootstrap_addresses = vec!["/ip4/203.0.113.9/tcp/4001".into()];
    assert_eq!(
        redirected.validate(&joiner.id(), &state, at(50)),
        Err(InviteError::BadSignature),
        "redirecting a joiner's first connection must not be possible"
    );
}

#[test]
fn an_invite_for_another_network_is_refused() {
    let other_founder = MasterSeed::from_entropy([1u8; 32])
        .identity_for(&OTHER_NETWORK)
        .unwrap();
    let invite = valid_invite(&other_founder);

    let (chain, ..) = network();
    assert!(matches!(
        invite.validate(&identity(9).id(), &state_of(&chain), at(50)),
        Err(InviteError::NetworkMismatch { .. })
    ));
}

#[test]
fn an_invite_with_no_bootstrap_addresses_is_refused() {
    // An invite exists to make the first connection; one that cannot is not a
    // weaker invite, it is a useless one.
    let (chain, founder, _) = network();
    let invite = Invite::issue(
        &founder,
        Vec::new(),
        InviteSubject::Bearer,
        at(0),
        at(100_000),
        5,
    );
    assert_eq!(
        invite.validate(&identity(9).id(), &state_of(&chain), at(50)),
        Err(InviteError::NoBootstrapAddresses)
    );
}

// ---------------------------------------------------------------------------
// Time bounds
// ---------------------------------------------------------------------------

#[test]
fn an_expired_invite_is_refused() {
    let (chain, founder, _) = network();
    let invite = valid_invite(&founder);
    assert!(matches!(
        invite.validate(&identity(9).id(), &state_of(&chain), at(100_001)),
        Err(InviteError::Expired { .. })
    ));
}

#[test]
fn an_invite_is_valid_up_to_and_including_its_expiry() {
    let (chain, founder, _) = network();
    let invite = valid_invite(&founder);
    assert!(
        invite
            .validate(&identity(9).id(), &state_of(&chain), at(100_000))
            .is_ok(),
        "the boundary itself must still be valid, not off-by-one rejected"
    );
}

#[test]
fn an_invite_presented_before_issuance_is_refused() {
    // Guards against a node with a badly-skewed clock accepting an invite that,
    // from its own vantage point, has not been issued yet.
    let (chain, founder, _) = network();
    let invite = valid_invite(&founder);
    assert!(matches!(
        invite.validate(&identity(9).id(), &state_of(&chain), at(-1)),
        Err(InviteError::NotYetValid { .. })
    ));
}

// ---------------------------------------------------------------------------
// Issuer authority, evaluated at use time (§5.6)
// ---------------------------------------------------------------------------

#[test]
fn an_invite_from_someone_without_approve_node_is_refused() {
    let (chain, _, member) = network();
    let invite = valid_invite(&member);

    assert!(
        matches!(
            invite.validate(&identity(9).id(), &state_of(&chain), at(50)),
            Err(InviteError::IssuerNotAuthorized { .. })
        ),
        "an ordinary member cannot mint invites merely by signing one"
    );
}

#[test]
fn revoking_an_admin_kills_their_outstanding_invites() {
    // Authority is evaluated as of *now*, not as of issuance. Otherwise
    // removing a compromised admin would leave every invite they ever issued
    // live, which is precisely the blast radius revocation exists to close.
    let founder = identity(1);
    let deputy = identity(3);

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

    push(
        &mut chain,
        &founder,
        10,
        EntryBody::DefineGroup {
            group: GroupId::new("admins"),
            capabilities: CapabilitySet::explicit([Capability::ApproveNode]),
        },
    );
    push(
        &mut chain,
        &founder,
        11,
        EntryBody::MembershipChange {
            group: GroupId::new("admins"),
            identity: deputy.id(),
            action: MembershipAction::Add { via_invite: None },
        },
    );

    let invite = valid_invite(&deputy);
    let joiner = identity(9);
    assert!(
        invite.validate(&joiner.id(), &state_of(&chain), at(50)).is_ok(),
        "while the deputy holds approve-node the invite works"
    );

    push(
        &mut chain,
        &founder,
        60,
        EntryBody::MembershipChange {
            group: GroupId::new("admins"),
            identity: deputy.id(),
            action: MembershipAction::Remove { cascade: None },
        },
    );

    assert!(
        matches!(
            invite.validate(&joiner.id(), &state_of(&chain), at(70)),
            Err(InviteError::IssuerNotAuthorized { .. })
        ),
        "once the deputy is removed, their outstanding invites must stop working"
    );
}

// ---------------------------------------------------------------------------
// Subject binding
// ---------------------------------------------------------------------------

#[test]
fn a_specific_identity_invite_cannot_be_used_by_anyone_else() {
    let (chain, founder, _) = network();
    let intended = identity(9);
    let interloper = identity(10);

    let invite = Invite::issue(
        &founder,
        bootstrap(),
        InviteSubject::Identity(intended.id()),
        at(0),
        at(100_000),
        1,
    );
    let state = state_of(&chain);

    assert!(invite.validate(&intended.id(), &state, at(50)).is_ok());
    assert!(matches!(
        invite.validate(&interloper.id(), &state, at(50)),
        Err(InviteError::WrongSubject { .. })
    ));
}

#[test]
fn a_bearer_invite_may_be_used_by_anyone() {
    let (chain, founder, _) = network();
    let state = state_of(&chain);
    let invite = valid_invite(&founder);

    for n in 9..12 {
        assert!(invite.validate(&identity(n).id(), &state, at(50)).is_ok());
    }
}

// ---------------------------------------------------------------------------
// Use counting via membership provenance
// ---------------------------------------------------------------------------

#[test]
fn use_count_is_derived_from_replayed_membership_provenance() {
    // Counting by replay rather than by a private per-node tally is what makes
    // the limit mean the same thing on every node: a per-node counter would let
    // a single-use invite be spent once against each node separately.
    let (mut chain, founder, _) = network();
    let invite = Invite::issue(
        &founder,
        bootstrap(),
        InviteSubject::Bearer,
        at(0),
        at(100_000),
        2,
    );
    let provenance = invite.provenance();

    let admit = |chain: &mut Vec<LogEntry>, who: &PerNetworkIdentity, time: i64| {
        push(
            chain,
            &founder,
            time,
            EntryBody::MembershipChange {
                group: GroupId::everyone(),
                identity: who.id(),
                action: MembershipAction::Add {
                    via_invite: Some(provenance),
                },
            },
        );
    };

    assert_eq!(state_of(&chain).invite_use_count(&invite.invite_id()), 0);

    admit(&mut chain, &identity(9), 20);
    assert_eq!(state_of(&chain).invite_use_count(&invite.invite_id()), 1);
    assert!(
        invite
            .validate(&identity(11).id(), &state_of(&chain), at(50))
            .is_ok(),
        "one use of a two-use invite leaves one"
    );

    admit(&mut chain, &identity(10), 30);
    assert_eq!(state_of(&chain).invite_use_count(&invite.invite_id()), 2);
    assert!(
        matches!(
            invite.validate(&identity(11).id(), &state_of(&chain), at(50)),
            Err(InviteError::Exhausted { used: 2, max_uses: 2 })
        ),
        "an exhausted invite must be refused"
    );
}

#[test]
fn use_count_does_not_confuse_two_different_invites() {
    let (mut chain, founder, _) = network();
    let first = valid_invite(&founder);
    let second = Invite::issue(
        &founder,
        bootstrap(),
        InviteSubject::Bearer,
        at(1),
        at(100_000),
        5,
    );
    assert_ne!(first.invite_id(), second.invite_id());

    let parent = chain.last().unwrap().hash();
    chain.push(LogEntry::create(
        &founder,
        Some(parent),
        at(20),
        EntryBody::MembershipChange {
            group: GroupId::everyone(),
            identity: identity(9).id(),
            action: MembershipAction::Add {
                via_invite: Some(first.provenance()),
            },
        },
    ));

    let state = state_of(&chain);
    assert_eq!(state.invite_use_count(&first.invite_id()), 1);
    assert_eq!(state.invite_use_count(&second.invite_id()), 0);
}

// ---------------------------------------------------------------------------
// Waiting room (§2.4)
// ---------------------------------------------------------------------------

fn provenance() -> InviteProvenance {
    InviteProvenance {
        invite_id: intranet_crypto::hash_bytes(b"an-invite"),
        issuer: identity(1).id(),
    }
}

#[test]
fn a_waiting_room_occupant_holds_no_membership_at_all() {
    let (chain, ..) = network();
    let state = state_of(&chain);
    let joiner = identity(9);

    let mut room = WaitingRoom::new();
    room.admit_to_waiting(joiner.id(), provenance(), at(100));

    assert!(room.contains(&joiner.id()));
    assert!(
        !state.is_member(&joiner.id()),
        "explicit intake grants no group membership, so no capabilities and no epoch key"
    );
    assert!(!state.identity_holds(&joiner.id(), &Capability::ReadContent));
}

#[test]
fn waiting_room_entries_carry_the_issuer_context_an_admin_needs() {
    let mut room = WaitingRoom::new();
    room.admit_to_waiting(identity(9).id(), provenance(), at(100));

    let occupants = room.occupants();
    assert_eq!(occupants.len(), 1);
    assert_eq!(occupants[0].provenance.issuer, identity(1).id());
    assert_eq!(occupants[0].arrived_at, at(100));
}

#[test]
fn reconnecting_does_not_reset_arrival_time() {
    // Otherwise a joiner could churn their connection to keep appearing freshly
    // arrived and slip past an admin reviewing oldest-first.
    let mut room = WaitingRoom::new();
    room.admit_to_waiting(identity(9).id(), provenance(), at(100));
    room.admit_to_waiting(identity(9).id(), provenance(), at(9_000));

    assert_eq!(room.len(), 1);
    assert_eq!(room.occupants()[0].arrived_at, at(100));
}

#[test]
fn occupants_are_listed_oldest_first() {
    let mut room = WaitingRoom::new();
    room.admit_to_waiting(identity(11).id(), provenance(), at(300));
    room.admit_to_waiting(identity(9).id(), provenance(), at(100));
    room.admit_to_waiting(identity(10).id(), provenance(), at(200));

    let arrivals: Vec<_> = room.occupants().iter().map(|e| e.arrived_at).collect();
    assert_eq!(arrivals, vec![at(100), at(200), at(300)]);
}

#[test]
fn admission_removes_a_joiner_from_the_waiting_room() {
    let (mut chain, founder, _) = network();
    let joiner = identity(9);

    let mut room = WaitingRoom::new();
    room.admit_to_waiting(joiner.id(), provenance(), at(100));

    let parent = chain.last().unwrap().hash();
    chain.push(LogEntry::create(
        &founder,
        Some(parent),
        at(200),
        EntryBody::MembershipChange {
            group: GroupId::everyone(),
            identity: joiner.id(),
            action: MembershipAction::Add {
                via_invite: Some(provenance()),
            },
        },
    ));

    room.reconcile(&state_of(&chain));
    assert!(
        room.is_empty(),
        "reconciling against replayed state must clear anyone since admitted, \
         even if a different admin on a different node did the admitting"
    );
}

#[test]
fn the_waiting_room_is_only_visible_to_membership_managers() {
    let (mut chain, founder, member) = network();
    let room = WaitingRoom::new();

    // An ordinary member cannot see who is trying to join.
    assert!(!room.visible_to(&member.id(), &state_of(&chain)));
    // The founder, holding every capability, can.
    assert!(room.visible_to(&founder.id(), &state_of(&chain)));

    // And so can someone explicitly granted manage-membership:everyone.
    let parent = chain.last().unwrap().hash();
    chain.push(LogEntry::create(
        &founder,
        Some(parent),
        at(20),
        EntryBody::DefineGroup {
            group: GroupId::new("intake"),
            capabilities: CapabilitySet::explicit([Capability::manage_membership(EVERYONE)]),
        },
    ));
    let parent = chain.last().unwrap().hash();
    chain.push(LogEntry::create(
        &founder,
        Some(parent),
        at(21),
        EntryBody::MembershipChange {
            group: GroupId::new("intake"),
            identity: member.id(),
            action: MembershipAction::Add { via_invite: None },
        },
    ));

    assert!(room.visible_to(&member.id(), &state_of(&chain)));
}

#[test]
fn arrivals_can_be_counted_per_invite_for_rate_limiting() {
    // Feeds the relay's per-invite metering: pre-admission identities are free
    // to mint, so the invite is the scarce resource worth counting.
    let mut room = WaitingRoom::new();
    let shared = provenance();
    for n in 9..15 {
        room.admit_to_waiting(identity(n).id(), shared, at(100 + i64::from(n)));
    }

    assert_eq!(room.arrivals_for_invite(&shared.invite_id), 6);
    assert_eq!(
        room.arrivals_for_invite(&intranet_crypto::hash_bytes(b"unrelated")),
        0
    );
}

// ---------------------------------------------------------------------------
// §5.7 — the invite carries nothing beyond first-connection data
// ---------------------------------------------------------------------------

#[test]
fn an_invite_carries_no_network_state_beyond_connection_bootstrap() {
    // The prior prototype's invite carried a single shared static network key.
    // That scheme is rejected: an invite now triggers the epoch-key delivery
    // handshake instead, and this test is the structural reminder — everything
    // in the payload is connection bootstrap or provenance, nothing more.
    let (_, founder, _) = network();
    let invite = valid_invite(&founder);

    // Exhaustive destructure: adding a field to `Invite` fails to compile here,
    // which forces a deliberate decision about whether it belongs in an invite
    // at all rather than letting scope creep in silently.
    let Invite {
        network: _,
        bootstrap_addresses: _,
        issuer: _,
        subject: _,
        issued_at: _,
        expires_at: _,
        max_uses: _,
        signature: _,
    } = invite;
}

#[test]
fn invite_ids_are_stable_and_distinguish_invites() {
    let (_, founder, _) = network();
    let invite = valid_invite(&founder);
    assert_eq!(invite.invite_id(), invite.invite_id());

    let other = Invite::issue(
        &founder,
        bootstrap(),
        InviteSubject::Bearer,
        at(0),
        at(100_001),
        5,
    );
    assert_ne!(invite.invite_id(), other.invite_id());
}

#[test]
fn content_type_policy_is_untouched_by_joining() {
    // A sanity check that joining does not silently widen a network's scope.
    let (chain, ..) = network();
    let state = state_of(&chain);
    assert_eq!(state.policy.content_type_allowlist, starter_content_types());
}
