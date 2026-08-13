//! Capability ledger conformance tests — Core Protocol Spec §4.

use intranet_crypto::Timestamp;
use intranet_governance::{
    Capability, CapabilitySet, EntryBody, GovernanceState, GroupId, LogEntry,
    MembershipAction, NetworkPolicy,
};
use intranet_identity::{MasterSeed, NetworkId, PerNetworkIdentity};
use intranet_ledger::{
    AuditRateLimit, AuditRequest, BandwidthCap, CapabilityAdvertisement, CapabilityLedger,
    ComputeClass, LedgerError, ReliabilityObservations,
};

const NETWORK: NetworkId = NetworkId::from_bytes([42u8; 32]);
const OTHER: NetworkId = NetworkId::from_bytes([43u8; 32]);

fn identity(n: u8) -> PerNetworkIdentity {
    MasterSeed::from_entropy([n; 32]).identity_for(&NETWORK).unwrap()
}

fn at(millis: i64) -> Timestamp {
    Timestamp::from_millis(millis)
}

fn push(chain: &mut Vec<LogEntry>, author: &PerNetworkIdentity, time: i64, body: EntryBody) {
    let parent = chain.last().unwrap().hash();
    chain.push(LogEntry::create(author, Some(parent), at(time), body));
}

/// A network whose founder has admitted `members` into `everyone`.
fn network_with(members: &[&PerNetworkIdentity]) -> Vec<LogEntry> {
    let founder = identity(1);
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

fn advert_for(
    node: &PerNetworkIdentity,
    storage: u64,
    up: u64,
    media_relay: bool,
    issued_at: i64,
) -> CapabilityAdvertisement {
    CapabilityAdvertisement::create(
        node,
        storage,
        BandwidthCap {
            up_bytes_per_sec: up,
            down_bytes_per_sec: up * 4,
            active_window: None,
        },
        false,
        media_relay,
        ComputeClass::Modest,
        at(issued_at),
    )
}

// ---------------------------------------------------------------------------
// Ledger admission
// ---------------------------------------------------------------------------

#[test]
fn a_members_advertisement_is_accepted() {
    let node = identity(2);
    let state = GovernanceState::replay(&network_with(&[&node])).unwrap();
    let mut ledger = CapabilityLedger::new(NETWORK);

    ledger
        .insert(advert_for(&node, 1_000, 500, false, 100), &state)
        .unwrap();
    assert_eq!(ledger.len(), 1);
    assert_eq!(ledger.get(&node.id()).unwrap().storage_offered, 1_000);
}

#[test]
fn a_non_members_advertisement_is_refused() {
    // Otherwise a revoked or never-admitted node could keep attracting
    // placement decisions simply by continuing to announce.
    let stranger = identity(9);
    let state = GovernanceState::replay(&network_with(&[])).unwrap();
    let mut ledger = CapabilityLedger::new(NETWORK);

    assert!(matches!(
        ledger.insert(advert_for(&stranger, 1_000, 500, false, 100), &state),
        Err(LedgerError::NotAMember { .. })
    ));
}

#[test]
fn a_forged_advertisement_is_refused() {
    // Inflating a victim's declared capacity would steer placement onto them.
    let node = identity(2);
    let state = GovernanceState::replay(&network_with(&[&node])).unwrap();
    let mut ledger = CapabilityLedger::new(NETWORK);

    let mut forged = advert_for(&node, 1_000, 500, false, 100);
    forged.storage_offered = 1_000_000_000_000;

    assert_eq!(
        ledger.insert(forged, &state),
        Err(LedgerError::BadSignature)
    );
}

#[test]
fn an_advertisement_from_another_network_is_refused() {
    let node = identity(2);
    let elsewhere = MasterSeed::from_entropy([2u8; 32]).identity_for(&OTHER).unwrap();
    let state = GovernanceState::replay(&network_with(&[&node])).unwrap();
    let mut ledger = CapabilityLedger::new(NETWORK);

    assert!(matches!(
        ledger.insert(advert_for(&elsewhere, 1_000, 500, false, 100), &state),
        Err(LedgerError::NetworkMismatch { .. })
    ));
}

#[test]
fn a_newer_advertisement_replaces_an_older_one() {
    let node = identity(2);
    let state = GovernanceState::replay(&network_with(&[&node])).unwrap();
    let mut ledger = CapabilityLedger::new(NETWORK);

    ledger.insert(advert_for(&node, 1_000, 500, false, 100), &state).unwrap();
    ledger.insert(advert_for(&node, 9_000, 500, false, 200), &state).unwrap();

    assert_eq!(ledger.len(), 1);
    assert_eq!(ledger.get(&node.id()).unwrap().storage_offered, 9_000);
}

#[test]
fn a_stale_advertisement_arriving_late_does_not_overwrite_a_newer_one() {
    // Gossip reorders; that is ordinary, not a fault, so this is silently
    // ignored rather than treated as an error.
    let node = identity(2);
    let state = GovernanceState::replay(&network_with(&[&node])).unwrap();
    let mut ledger = CapabilityLedger::new(NETWORK);

    ledger.insert(advert_for(&node, 9_000, 500, false, 200), &state).unwrap();
    ledger.insert(advert_for(&node, 1_000, 500, false, 100), &state).unwrap();

    assert_eq!(
        ledger.get(&node.id()).unwrap().storage_offered,
        9_000,
        "an out-of-order older advertisement must not win"
    );
}

#[test]
fn expiry_drops_unrefreshed_advertisements() {
    let node = identity(2);
    let state = GovernanceState::replay(&network_with(&[&node])).unwrap();
    let mut ledger = CapabilityLedger::new(NETWORK);
    ledger.insert(advert_for(&node, 1_000, 500, false, 0), &state).unwrap();

    assert_eq!(ledger.expire(at(1_000), 5_000), 0);
    assert_eq!(ledger.expire(at(6_000), 5_000), 1);
    assert!(ledger.is_empty());
}

#[test]
fn reconciling_drops_advertisements_from_departed_members() {
    let node = identity(2);
    let mut chain = network_with(&[&node]);
    let state = GovernanceState::replay(&chain).unwrap();

    let mut ledger = CapabilityLedger::new(NETWORK);
    ledger.insert(advert_for(&node, 1_000, 500, false, 0), &state).unwrap();
    assert_eq!(ledger.len(), 1);

    push(
        &mut chain,
        &identity(1),
        500,
        EntryBody::MembershipChange {
            group: GroupId::everyone(),
            identity: node.id(),
            action: MembershipAction::Remove { cascade: None },
        },
    );
    let after = GovernanceState::replay(&chain).unwrap();

    assert_eq!(ledger.reconcile(&after), 1);
    assert!(ledger.is_empty());
}

// ---------------------------------------------------------------------------
// Placement through the ledger
// ---------------------------------------------------------------------------

/// A ledger populated with `count` members offering identical capacity.
fn populated(count: u8) -> (CapabilityLedger, Vec<PerNetworkIdentity>) {
    let members: Vec<PerNetworkIdentity> = (2..2 + count).map(identity).collect();
    let refs: Vec<&PerNetworkIdentity> = members.iter().collect();
    let state = GovernanceState::replay(&network_with(&refs)).unwrap();

    let mut ledger = CapabilityLedger::new(NETWORK);
    for member in &members {
        ledger
            .insert(advert_for(member, 1_000_000, 500_000, true, 0), &state)
            .unwrap();
    }
    (ledger, members)
}

#[test]
fn two_nodes_compute_the_identical_replica_set() {
    // The deterministic, coordination-free property HRW was chosen for. A hard
    // pass/fail check, not an approximate one.
    let (ledger_a, members) = populated(10);
    let refs: Vec<&PerNetworkIdentity> = members.iter().collect();
    let state = GovernanceState::replay(&network_with(&refs)).unwrap();

    // A second node builds its ledger by inserting in the opposite order.
    let mut ledger_b = CapabilityLedger::new(NETWORK);
    for member in members.iter().rev() {
        ledger_b
            .insert(advert_for(member, 1_000_000, 500_000, true, 0), &state)
            .unwrap();
    }

    assert_eq!(
        ledger_a.select_replicas(b"some-cid", 3),
        ledger_b.select_replicas(b"some-cid", 3)
    );
}

#[test]
fn divergent_local_reliability_cannot_change_placement() {
    // The regression test for the contradiction a review pass found: placement
    // must read only gossiped capacity. Local observations are structurally
    // incapable of reaching the placement path — there is no parameter for
    // them — so wildly different local views must still agree.
    let (ledger, members) = populated(8);

    let mut node_a_view = ReliabilityObservations::new();
    let mut node_b_view = ReliabilityObservations::new();
    for member in &members {
        for _ in 0..50 {
            node_a_view.record_failed(member.id());
            node_b_view.record_verified(member.id());
        }
    }

    let from_a = ledger.select_replicas(b"cid", 4);
    let from_b = ledger.select_replicas(b"cid", 4);
    assert_eq!(from_a, from_b);
    assert_eq!(from_a.len(), 4);
}

#[test]
fn stream_tiers_draw_from_media_relays_and_weight_upload() {
    let storage_only = identity(2);
    let relay_a = identity(3);
    let relay_b = identity(4);
    let state = GovernanceState::replay(&network_with(&[&storage_only, &relay_a, &relay_b])).unwrap();

    let mut ledger = CapabilityLedger::new(NETWORK);
    // Enormous disk, but not willing to relay media.
    ledger
        .insert(advert_for(&storage_only, 100_000_000, 10_000_000, false, 0), &state)
        .unwrap();
    ledger
        .insert(advert_for(&relay_a, 1_000, 9_000_000, true, 0), &state)
        .unwrap();
    ledger
        .insert(advert_for(&relay_b, 1_000, 1_000, true, 0), &state)
        .unwrap();

    let tier = ledger.select_stream_tier(b"stream-1", 5);
    assert!(
        !tier.contains(&storage_only.id()),
        "a node that did not volunteer to relay media must never be assigned a tier slot"
    );
    assert!(tier.contains(&relay_a.id()));
}

#[test]
fn a_small_network_still_gets_replicas_just_fewer() {
    let (ledger, _) = populated(2);
    let selected = ledger.select_replicas(b"cid", 5);
    assert_eq!(selected.len(), 2, "degrade, never refuse to operate");
}

// ---------------------------------------------------------------------------
// Reliability observations (§4.6)
// ---------------------------------------------------------------------------

#[test]
fn observations_accumulate_per_peer() {
    let mut observations = ReliabilityObservations::new();
    let good = identity(2).id();
    let bad = identity(3).id();

    for _ in 0..9 {
        observations.record_verified(good);
    }
    observations.record_verified(bad);
    for _ in 0..9 {
        observations.record_failed(bad);
    }

    assert_eq!(observations.for_peer(&good).failure_rate(), Some(0.0));
    assert_eq!(observations.for_peer(&bad).failure_rate(), Some(0.9));
}

#[test]
fn an_unobserved_peer_reports_no_evidence_rather_than_perfect_reliability() {
    // Collapsing "never seen" into 0.0 would let an unknown peer look exactly
    // as good as one with a long clean record.
    let observations = ReliabilityObservations::new();
    assert_eq!(observations.for_peer(&identity(9).id()).failure_rate(), None);
    assert_eq!(observations.for_peer(&identity(9).id()).total(), 0);
}

#[test]
fn unreliable_peers_are_deprioritized_but_never_excluded() {
    // A soft signal for selection only: it reorders candidates, it does not
    // gate membership or capability, and it never removes anyone.
    let mut observations = ReliabilityObservations::new();
    let reliable = identity(2).id();
    let unknown = identity(3).id();
    let unreliable = identity(4).id();

    for _ in 0..10 {
        observations.record_verified(reliable);
        observations.record_failed(unreliable);
    }

    let mut candidates = vec![unreliable, unknown, reliable];
    observations.deprioritize_unreliable(&mut candidates, 0.5);

    assert_eq!(candidates, vec![reliable, unknown, unreliable]);
    assert_eq!(candidates.len(), 3, "nobody is dropped, only reordered");
}

// ---------------------------------------------------------------------------
// Reputation audit (§4.6)
// ---------------------------------------------------------------------------

/// A network where `auditor` holds `audit-reputation`.
fn audit_network(auditor: &PerNetworkIdentity, subject: &PerNetworkIdentity) -> Vec<LogEntry> {
    let founder = identity(1);
    let mut chain = network_with(&[auditor, subject]);
    push(
        &mut chain,
        &founder,
        100,
        EntryBody::DefineGroup {
            group: GroupId::new("oversight"),
            capabilities: CapabilitySet::explicit([Capability::AuditReputation]),
        },
    );
    push(
        &mut chain,
        &founder,
        101,
        EntryBody::MembershipChange {
            group: GroupId::new("oversight"),
            identity: auditor.id(),
            action: MembershipAction::Add { via_invite: None },
        },
    );
    chain
}

#[test]
fn an_authorized_auditor_receives_signed_raw_counters() {
    let auditor = identity(5);
    let subject = identity(6);
    let responder = identity(2);
    let state = GovernanceState::replay(&audit_network(&auditor, &subject)).unwrap();

    let mut observations = ReliabilityObservations::new();
    for _ in 0..3 {
        observations.record_failed(subject.id());
    }
    observations.record_verified(subject.id());

    let request = AuditRequest::create(&auditor, subject.id(), at(1_000));
    let response = observations
        .respond_to_audit(&request, &responder, &state, at(1_000), AuditRateLimit::default())
        .expect("an authorized audit must be answered");

    assert!(response.verify().is_ok(), "responses are signed so a requester \
         cross-referencing many observers can prove each came from the node it claims");
    assert_eq!(response.observations.failed, 3);
    assert_eq!(response.observations.verified, 1);
    assert_eq!(response.subject, subject.id());
}

#[test]
fn an_unauthorized_requester_is_refused() {
    let ordinary = identity(5);
    let subject = identity(6);
    let responder = identity(2);
    // Note: this network does *not* grant audit-reputation.
    let state = GovernanceState::replay(&network_with(&[&ordinary, &subject])).unwrap();

    let mut observations = ReliabilityObservations::new();
    observations.record_failed(subject.id());

    let request = AuditRequest::create(&ordinary, subject.id(), at(1_000));
    assert!(matches!(
        observations.respond_to_audit(
            &request,
            &responder,
            &state,
            at(1_000),
            AuditRateLimit::default()
        ),
        Err(LedgerError::AuditNotAuthorized { .. })
    ));
}

#[test]
fn a_forged_audit_request_is_refused() {
    let auditor = identity(5);
    let subject = identity(6);
    let responder = identity(2);
    let state = GovernanceState::replay(&audit_network(&auditor, &subject)).unwrap();

    let mut observations = ReliabilityObservations::new();
    let mut request = AuditRequest::create(&auditor, subject.id(), at(1_000));
    request.subject = identity(7).id();

    assert_eq!(
        observations.respond_to_audit(
            &request,
            &responder,
            &state,
            at(1_000),
            AuditRateLimit::default()
        ),
        Err(LedgerError::BadSignature)
    );
}

#[test]
fn audits_are_rate_limited_so_the_mechanism_cannot_become_harassment() {
    let auditor = identity(5);
    let subject = identity(6);
    let responder = identity(2);
    let state = GovernanceState::replay(&audit_network(&auditor, &subject)).unwrap();
    let policy = AuditRateLimit {
        max_requests_per_window: 3,
        window_millis: 60_000,
    };

    let mut observations = ReliabilityObservations::new();
    for i in 0..3 {
        let request = AuditRequest::create(&auditor, subject.id(), at(i));
        assert!(
            observations
                .respond_to_audit(&request, &responder, &state, at(i), policy)
                .is_ok()
        );
    }

    let excess = AuditRequest::create(&auditor, subject.id(), at(4));
    assert!(matches!(
        observations.respond_to_audit(&excess, &responder, &state, at(4), policy),
        Err(LedgerError::AuditRateLimited { .. })
    ));

    // Once the window rolls over, oversight resumes: the limit throttles, it
    // does not permanently lock an auditor out.
    let later = AuditRequest::create(&auditor, subject.id(), at(70_000));
    assert!(
        observations
            .respond_to_audit(&later, &responder, &state, at(70_000), policy)
            .is_ok()
    );
}

#[test]
fn responding_is_mandatory_even_with_nothing_to_report() {
    // Allowing refusal — including a silent "I have nothing" refusal — would let
    // a compromised node decline audits of itself and create a blind spot.
    let auditor = identity(5);
    let subject = identity(6);
    let responder = identity(2);
    let state = GovernanceState::replay(&audit_network(&auditor, &subject)).unwrap();

    let mut observations = ReliabilityObservations::new();
    let request = AuditRequest::create(&auditor, subject.id(), at(1_000));
    let response = observations
        .respond_to_audit(&request, &responder, &state, at(1_000), AuditRateLimit::default())
        .expect("a node with no observations must still answer");

    assert_eq!(response.observations.total(), 0);
    assert!(response.verify().is_ok());
}

#[test]
fn a_tampered_audit_response_fails_verification() {
    // Corroboration across many observers is the whole value of the mechanism,
    // so a requester must not be able to manufacture it.
    let auditor = identity(5);
    let subject = identity(6);
    let responder = identity(2);
    let state = GovernanceState::replay(&audit_network(&auditor, &subject)).unwrap();

    let mut observations = ReliabilityObservations::new();
    observations.record_verified(subject.id());

    let request = AuditRequest::create(&auditor, subject.id(), at(1_000));
    let mut response = observations
        .respond_to_audit(&request, &responder, &state, at(1_000), AuditRateLimit::default())
        .unwrap();

    response.observations.failed = 9_999;
    assert_eq!(response.verify(), Err(LedgerError::BadSignature));
}
