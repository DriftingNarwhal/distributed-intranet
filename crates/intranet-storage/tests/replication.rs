//! Replica maintenance conformance tests — Storage Spec §3.1–3.4.

use intranet_crypto::{Hash, Timestamp};
use intranet_governance::{
    Capability, EntryBody, GovernanceState, GroupId, LogEntry, MembershipAction, NetworkPolicy,
};
use intranet_identity::{MasterSeed, NetworkId, PerNetworkIdentity};
use intranet_ledger::{BandwidthCap, CapabilityAdvertisement, CapabilityLedger, ComputeClass};
use intranet_storage::{
    Cid, HoldingAnnouncement, ReplicationHealth, ReplicationView, StorageError,
};
use std::collections::BTreeSet;

const NETWORK: NetworkId = NetworkId::from_bytes([42u8; 32]);
const OTHER: NetworkId = NetworkId::from_bytes([43u8; 32]);

fn identity(n: u8) -> PerNetworkIdentity {
    MasterSeed::from_entropy([n; 32]).identity_for(&NETWORK).unwrap()
}

fn at(millis: i64) -> Timestamp {
    Timestamp::from_millis(millis)
}

fn cid(n: u8) -> Cid {
    Cid::from_hash(Hash::from_bytes([n; 32]))
}

fn push(chain: &mut Vec<LogEntry>, author: &PerNetworkIdentity, time: i64, body: EntryBody) {
    let parent = chain.last().unwrap().hash();
    chain.push(LogEntry::create(author, Some(parent), at(time), body));
}

fn network(members: &[&PerNetworkIdentity]) -> Vec<LogEntry> {
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

/// A network of `count` members, each offering storage, with a populated ledger.
fn fixture(count: u8) -> (Vec<PerNetworkIdentity>, GovernanceState, CapabilityLedger) {
    let members: Vec<PerNetworkIdentity> = (2..2 + count).map(identity).collect();
    let refs: Vec<&PerNetworkIdentity> = members.iter().collect();
    let state = GovernanceState::replay(&network(&refs)).unwrap();

    let mut ledger = CapabilityLedger::new(NETWORK);
    for member in &members {
        ledger
            .insert(
                CapabilityAdvertisement::create(
                    member,
                    1_000_000,
                    BandwidthCap {
                        up_bytes_per_sec: 500_000,
                        down_bytes_per_sec: 2_000_000,
                        active_window: None,
                    },
                    false,
                    false,
                    ComputeClass::Modest,
                    at(0),
                ),
                &state,
            )
            .unwrap();
    }
    (members, state, ledger)
}

/// Announces that each of `holders` holds `content`.
fn announce(
    view: &mut ReplicationView,
    holders: &[&PerNetworkIdentity],
    content: Cid,
    when: i64,
    state: &GovernanceState,
) {
    for holder in holders {
        let announcement =
            HoldingAnnouncement::create(holder, BTreeSet::from([content]), at(when));
        view.record(&announcement, state).unwrap();
    }
}

/// The nodes placement assigns for `content` at `target`.
fn assigned(
    ledger: &CapabilityLedger,
    content: Cid,
    target: usize,
) -> Vec<intranet_identity::PerNetworkIdentityId> {
    ledger.select_replicas(content.hash().as_bytes(), target)
}

// ---------------------------------------------------------------------------
// Announcements
// ---------------------------------------------------------------------------

#[test]
fn a_signed_announcement_is_recorded() {
    let (members, state, _) = fixture(3);
    let mut view = ReplicationView::new(NETWORK);
    announce(&mut view, &[&members[0]], cid(1), 100, &state);

    assert_eq!(view.holders_of(&cid(1)), vec![members[0].id()]);
}

#[test]
fn a_forged_announcement_is_refused() {
    // Otherwise a node could claim to hold content it does not, suppressing a
    // repair that should happen and quietly costing durability.
    let (members, state, _) = fixture(3);
    let mut view = ReplicationView::new(NETWORK);

    let mut forged =
        HoldingAnnouncement::create(&members[0], BTreeSet::from([cid(1)]), at(100));
    forged.holdings.insert(cid(2));

    assert_eq!(view.record(&forged, &state), Err(StorageError::BadSignature));
}

#[test]
fn an_announcement_from_a_non_member_is_refused() {
    let (_, state, _) = fixture(3);
    let stranger = identity(99);
    let mut view = ReplicationView::new(NETWORK);

    let announcement =
        HoldingAnnouncement::create(&stranger, BTreeSet::from([cid(1)]), at(100));
    assert!(matches!(
        view.record(&announcement, &state),
        Err(StorageError::PublisherNotAMember { .. })
    ));
}

#[test]
fn an_announcement_from_another_network_is_refused() {
    let (_, state, _) = fixture(3);
    let elsewhere = MasterSeed::from_entropy([2u8; 32]).identity_for(&OTHER).unwrap();
    let mut view = ReplicationView::new(NETWORK);

    let announcement =
        HoldingAnnouncement::create(&elsewhere, BTreeSet::from([cid(1)]), at(100));
    assert!(view.record(&announcement, &state).is_err());
}

#[test]
fn an_out_of_order_stale_announcement_does_not_age_out_a_live_holder() {
    // Gossip reorders. Keeping the last-arrived rather than the freshest would
    // let a delayed old announcement expire a node that is still holding.
    let (members, state, _) = fixture(3);
    let mut view = ReplicationView::new(NETWORK).with_ttl(1_000);

    announce(&mut view, &[&members[0]], cid(1), 5_000, &state);
    announce(&mut view, &[&members[0]], cid(1), 100, &state);

    assert_eq!(view.expire(at(5_500)), 0, "the fresh announcement must win");
    assert_eq!(view.holders_of(&cid(1)).len(), 1);
}

// ---------------------------------------------------------------------------
// Detection (§3.4)
// ---------------------------------------------------------------------------

#[test]
fn healthy_content_needs_no_repair() {
    let (_, state, ledger) = fixture(6);
    let content = cid(1);
    let holders = assigned(&ledger, content, 3);

    let mut view = ReplicationView::new(NETWORK);
    for node in &holders {
        let holder = (2u8..8)
            .map(identity)
            .find(|candidate| candidate.id() == *node)
            .unwrap();
        announce(&mut view, &[&holder], content, 100, &state);
    }

    let status = view.assess(&content, &ledger, 3);
    assert_eq!(status.health, ReplicationHealth::Healthy);
    assert_eq!(status.durable_holders.len(), 3);
    assert!(view.plan_repair(&content, &ledger, 3).is_none());
}

#[test]
fn a_departed_holder_surfaces_as_under_replication_with_no_failure_report() {
    // The detection mechanism: a node that goes away stops announcing, its
    // holdings age out, and the shortfall becomes visible on its own.
    let (members, state, ledger) = fixture(6);
    let content = cid(1);
    let holders = assigned(&ledger, content, 3);
    let holder_nodes: Vec<&PerNetworkIdentity> = members
        .iter()
        .filter(|m| holders.contains(&m.id()))
        .collect();

    let mut view = ReplicationView::new(NETWORK).with_ttl(1_000);
    announce(&mut view, &holder_nodes, content, 100, &state);
    assert_eq!(view.assess(&content, &ledger, 3).health, ReplicationHealth::Healthy);

    // Two keep announcing; one goes silent.
    announce(&mut view, &holder_nodes[..2], content, 2_000, &state);
    assert_eq!(view.expire(at(2_500)), 1, "the silent holder ages out");

    let status = view.assess(&content, &ledger, 3);
    assert_eq!(status.health, ReplicationHealth::UnderReplicated);
    assert_eq!(status.durable_holders.len(), 2);
}

#[test]
fn a_revoked_holder_stops_counting_toward_durability() {
    let (members, mut chain_state, ledger) = fixture(4);
    let _ = &mut chain_state;
    let content = cid(1);

    let mut chain = network(&members.iter().collect::<Vec<_>>());
    let state = GovernanceState::replay(&chain).unwrap();
    let mut view = ReplicationView::new(NETWORK);
    announce(&mut view, &members.iter().collect::<Vec<_>>(), content, 100, &state);

    push(
        &mut chain,
        &identity(1),
        900,
        EntryBody::MembershipChange {
            group: GroupId::everyone(),
            identity: members[0].id(),
            action: MembershipAction::Remove { cascade: None },
        },
    );
    let after = GovernanceState::replay(&chain).unwrap();

    assert_eq!(view.reconcile(&after), 1);
    assert!(!view.holders_of(&content).contains(&members[0].id()));
    let _ = ledger;
}

#[test]
fn opportunistic_copies_do_not_mask_a_durability_shortfall() {
    // Swarm copies serve requests exactly like assigned replicas, but they
    // vanish when interest does. Counting them toward N would let transient
    // popularity hide a genuine shortfall.
    let (members, state, ledger) = fixture(8);
    let content = cid(1);
    let holders = assigned(&ledger, content, 3);

    // Only one assigned node holds it; several unassigned nodes cached it.
    let assigned_holder: Vec<&PerNetworkIdentity> = members
        .iter()
        .filter(|m| m.id() == holders[0])
        .collect();
    let cachers: Vec<&PerNetworkIdentity> = members
        .iter()
        .filter(|m| !holders.contains(&m.id()))
        .take(4)
        .collect();

    let mut view = ReplicationView::new(NETWORK);
    announce(&mut view, &assigned_holder, content, 100, &state);
    announce(&mut view, &cachers, content, 100, &state);

    let status = view.assess(&content, &ledger, 3);
    assert_eq!(status.durable_holders.len(), 1);
    assert_eq!(status.opportunistic_holders.len(), 4);
    assert!(status.total_copies() > status.target, "plenty of copies exist");
    assert_eq!(
        status.health,
        ReplicationHealth::UnderReplicated,
        "durability is still short despite abundant transient copies"
    );
}

// ---------------------------------------------------------------------------
// Degraded small networks (§3.2)
// ---------------------------------------------------------------------------

#[test]
fn a_network_smaller_than_its_target_is_degraded_not_repairable() {
    // A three-person friend network must still function. The shortfall is
    // reported, never treated as a fault to keep retrying.
    let (members, state, ledger) = fixture(2);
    let content = cid(1);

    let mut view = ReplicationView::new(NETWORK);
    announce(&mut view, &members.iter().collect::<Vec<_>>(), content, 100, &state);

    let status = view.assess(&content, &ledger, 5);
    assert_eq!(status.eligible, 2);
    assert_eq!(status.durable_holders.len(), 2);
    assert_eq!(status.health, ReplicationHealth::Degraded);
    assert!(
        view.plan_repair(&content, &ledger, 5).is_none(),
        "there is nobody left to repair onto, so no plan should be produced"
    );
}

#[test]
fn degraded_durability_is_observable() {
    let (members, state, ledger) = fixture(2);
    let content = cid(1);
    let mut view = ReplicationView::new(NETWORK);
    announce(&mut view, &[&members[0]], content, 100, &state);

    let summary = view.assess(&content, &ledger, 5).summary();
    assert!(summary.contains("of target 5"), "got: {summary}");
}

// ---------------------------------------------------------------------------
// Repair planning (§3.4)
// ---------------------------------------------------------------------------

#[test]
fn repair_assigns_the_next_ranked_nodes_not_already_holding() {
    let (members, state, ledger) = fixture(8);
    let content = cid(1);
    let holders = assigned(&ledger, content, 3);
    let present: Vec<&PerNetworkIdentity> = members
        .iter()
        .filter(|m| m.id() == holders[0])
        .collect();

    let mut view = ReplicationView::new(NETWORK);
    announce(&mut view, &present, content, 100, &state);

    let plan = view.plan_repair(&content, &ledger, 3).expect("repair needed");
    assert_eq!(plan.cid, content);
    assert_eq!(plan.assign_to.len(), 2, "two copies short of target");
    assert!(
        !plan.assign_to.contains(&holders[0]),
        "a node already holding it must not be assigned again"
    );
}

#[test]
fn two_nodes_plan_the_identical_repair() {
    // Repair plans come from the same deterministic ranking placement uses, so
    // redundant repair converges rather than conflicting.
    let (members, state, ledger) = fixture(8);
    let content = cid(1);

    let build_view = || {
        let mut view = ReplicationView::new(NETWORK);
        announce(&mut view, &[&members[0]], content, 100, &state);
        view
    };

    assert_eq!(
        build_view().plan_repair(&content, &ledger, 3),
        build_view().plan_repair(&content, &ledger, 3)
    );
}

#[test]
fn a_failing_holder_is_replaced_by_the_next_node_in_the_ranking() {
    // The correction the HRW change relies on: unreliable nodes are handled
    // here, by observed outcome, not by biasing placement with private
    // reputation that no two nodes agree on.
    let (members, state, ledger) = fixture(8);
    let content = cid(1);
    let ranked = ledger.select_replicas(content.hash().as_bytes(), 8);
    let target = 3;

    // The top-ranked node never announces — it was assigned but is not holding.
    let holding: Vec<&PerNetworkIdentity> = members
        .iter()
        .filter(|m| ranked[1..target].contains(&m.id()))
        .collect();

    let mut view = ReplicationView::new(NETWORK);
    announce(&mut view, &holding, content, 100, &state);

    let plan = view.plan_repair(&content, &ledger, target).expect("repair needed");
    assert_eq!(
        plan.assign_to,
        vec![ranked[0]],
        "the highest-ranked node not holding it is assigned, whoever that is"
    );
}

#[test]
fn repair_extends_past_the_original_cutoff_when_assigned_nodes_are_gone() {
    // With the top-ranked node withdrawn from the ledger entirely, placement
    // recomputes and the next node moves up on its own — repair needs no memory
    // of who was previously assigned.
    let (members, state, _) = fixture(6);
    let content = cid(1);

    let mut full = CapabilityLedger::new(NETWORK);
    for member in &members {
        full.insert(
            CapabilityAdvertisement::create(
                member,
                1_000_000,
                BandwidthCap {
                    up_bytes_per_sec: 500_000,
                    down_bytes_per_sec: 2_000_000,
                    active_window: None,
                },
                false,
                false,
                ComputeClass::Modest,
                at(0),
            ),
            &state,
        )
        .unwrap();
    }
    let original = full.select_replicas(content.hash().as_bytes(), 3);

    // The top-ranked node withdraws its storage offer.
    let mut reduced = full.clone();
    reduced.remove(&original[0]);
    let recomputed = reduced.select_replicas(content.hash().as_bytes(), 3);

    assert!(!recomputed.contains(&original[0]));
    assert_eq!(recomputed.len(), 3, "a replacement moved up automatically");
    assert_eq!(
        recomputed[..2],
        original[1..3],
        "the survivors keep their positions rather than reshuffling"
    );
}

#[test]
fn repair_can_be_planned_across_everything_tracked() {
    let (members, state, ledger) = fixture(6);
    let mut view = ReplicationView::new(NETWORK);
    for n in 1u8..=4 {
        announce(&mut view, &[&members[0]], cid(n), 100, &state);
    }

    let plans = view.plan_all_repairs(&ledger, 3);
    assert_eq!(plans.len(), 4, "every under-replicated item gets a plan");
}

#[test]
fn content_nobody_holds_is_reported_lost_rather_than_repairable() {
    // Repair copies from an existing holder. With no holder there is nothing to
    // copy from, so a plan would describe work that cannot be performed —
    // placement can say where a copy should go, but cannot conjure bytes.
    let (_, _, ledger) = fixture(6);
    let view = ReplicationView::new(NETWORK);

    let status = view.assess(&cid(9), &ledger, 3);
    assert_eq!(status.health, ReplicationHealth::Lost);
    assert_eq!(status.total_copies(), 0);
    assert!(view.plan_repair(&cid(9), &ledger, 3).is_none());
    assert_eq!(view.tracked().count(), 0);
}

#[test]
fn losing_every_holder_is_reported_as_lost_not_merely_under_replicated() {
    // Operationally this is the urgent case, and it must not be filed under the
    // same heading as "one replica short".
    let (members, state, ledger) = fixture(6);
    let content = cid(1);

    let mut view = ReplicationView::new(NETWORK).with_ttl(1_000);
    announce(&mut view, &members.iter().collect::<Vec<_>>(), content, 100, &state);
    assert_ne!(view.assess(&content, &ledger, 3).health, ReplicationHealth::Lost);

    // Everyone goes silent.
    assert!(view.expire(at(5_000)) > 0);
    assert_eq!(view.assess(&content, &ledger, 3).health, ReplicationHealth::Lost);
    assert!(view.plan_repair(&content, &ledger, 3).is_none());
}

// ---------------------------------------------------------------------------
// Opt-in participation (§3.4)
// ---------------------------------------------------------------------------

#[test]
fn only_nodes_offering_storage_run_repair() {
    // Repair is opt-in like every other contribution. Assigning repair duty to
    // a node that declared no storage would conscript it into the role it
    // declined.
    let contributor = identity(2);
    let abstainer = identity(3);
    let state = GovernanceState::replay(&network(&[&contributor, &abstainer])).unwrap();

    let mut ledger = CapabilityLedger::new(NETWORK);
    ledger
        .insert(
            CapabilityAdvertisement::create(
                &contributor,
                1_000_000,
                BandwidthCap::NONE,
                false,
                false,
                ComputeClass::Modest,
                at(0),
            ),
            &state,
        )
        .unwrap();
    ledger
        .insert(CapabilityAdvertisement::none(&abstainer, at(0)), &state)
        .unwrap();

    assert!(intranet_storage::replication::runs_repair(&contributor.id(), &ledger));
    assert!(!intranet_storage::replication::runs_repair(&abstainer.id(), &ledger));
    assert!(
        !intranet_storage::replication::runs_repair(&identity(9).id(), &ledger),
        "a node with no advertisement at all has not opted in"
    );
}

#[test]
fn a_node_offering_no_storage_is_never_assigned_repair_work() {
    let contributor = identity(2);
    let abstainer = identity(3);
    let state = GovernanceState::replay(&network(&[&contributor, &abstainer])).unwrap();

    let mut ledger = CapabilityLedger::new(NETWORK);
    ledger
        .insert(
            CapabilityAdvertisement::create(
                &contributor,
                1_000_000,
                BandwidthCap::NONE,
                false,
                false,
                ComputeClass::Modest,
                at(0),
            ),
            &state,
        )
        .unwrap();
    ledger
        .insert(CapabilityAdvertisement::none(&abstainer, at(0)), &state)
        .unwrap();

    let view = ReplicationView::new(NETWORK);
    let status = view.assess(&cid(1), &ledger, 3);
    assert_eq!(status.eligible, 1, "only the contributor is eligible");

    if let Some(plan) = view.plan_repair(&cid(1), &ledger, 3) {
        assert!(!plan.assign_to.contains(&abstainer.id()));
    }
}
