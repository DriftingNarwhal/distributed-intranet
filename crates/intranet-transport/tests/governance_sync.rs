//! Governance log propagation over libp2p — Core Protocol Spec §2.7, Harness §3.
//!
//! # What these cover that the governance crate's own tests cannot
//!
//! `intranet-governance` tests fork choice, finality and replay thoroughly, but
//! entirely in one process against one log. Everything those tests assert is
//! true of a log that never left the machine it was built on. The properties
//! that only exist once two nodes are involved — that an entry survives the trip
//! intact, that a partition's divergent branches actually reach each other on
//! heal, that they arrive in an order the receiver can use — had no coverage at
//! all until the sync protocol existed.
//!
//! A partition here is simply two nodes that have not been connected, and a heal
//! is connecting them. That is not a simplification of the real case: the sync
//! protocol is pull-based precisely so that a heal and a first meeting are the
//! same code path (see `intranet_transport::sync`), so exercising one exercises
//! the other.

use intranet_crypto::{Hash, Timestamp};
use intranet_governance::{
    Capability, CapabilitySet, EntryBody, GroupId, LogEntry, MembershipAction,
    NetworkPolicy,
};
use intranet_identity::{
    DeviceCertificate, DevicePublicKey, DeviceSeed, MasterSeed, NetworkId, PerNetworkIdentity,
};
use intranet_transport::{MemberNode, NodeEvent};
use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;
use std::time::Duration;

const NETWORK: NetworkId = NetworkId::from_bytes([42u8; 32]);

fn identity(n: u8) -> PerNetworkIdentity {
    MasterSeed::from_entropy([n; 32]).identity_for(&NETWORK).unwrap()
}

/// A genesis entry authored by `founder`, who thereby holds every capability.
fn genesis(founder: &PerNetworkIdentity) -> LogEntry {
    LogEntry::create(
        founder,
        None,
        Timestamp::from_millis(0),
        EntryBody::Genesis {
            network: NETWORK,
            policy: NetworkPolicy::conservative_default(),
            everyone_capabilities: [Capability::ReadContent].into_iter().collect(),
        },
    )
}

/// A capability-gated entry — the kind fork choice actually counts (§2.7.1).
fn gated(author: &PerNetworkIdentity, parent: Hash, label: &str, at: i64) -> LogEntry {
    LogEntry::create(
        author,
        Some(parent),
        Timestamp::from_millis(at),
        EntryBody::DefineGroup {
            group: GroupId::new(label),
            capabilities: CapabilitySet::explicit([Capability::ReadContent]),
        },
    )
}

/// A capability-free entry — the kind a branch-grinding attacker mints freely.
fn ungated(author: &PerNetworkIdentity, parent: Hash, n: u32, at: i64) -> LogEntry {
    let device_seed = DeviceSeed::from_entropy([(n % 251) as u8; 32]);
    let key = device_seed.key_for(&NETWORK).unwrap();
    let device = DevicePublicKey::from_verifying_key(*key.id().verifying_key());
    let certificate = DeviceCertificate::issue(
        author,
        device,
        format!("device{n}"),
        Timestamp::from_millis(at),
    );
    LogEntry::create(
        author,
        Some(parent),
        Timestamp::from_millis(at),
        EntryBody::DeviceEnrollment(certificate),
    )
}

/// Brings up a node listening on loopback, returning it with its address.
async fn node(seed: u8) -> (MemberNode, Multiaddr) {
    let identity = identity(seed);
    let mut node = MemberNode::new(&identity).unwrap();
    node.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap()).unwrap();

    let address = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let NodeEvent::Listening(address) = node.next_event().await
                && address.iter().any(|p| matches!(p, Protocol::Tcp(_)))
            {
                return address;
            }
        }
    })
    .await
    .expect("the node should listen");

    (node, address.with(Protocol::P2p(identity.peer_id())))
}

/// Drives both nodes until `done`, or the deadline passes.
///
/// Both must be polled: a swarm makes no progress unless something is awaiting
/// it, so driving only the node under test would leave its peer unable to answer
/// and the sync would appear to hang for reasons that have nothing to do with
/// the protocol.
async fn drive(
    a: &mut MemberNode,
    b: &mut MemberNode,
    limit: Duration,
    done: impl Fn(&MemberNode, &MemberNode) -> bool,
) -> bool {
    tokio::time::timeout(limit, async {
        loop {
            if done(a, b) {
                return true;
            }
            tokio::select! {
                _ = a.next_event() => {}
                _ = b.next_event() => {}
            }
        }
    })
    .await
    .unwrap_or(false)
}

/// Chain lengths match — the cheap convergence predicate.
fn same_length(a: &MemberNode, b: &MemberNode) -> bool {
    a.governance_log().len() == b.governance_log().len()
}

/// Asserts two nodes agree on the log, on the canonical branch, and on state.
///
/// All three, because they fail independently and only the third is what
/// members actually experience: two nodes can hold identical entry sets and
/// still disagree about which branch is canonical, and two nodes can agree on
/// the canonical branch and still replay it into different authorization state.
fn assert_converged(a: &MemberNode, b: &MemberNode) {
    assert_eq!(
        a.governance_log().len(),
        b.governance_log().len(),
        "both nodes should hold the same number of entries"
    );
    assert_eq!(
        a.governance_log().canonical_chain(),
        b.governance_log().canonical_chain(),
        "both nodes should choose the same canonical branch"
    );
    assert_eq!(
        a.governance_log().replay_canonical().unwrap().state_hash(),
        b.governance_log().replay_canonical().unwrap().state_hash(),
        "both nodes should replay the canonical branch into identical state — \
         this is the deterministic check Harness §3 requires be hard pass/fail"
    );
}

#[tokio::test]
async fn a_node_that_has_never_seen_the_log_receives_it_on_connecting() {
    let founder = identity(1);
    let (mut source, _) = node(1).await;
    let (mut joiner, joiner_addr) = node(2).await;

    let mut parent = source.append_entry(genesis(&founder)).unwrap();
    for i in 0..4 {
        parent = source
            .append_entry(gated(&founder, parent, &format!("group{i}"), 10 + i))
            .unwrap();
    }
    assert_eq!(source.governance_log().len(), 5);
    assert!(joiner.governance_log().is_empty());

    source.dial_candidates([joiner_addr]).unwrap();
    assert!(
        drive(&mut source, &mut joiner, Duration::from_secs(20), same_length).await,
        "the joiner should have received the whole log"
    );

    assert_converged(&source, &joiner);
}

#[tokio::test]
async fn entries_appended_during_a_partition_reach_the_other_side_on_heal() {
    // The §3 round trip: both sides append to the same parent while unable to
    // see each other, then heal and must converge on one canonical branch.
    let founder = identity(1);
    let (mut left, _) = node(1).await;
    let (mut right, right_addr) = node(2).await;

    // Shared history, as both sides would hold before the split.
    let shared = genesis(&founder);
    let root = left.append_entry(shared.clone()).unwrap();
    right.append_entry(shared).unwrap();

    // Partitioned: neither node has ever been connected to the other, so
    // neither can possibly learn what the other is doing.
    let mut left_tip = root;
    for i in 0..3 {
        left_tip = left
            .append_entry(gated(&founder, left_tip, &format!("left{i}"), 20 + i))
            .unwrap();
    }
    let right_tip = right
        .append_entry(gated(&founder, root, "right0", 30))
        .unwrap();

    assert_ne!(left_tip, right_tip, "the two sides should have diverged");
    assert_eq!(left.governance_log().len(), 4);
    assert_eq!(right.governance_log().len(), 2);

    // Heal.
    left.dial_candidates([right_addr]).unwrap();
    assert!(
        drive(&mut left, &mut right, Duration::from_secs(20), |a, b| {
            a.governance_log().len() == 5 && b.governance_log().len() == 5
        })
        .await,
        "each side should end up holding both branches"
    );

    assert_converged(&left, &right);
    assert_eq!(
        left.governance_log().canonical_chain().last(),
        Some(&left_tip),
        "the longer branch, by capability-gated action count, should win (§2.7.1)"
    );
}

#[tokio::test]
async fn capability_free_padding_does_not_win_a_partition_race() {
    // Harness §3's named negative test, run across a real connection rather than
    // in one log. The attacker mints entries requiring no capability as fast as
    // it likes; fork choice counts only capability-gated actions, so speed buys
    // nothing. Running it over the wire also checks the padding actually
    // *propagates* — an attack that silently failed to transfer would make this
    // pass for entirely the wrong reason.
    let founder = identity(1);
    let attacker = identity(2);
    let (mut honest, _) = node(1).await;
    let (mut grinder, grinder_addr) = node(2).await;

    let shared_genesis = genesis(&founder);
    let root = honest.append_entry(shared_genesis.clone()).unwrap();
    grinder.append_entry(shared_genesis).unwrap();

    // The attacker must be a member before its entries mean anything.
    let admit = LogEntry::create(
        &founder,
        Some(root),
        Timestamp::from_millis(5),
        EntryBody::MembershipChange {
            group: GroupId::everyone(),
            identity: attacker.id(),
            action: MembershipAction::Add { via_invite: None },
        },
    );
    let fork_point = honest.append_entry(admit.clone()).unwrap();
    grinder.append_entry(admit).unwrap();

    // Honest side: two genuine capability-gated actions.
    let mut honest_tip = fork_point;
    for i in 0..2 {
        honest_tip = honest
            .append_entry(gated(&founder, honest_tip, &format!("honest{i}"), 10 + i))
            .unwrap();
    }

    // Attacker side: 20 capability-free entries, a far longer branch by raw count.
    let padding = 20;
    let mut grind_tip = fork_point;
    for i in 0..padding {
        grind_tip = grinder
            .append_entry(ungated(&attacker, grind_tip, i, 100 + i64::from(i)))
            .unwrap();
    }

    honest.dial_candidates([grinder_addr]).unwrap();
    let total = 2 + 2 + padding as usize;
    assert!(
        drive(&mut honest, &mut grinder, Duration::from_secs(30), |a, b| {
            a.governance_log().len() == total && b.governance_log().len() == total
        })
        .await,
        "both sides should hold every entry, including the padding"
    );

    assert_converged(&honest, &grinder);
    assert_eq!(
        honest.governance_log().canonical_chain().last(),
        Some(&honest_tip),
        "a branch of {padding} capability-free entries must not displace one with more \
         capability-gated actions — buying finality with speed is exactly the exploit \
         the capability-gated count exists to close"
    );
    assert_ne!(
        honest.governance_log().canonical_chain().last(),
        Some(&grind_tip)
    );
}

#[tokio::test]
async fn a_deep_chain_arrives_in_an_order_the_receiver_can_insert() {
    // `GovernanceLog::insert` refuses an entry whose parent it has never seen,
    // so a receiver handed a child before its parent drops it — and a dropped
    // entry is indistinguishable from one that was never sent. Asserting zero
    // rejections is what turns that silent failure into a visible one.
    let founder = identity(1);
    let (mut source, _) = node(1).await;
    let (mut joiner, joiner_addr) = node(2).await;

    let depth = 40;
    let mut parent = source.append_entry(genesis(&founder)).unwrap();
    for i in 0..depth {
        parent = source
            .append_entry(gated(&founder, parent, &format!("deep{i}"), 10 + i))
            .unwrap();
    }

    source.dial_candidates([joiner_addr]).unwrap();

    let mut rejected_total = 0;
    let synced = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if joiner.governance_log().len() as i64 == depth + 1 {
                return true;
            }
            tokio::select! {
                _ = source.next_event() => {}
                event = joiner.next_event() => {
                    if let NodeEvent::Synced { rejected, .. } = event {
                        rejected_total += rejected;
                    }
                }
            }
        }
    })
    .await
    .unwrap_or(false);

    assert!(synced, "a {depth}-deep chain should transfer in full");
    assert_eq!(
        rejected_total, 0,
        "every entry must arrive after its parent; a rejection means the ordering \
         guarantee in `ancestors_first` did not hold"
    );
    assert_converged(&source, &joiner);
}

#[tokio::test]
async fn a_log_larger_than_one_response_still_converges() {
    // Responses are capped, so a log past the cap needs more than one exchange.
    // Resumption is the part worth testing: a truncated sync that looked
    // complete would leave the receiver permanently short with nothing
    // indicating why, which is the same silent-shortfall failure as a dropped
    // entry.
    let founder = identity(1);
    let (mut source, _) = node(1).await;
    let (mut joiner, joiner_addr) = node(2).await;

    let depth = intranet_governance::MAX_ENTRIES_PER_RESPONSE + 40;
    let mut parent = source.append_entry(genesis(&founder)).unwrap();
    for i in 0..depth {
        parent = source
            .append_entry(gated(&founder, parent, &format!("bulk{i}"), 10 + i as i64))
            .unwrap();
    }
    assert!(source.governance_log().len() > intranet_governance::MAX_ENTRIES_PER_RESPONSE);

    source.dial_candidates([joiner_addr]).unwrap();

    // Observing an actual truncation is the point. Without this the test would
    // pass identically against a build whose cap never engaged, proving only
    // that a large log transfers rather than that resumption works.
    let mut saw_truncation = false;
    let converged = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if joiner.governance_log().len() == source.governance_log().len() {
                return true;
            }
            tokio::select! {
                _ = source.next_event() => {}
                event = joiner.next_event() => {
                    if let NodeEvent::Synced { truncated: true, .. } = event {
                        saw_truncation = true;
                    }
                }
            }
        }
    })
    .await
    .unwrap_or(false);

    assert!(
        converged,
        "a log past the per-response cap should still converge, over several exchanges"
    );
    assert!(
        saw_truncation,
        "the cap should have engaged on a log of {} entries — if it did not, this test \
         never exercised resumption at all",
        depth + 1
    );
    assert_converged(&source, &joiner);
}

#[tokio::test]
async fn a_log_with_nothing_to_offer_syncs_to_a_no_op() {
    // The quiet case, and the one that would hide a protocol that only appears
    // to work because it always has something to send: two nodes already in step
    // must exchange heads and then stop, not loop forever re-fetching.
    let founder = identity(1);
    let (mut left, _) = node(1).await;
    let (mut right, right_addr) = node(2).await;

    let shared = genesis(&founder);
    left.append_entry(shared.clone()).unwrap();
    right.append_entry(shared).unwrap();

    left.dial_candidates([right_addr]).unwrap();

    // Drive well past the point a sync would have completed, counting any entry
    // transfer. There should be none: neither side lacks anything.
    let mut transfers = 0;
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            tokio::select! {
                event = left.next_event() => {
                    if let NodeEvent::Synced { accepted, .. } = event {
                        transfers += accepted;
                    }
                }
                event = right.next_event() => {
                    if let NodeEvent::Synced { accepted, .. } = event {
                        transfers += accepted;
                    }
                }
            }
        }
    })
    .await;

    assert_eq!(transfers, 0, "two logs already in step should transfer nothing");
    assert_eq!(left.governance_log().len(), 1);
    assert_eq!(right.governance_log().len(), 1);
    assert_converged(&left, &right);
}

#[tokio::test]
async fn an_entry_appended_after_connecting_reaches_the_peer_on_the_next_sync() {
    // Appending does not push (see `MemberNode::append_entry`), so a peer learns
    // about it on its next sync. This pins that the pull path genuinely works
    // while connected — if it only worked at connection time, every steady-state
    // update would silently stall until a reconnect.
    let founder = identity(1);
    let (mut left, _) = node(1).await;
    let (mut right, right_addr) = node(2).await;

    let shared = genesis(&founder);
    let root = left.append_entry(shared.clone()).unwrap();
    right.append_entry(shared).unwrap();

    left.dial_candidates([right_addr]).unwrap();
    assert!(
        drive(&mut left, &mut right, Duration::from_secs(15), |a, b| {
            a.governance_log().len() == 1 && b.governance_log().len() == 1
        })
        .await
    );

    let peer = right.peer_id();
    left.append_entry(gated(&founder, root, "later", 50)).unwrap();
    right.sync_with(peer);

    assert!(
        drive(&mut left, &mut right, Duration::from_secs(15), |_, b| {
            b.governance_log().len() == 2
        })
        .await,
        "an entry appended after the connection should transfer on the next sync"
    );
    assert_converged(&left, &right);
}
