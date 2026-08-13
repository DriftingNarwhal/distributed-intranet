//! Real-time transport conformance tests — Real-Time Spec, Harness §5.

use intranet_crypto::{Hash, Timestamp};
use intranet_governance::{
    Capability, EntryBody, GovernanceState, GroupId, LogEntry, MembershipAction, NetworkPolicy,
};
use intranet_identity::{MasterSeed, NetworkId, PerNetworkIdentity, PerNetworkIdentityId};
use intranet_ledger::{
    BandwidthCap, CapabilityAdvertisement, CapabilityLedger, ComputeClass, ReliabilityObservations,
};
use intranet_realtime::{
    CallId, CallKey, CallKeyEnvelope, CallSession, LiveStream, ProposalOutcome, RealtimeError,
    RelayObservation, RenegotiationTrigger, StreamId, Topology, VodRetention, assign_tier,
    relay,
};
use intranet_storage::Cid;
use std::collections::BTreeSet;

const NETWORK: NetworkId = NetworkId::from_bytes([42u8; 32]);

fn identity(n: u8) -> PerNetworkIdentity {
    MasterSeed::from_entropy([n; 32]).identity_for(&NETWORK).unwrap()
}

fn at(millis: i64) -> Timestamp {
    Timestamp::from_millis(millis)
}

fn call() -> CallId {
    CallId::from_bytes([7u8; 32])
}

fn cid(n: u8) -> Cid {
    Cid::from_hash(Hash::from_bytes([n; 32]))
}

fn push(chain: &mut Vec<LogEntry>, author: &PerNetworkIdentity, time: i64, body: EntryBody) {
    let parent = chain.last().unwrap().hash();
    chain.push(LogEntry::create(author, Some(parent), at(time), body));
}

fn network(members: &[&PerNetworkIdentity]) -> GovernanceState {
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
    GovernanceState::replay(&chain).unwrap()
}

/// A ledger where each `(seed, upload, media_willing)` node has advertised.
fn ledger_of(nodes: &[(u8, u64, bool)]) -> (CapabilityLedger, Vec<PerNetworkIdentity>) {
    let identities: Vec<PerNetworkIdentity> = nodes.iter().map(|(n, _, _)| identity(*n)).collect();
    let refs: Vec<&PerNetworkIdentity> = identities.iter().collect();
    let state = network(&refs);

    let mut ledger = CapabilityLedger::new(NETWORK);
    for (identity, (_, upload, media)) in identities.iter().zip(nodes) {
        ledger
            .insert(
                CapabilityAdvertisement::create(
                    identity,
                    1_000,
                    BandwidthCap {
                        up_bytes_per_sec: *upload,
                        down_bytes_per_sec: upload * 4,
                        active_window: None,
                    },
                    false,
                    *media,
                    ComputeClass::Modest,
                    at(0),
                ),
                &state,
            )
            .unwrap();
    }
    (ledger, identities)
}

// ---------------------------------------------------------------------------
// Call media encryption (§1.3, §2.2)
// ---------------------------------------------------------------------------

#[test]
fn a_frame_round_trips_between_participants() {
    let key = CallKey::generate().unwrap();
    let frame = key.seal_frame(&call(), 1, b"audio samples");
    assert_eq!(key.open_frame(&call(), &frame).unwrap(), b"audio samples");
}

#[test]
fn a_relay_holding_only_the_frame_learns_nothing() {
    // What "blind" means concretely: the relay sees an opaque payload and a
    // sequence number for ordering, and nothing else.
    let key = CallKey::generate().unwrap();
    let frame = key.seal_frame(&call(), 1, b"a private conversation");

    assert!(
        !frame
            .ciphertext
            .windows(7)
            .any(|w| w == b"private"),
        "plaintext must not survive into what a relay forwards"
    );
    assert!(
        CallKey::generate()
            .unwrap()
            .open_frame(&call(), &frame)
            .is_err(),
        "a relay without the call key cannot open a frame"
    );
}

#[test]
fn a_relay_cannot_modify_a_frame_undetected() {
    // Authentication, not just confidentiality: tampering fails at the
    // receiving participant rather than passing through silently.
    let key = CallKey::generate().unwrap();
    let mut frame = key.seal_frame(&call(), 1, b"original");
    let last = frame.ciphertext.len() - 1;
    frame.ciphertext[last] ^= 0x01;

    assert!(matches!(
        key.open_frame(&call(), &frame),
        Err(RealtimeError::FrameAuthenticationFailed { sequence: 1 })
    ));
}

#[test]
fn a_frame_cannot_be_replayed_at_a_different_sequence() {
    // The nonce binds to the sequence number, so a relay reordering or
    // duplicating frames cannot pass one off as another.
    let key = CallKey::generate().unwrap();
    let mut frame = key.seal_frame(&call(), 1, b"first");
    frame.sequence = 2;
    assert!(key.open_frame(&call(), &frame).is_err());
}

#[test]
fn a_frame_cannot_be_replayed_into_a_different_call() {
    let key = CallKey::generate().unwrap();
    let frame = key.seal_frame(&call(), 1, b"first");
    let other_call = CallId::from_bytes([9u8; 32]);
    assert!(key.open_frame(&other_call, &frame).is_err());
}

#[test]
fn call_keys_are_delivered_under_identity_derived_secrets() {
    // §1.3: keys derive from participants' per-network identities, with no
    // separate encryption keypair in the picture.
    let initiator = identity(2);
    let participant = identity(3);
    let key = CallKey::generate().unwrap();

    let envelope =
        CallKeyEnvelope::seal(&initiator, &participant.id(), call(), &key).unwrap();
    let received = envelope.open(&participant).unwrap();

    assert_eq!(received.fingerprint(), key.fingerprint());
}

#[test]
fn an_envelope_cannot_be_opened_by_anyone_else() {
    let initiator = identity(2);
    let participant = identity(3);
    let eavesdropper = identity(4);
    let key = CallKey::generate().unwrap();

    let envelope =
        CallKeyEnvelope::seal(&initiator, &participant.id(), call(), &key).unwrap();
    assert!(matches!(
        envelope.open(&eavesdropper),
        Err(RealtimeError::NotTheRecipient)
    ));
}

#[test]
fn key_agreement_reaches_the_same_secret_from_both_sides() {
    let a = identity(2);
    let b = identity(3);
    assert_eq!(a.agree(&b.id()).unwrap(), b.agree(&a.id()).unwrap());
    assert_ne!(a.agree(&b.id()).unwrap(), a.agree(&identity(4).id()).unwrap());
}

#[test]
fn each_call_gets_a_fresh_key() {
    // Deriving from the participant set instead would mean one recovered key
    // opens every call that group ever had.
    let first = CallKey::generate().unwrap();
    let second = CallKey::generate().unwrap();
    assert_ne!(first.fingerprint(), second.fingerprint());
}

// ---------------------------------------------------------------------------
// Mesh and relay topology (§1.2, §1.4)
// ---------------------------------------------------------------------------

fn participants(count: u8) -> BTreeSet<PerNetworkIdentityId> {
    (2..2 + count).map(|n| identity(n).id()).collect()
}

#[test]
fn a_small_call_stays_in_mesh() {
    let session = CallSession::open(participants(3), 4);
    assert_eq!(session.active_topology(), Topology::Mesh);
    assert!(session.evaluate(true).is_none());
    assert!(
        !session.active_topology().involves_relay(),
        "no third party touches the media below the threshold"
    );
}

#[test]
fn reaching_the_threshold_triggers_a_move_to_relay() {
    let mut session = CallSession::open(participants(3), 4);
    assert!(session.evaluate(true).is_none());

    session.join(identity(99).id());
    assert_eq!(
        session.evaluate(true),
        Some(RenegotiationTrigger::ThresholdReached)
    );
}

#[test]
fn mesh_upload_cost_grows_with_the_call() {
    // The number the threshold exists to bound.
    assert_eq!(CallSession::open(participants(2), 4).mesh_upload_streams(), 1);
    assert_eq!(CallSession::open(participants(5), 4).mesh_upload_streams(), 4);
}

#[test]
fn dropping_below_the_threshold_returns_to_mesh() {
    let relay = identity(50).id();
    let mut session = CallSession::open(participants(5), 4);
    session
        .receive_proposal(
            session
                .propose(
                    identity(2).id(),
                    RenegotiationTrigger::ThresholdReached,
                    Some(intranet_realtime::RelayChoice {
                        relay,
                        worst_latency_millis: 10,
                        upload_capacity: 1_000_000,
                    }),
                    at(100),
                )
                .unwrap(),
            at(100),
        );
    session.complete_handover().unwrap();
    assert!(session.active_topology().involves_relay());

    for n in 2..5u8 {
        session.leave(&identity(n).id());
    }
    assert_eq!(
        session.evaluate(true),
        Some(RenegotiationTrigger::BelowThreshold)
    );
}

#[test]
fn an_unreachable_relay_triggers_failover() {
    let relay = identity(50).id();
    let mut session = CallSession::open(participants(5), 4);
    session.receive_proposal(
        session
            .propose(
                identity(2).id(),
                RenegotiationTrigger::ThresholdReached,
                Some(intranet_realtime::RelayChoice {
                    relay,
                    worst_latency_millis: 10,
                    upload_capacity: 1_000_000,
                }),
                at(100),
            )
            .unwrap(),
        at(100),
    );
    session.complete_handover().unwrap();

    assert_eq!(
        session.evaluate(false),
        Some(RenegotiationTrigger::RelayUnavailable),
        "failover and the threshold transition share one mechanism"
    );
}

#[test]
fn a_relay_transition_without_a_candidate_is_refused() {
    let session = CallSession::open(participants(5), 4);
    assert_eq!(
        session
            .propose(
                identity(2).id(),
                RenegotiationTrigger::ThresholdReached,
                None,
                at(100)
            )
            .unwrap_err(),
        RealtimeError::NoRelayAvailable
    );
}

#[test]
fn media_keeps_flowing_over_the_old_path_until_handover_completes() {
    // Make-before-break: the new transport is established while the old one is
    // still carrying media, so the conversation never has a gap.
    let mut session = CallSession::open(participants(5), 4);
    let proposal = session
        .propose(
            identity(2).id(),
            RenegotiationTrigger::ThresholdReached,
            Some(intranet_realtime::RelayChoice {
                relay: identity(50).id(),
                worst_latency_millis: 10,
                upload_capacity: 1_000_000,
            }),
            at(100),
        )
        .unwrap();

    session.receive_proposal(proposal, at(100));
    assert_eq!(
        session.active_topology(),
        Topology::Mesh,
        "media is still on the old path"
    );
    assert!(session.pending_topology().is_some(), "the new one is coming up");

    session.complete_handover().unwrap();
    assert!(session.active_topology().involves_relay());
    assert!(session.pending_topology().is_none());
}

#[test]
fn an_abandoned_handover_leaves_the_call_on_its_existing_path() {
    // The failure make-before-break exists to survive: if the new transport
    // never comes up, the call continues rather than being left with neither.
    let mut session = CallSession::open(participants(5), 4);
    let proposal = session
        .propose(
            identity(2).id(),
            RenegotiationTrigger::ThresholdReached,
            Some(intranet_realtime::RelayChoice {
                relay: identity(50).id(),
                worst_latency_millis: 10,
                upload_capacity: 1_000_000,
            }),
            at(100),
        )
        .unwrap();
    session.receive_proposal(proposal, at(100));
    session.abandon_handover();

    assert_eq!(session.active_topology(), Topology::Mesh);
    assert!(session.pending_topology().is_none());
}

#[test]
fn completing_a_handover_with_nothing_pending_is_an_error() {
    let mut session = CallSession::open(participants(3), 4);
    assert_eq!(
        session.complete_handover().unwrap_err(),
        RealtimeError::NoHandoverPending
    );
}

#[test]
fn the_earlier_received_proposal_wins() {
    let mut session = CallSession::open(participants(5), 4);
    let make = |proposer: PerNetworkIdentityId, relay_seed: u8| {
        session
            .propose(
                proposer,
                RenegotiationTrigger::ThresholdReached,
                Some(intranet_realtime::RelayChoice {
                    relay: identity(relay_seed).id(),
                    worst_latency_millis: 10,
                    upload_capacity: 1_000_000,
                }),
                at(100),
            )
            .unwrap()
    };
    let first = make(identity(2).id(), 50);
    let second = make(identity(3).id(), 51);

    assert_eq!(
        session.receive_proposal(first, at(100)),
        ProposalOutcome::Accepted
    );
    assert_eq!(
        session.receive_proposal(second, at(200)),
        ProposalOutcome::Superseded,
        "a later arrival does not displace one already converging"
    );
    assert_eq!(
        session.pending_topology(),
        Some(Topology::Relayed {
            relay: identity(50).id()
        })
    );
}

#[test]
fn simultaneous_proposals_converge_on_a_stable_ordering() {
    // When timing is genuinely ambiguous every participant must still pick the
    // same winner, or the call splits across two topologies.
    let low = identity(2).id().min(identity(3).id());

    let converge = |order: bool| {
        let mut session = CallSession::open(participants(5), 4);
        let a = session
            .propose(
                identity(2).id(),
                RenegotiationTrigger::ThresholdReached,
                Some(intranet_realtime::RelayChoice {
                    relay: identity(50).id(),
                    worst_latency_millis: 10,
                    upload_capacity: 1_000_000,
                }),
                at(100),
            )
            .unwrap();
        let b = session
            .propose(
                identity(3).id(),
                RenegotiationTrigger::ThresholdReached,
                Some(intranet_realtime::RelayChoice {
                    relay: identity(51).id(),
                    worst_latency_millis: 10,
                    upload_capacity: 1_000_000,
                }),
                at(100),
            )
            .unwrap();

        let (first, second) = if order { (a, b) } else { (b, a) };
        session.receive_proposal(first, at(100));
        session.receive_proposal(second, at(100));
        session.pending_topology()
    };

    assert_eq!(
        converge(true),
        converge(false),
        "arrival order must not change the outcome when timing ties"
    );
    // And the winner is the lexicographically lower proposer's choice.
    let expected_relay = if low == identity(2).id() { 50 } else { 51 };
    assert_eq!(
        converge(true),
        Some(Topology::Relayed {
            relay: identity(expected_relay).id()
        })
    );
}

// ---------------------------------------------------------------------------
// Relay selection (§2.3)
// ---------------------------------------------------------------------------

#[test]
fn relay_selection_minimises_the_worst_participant_latency() {
    // A call is only as good as its least well-served participant, so a relay
    // that is excellent for most and terrible for one is the wrong choice.
    let (ledger, _) = ledger_of(&[(2, 1_000_000, true), (3, 1_000_000, true)]);
    let members = participants(2);
    let (near, lopsided) = (identity(2).id(), identity(3).id());
    let people: Vec<PerNetworkIdentityId> = members.iter().copied().collect();

    let observations = vec![
        RelayObservation { relay: near, participant: people[0], latency_millis: 40 },
        RelayObservation { relay: near, participant: people[1], latency_millis: 45 },
        RelayObservation { relay: lopsided, participant: people[0], latency_millis: 2 },
        RelayObservation { relay: lopsided, participant: people[1], latency_millis: 400 },
    ];

    let choice = relay::select(
        &observations,
        &members,
        &ledger,
        &ReliabilityObservations::new(),
        0.5,
    )
    .expect("a relay should be selected");

    assert_eq!(choice.relay, near);
    assert_eq!(choice.worst_latency_millis, 45);
}

#[test]
fn a_candidate_not_measured_by_everyone_is_skipped() {
    // An unmeasured leg could be the bad one, and choosing on partial
    // information quietly defeats the worst-case criterion.
    let (ledger, _) = ledger_of(&[(2, 1_000_000, true), (3, 1_000_000, true)]);
    let members = participants(2);
    let people: Vec<PerNetworkIdentityId> = members.iter().copied().collect();

    let observations = vec![
        // Only one participant measured this one.
        RelayObservation { relay: identity(3).id(), participant: people[0], latency_millis: 1 },
        RelayObservation { relay: identity(2).id(), participant: people[0], latency_millis: 50 },
        RelayObservation { relay: identity(2).id(), participant: people[1], latency_millis: 50 },
    ];

    let choice = relay::select(
        &observations,
        &members,
        &ledger,
        &ReliabilityObservations::new(),
        0.5,
    )
    .unwrap();
    assert_eq!(choice.relay, identity(2).id());
}

#[test]
fn a_node_that_did_not_volunteer_for_media_relaying_is_never_chosen() {
    // Bootstrap relaying and media relaying are different commitments; a node
    // offering a few seconds of hole-punch help has not signed up for an hour
    // of call traffic.
    let (ledger, _) = ledger_of(&[(2, 1_000_000, false)]);
    let members = participants(1);
    let people: Vec<PerNetworkIdentityId> = members.iter().copied().collect();

    let observations = vec![RelayObservation {
        relay: identity(2).id(),
        participant: people[0],
        latency_millis: 1,
    }];

    assert!(
        relay::select(
            &observations,
            &members,
            &ledger,
            &ReliabilityObservations::new(),
            0.5
        )
        .is_none()
    );
}

#[test]
fn an_unreliable_relay_is_ranked_behind_a_slower_reliable_one() {
    // Legitimate here, because relay choice is a local per-call decision with
    // no cross-node consistency requirement — unlike stream tier assignment.
    let (ledger, _) = ledger_of(&[(2, 1_000_000, true), (3, 1_000_000, true)]);
    let members = participants(1);
    let people: Vec<PerNetworkIdentityId> = members.iter().copied().collect();
    let (flaky, steady) = (identity(3).id(), identity(2).id());

    let mut reliability = ReliabilityObservations::new();
    for _ in 0..10 {
        reliability.record_failed(flaky);
    }

    let observations = vec![
        RelayObservation { relay: flaky, participant: people[0], latency_millis: 1 },
        RelayObservation { relay: steady, participant: people[0], latency_millis: 90 },
    ];

    let choice = relay::select(&observations, &members, &ledger, &reliability, 0.5).unwrap();
    assert_eq!(choice.relay, steady);
}

// ---------------------------------------------------------------------------
// Live streaming (§3)
// ---------------------------------------------------------------------------

#[test]
fn stream_tiers_are_deterministic_and_drawn_from_media_relays() {
    let (ledger, _) = ledger_of(&[
        (2, 1_000_000, true),
        (3, 1_000_000, true),
        (4, 1_000_000, false),
        (5, 1_000_000, true),
    ]);
    let stream = StreamId::from_hash(Hash::from_bytes([1u8; 32]));

    let first = assign_tier(&stream, &ledger, 2);
    let second = assign_tier(&stream, &ledger, 2);
    assert_eq!(first, second, "any node computes the same tier");
    assert!(
        !first.contains(&identity(4).id()),
        "a node that did not volunteer for media relaying is never in the tier"
    );
}

#[test]
fn stream_tiers_weight_upload_not_storage() {
    let (ledger, _) = ledger_of(&[(2, 50_000_000, true), (3, 1_000, true)]);
    let stream = StreamId::from_hash(Hash::from_bytes([1u8; 32]));

    let tier = assign_tier(&stream, &ledger, 1);
    assert_eq!(
        tier,
        vec![identity(2).id()],
        "the node with far more upload capacity should carry the tier"
    );
}

#[test]
fn a_tier_is_recomputed_only_when_a_member_drops_out() {
    let (ledger, _) = ledger_of(&[(2, 1_000_000, true), (3, 1_000_000, true), (5, 1_000_000, true)]);
    let stream = StreamId::from_hash(Hash::from_bytes([1u8; 32]));
    let live = LiveStream::start(stream, &ledger, 2, 10);

    assert!(
        !live.tier_needs_recompute(&ledger),
        "a stable tier avoids rebuilding connections for no reason"
    );

    let mut reduced = ledger.clone();
    reduced.remove(&live.tier()[0]);
    assert!(live.tier_needs_recompute(&reduced));
}

#[test]
fn a_departed_tier_member_is_replaced_on_recompute() {
    let (ledger, _) = ledger_of(&[(2, 1_000_000, true), (3, 1_000_000, true), (5, 1_000_000, true)]);
    let stream = StreamId::from_hash(Hash::from_bytes([1u8; 32]));
    let mut live = LiveStream::start(stream, &ledger, 2, 10);
    let departed = live.tier()[0];

    let mut reduced = ledger.clone();
    reduced.remove(&departed);
    live.recompute_tier(&reduced);

    assert!(!live.tier().contains(&departed));
    assert_eq!(live.tier().len(), 2, "a replacement moved up");
}

#[test]
fn a_broadcaster_with_no_volunteers_gets_an_empty_tier_rather_than_an_error() {
    // Degrading rather than failing: the broadcaster falls back to serving
    // viewers directly, which is worse but not broken.
    let (ledger, _) = ledger_of(&[(2, 1_000_000, false)]);
    let stream = StreamId::from_hash(Hash::from_bytes([1u8; 32]));
    assert!(assign_tier(&stream, &ledger, 3).is_empty());
}

// ---------------------------------------------------------------------------
// VOD (§4)
// ---------------------------------------------------------------------------

#[test]
fn a_finished_broadcast_becomes_ordinary_content_with_the_same_bytes() {
    // Encryption continuity: the exact ciphertext chunks that were propagated
    // live become the VOD, with no re-encryption step at all.
    let (ledger, _) = ledger_of(&[(2, 1_000_000, true)]);
    let stream = StreamId::from_hash(Hash::from_bytes([1u8; 32]));
    let live = LiveStream::start(stream, &ledger, 1, 3);

    let all: Vec<(u64, Cid)> = (1u8..=6).map(|n| (u64::from(n), cid(n))).collect();
    let manifest = live
        .into_vod(&all, 6_000, VodRetention::Enabled)
        .unwrap()
        .expect("retention enabled");

    assert_eq!(manifest.chunks.len(), 6);
    assert_eq!(
        manifest.chunks,
        all.iter().map(|(_, c)| *c).collect::<Vec<_>>(),
        "the same addresses, unchanged"
    );
}

#[test]
fn opting_out_prevents_a_platform_record_but_is_not_claimed_to_do_more() {
    // The honest framing: opt-out stops the platform publishing a discoverable
    // record. It cannot stop a viewer who already received the chunks from
    // keeping them, and the API does not pretend otherwise — the chunk
    // identifiers a viewer holds remain perfectly valid content addresses.
    let (ledger, _) = ledger_of(&[(2, 1_000_000, true)]);
    let stream = StreamId::from_hash(Hash::from_bytes([1u8; 32]));
    let live = LiveStream::start(stream, &ledger, 1, 3);

    let all: Vec<(u64, Cid)> = (1u8..=3).map(|n| (u64::from(n), cid(n))).collect();
    assert!(
        live.into_vod(&all, 3_000, VodRetention::Disabled)
            .unwrap()
            .is_none(),
        "no manifest is published"
    );
    // Nothing invalidates the chunks themselves — that is the honest limit.
    assert_eq!(all.len(), 3);
}
