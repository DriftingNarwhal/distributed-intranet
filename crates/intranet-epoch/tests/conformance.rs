//! Epoch keying conformance tests — Core Protocol Spec §3, Harness §3.

use intranet_crypto::{Hash, Timestamp};
use intranet_governance::{
    Capability, EntryBody, GovernanceLog, GroupId, HistoryAccess, LogEntry, MembershipAction,
    NetworkPolicy, RotationReason,
};
use intranet_epoch::{EpochKeyring, GroupSession, RotationStatus};
use intranet_identity::{MasterSeed, NetworkId, PerNetworkIdentity};
use intranet_storage::{ChunkSpec, Dek, DekWrapping, EpochKey, MutablePointer, encode};

const NETWORK: NetworkId = NetworkId::from_bytes([42u8; 32]);

fn identity(n: u8) -> PerNetworkIdentity {
    MasterSeed::from_entropy([n; 32]).identity_for(&NETWORK).unwrap()
}

fn at(millis: i64) -> Timestamp {
    Timestamp::from_millis(millis)
}

fn key(n: u8) -> EpochKey {
    EpochKey::from_bytes([n; 32])
}

// ---------------------------------------------------------------------------
// MLS group mechanics (§3.3)
// ---------------------------------------------------------------------------

#[test]
fn a_new_group_yields_a_stable_epoch_key() {
    let session = GroupSession::create(b"founder").unwrap();
    let first = session.epoch_key().unwrap();
    let again = session.epoch_key().unwrap();
    assert_eq!(first.fingerprint(), again.fingerprint());
    assert_eq!(session.member_count(), 1);
}

#[test]
fn adding_a_member_advances_the_epoch_and_both_derive_the_same_key() {
    let mut founder = GroupSession::create(b"founder").unwrap();
    let before = founder.epoch_key().unwrap();

    let joiner = GroupSession::prepare_join(b"joiner").unwrap();
    let rotation = founder.add_member(&joiner.key_package().unwrap()).unwrap();

    assert_ne!(before.fingerprint(), rotation.key.fingerprint(), "a membership change must rekey");
    assert_eq!(founder.member_count(), 2);

    let joined = joiner.join(rotation.welcome.as_ref().unwrap()).unwrap();
    assert_eq!(
        joined.epoch_key().unwrap().fingerprint(),
        rotation.key.fingerprint(),
        "every member must derive the identical epoch key"
    );
}

#[test]
fn removing_a_member_rekeys_beyond_their_reach() {
    // The cryptographic half of the revocation guarantee. The other half —
    // blocking new ciphertext — is the serving gate's job.
    let mut founder = GroupSession::create(b"founder").unwrap();
    let doomed = GroupSession::prepare_join(b"doomed").unwrap();
    let added = founder.add_member(&doomed.key_package().unwrap()).unwrap();
    let doomed = doomed.join(added.welcome.as_ref().unwrap()).unwrap();

    let held_by_removed = doomed.epoch_key().unwrap();
    assert_eq!(held_by_removed.fingerprint(), added.key.fingerprint());

    let removal = founder.remove_member(1).unwrap();
    assert_ne!(
        removal.key.fingerprint(),
        held_by_removed.fingerprint(),
        "the removed member's key must not survive the rotation"
    );
    assert_eq!(founder.member_count(), 1);

    // And the key they still hold cannot open anything wrapped under the new one.
    let dek = Dek::generate().unwrap();
    let pointer = intranet_storage::new_pointer_id().unwrap();
    let rewrapped = removal.key.wrap(&pointer, &dek);
    assert!(removal.key.unwrap_dek(&pointer, &rewrapped).is_ok());
    assert!(
        held_by_removed.unwrap_dek(&pointer, &rewrapped).is_err(),
        "a key held from before the rotation must not open a post-rotation wrapping"
    );
}

#[test]
fn a_self_initiated_rotation_advances_without_membership_change() {
    // §1.3 point 6: any member may request this after a device compromise,
    // without holding any capability.
    let mut session = GroupSession::create(b"member").unwrap();
    let before = session.epoch_key().unwrap();
    let rotation = session.rotate().unwrap();

    assert_ne!(before.fingerprint(), rotation.key.fingerprint());
    assert_eq!(session.member_count(), 1, "membership is unchanged");
    assert!(rotation.welcome.is_none());
}

#[test]
fn a_member_applies_another_members_commit_and_converges() {
    let mut founder = GroupSession::create(b"founder").unwrap();
    let joiner = GroupSession::prepare_join(b"joiner").unwrap();
    let added = founder.add_member(&joiner.key_package().unwrap()).unwrap();
    let mut joined = joiner.join(added.welcome.as_ref().unwrap()).unwrap();

    // The founder rotates; the other member applies the commit.
    let rotation = founder.rotate().unwrap();
    let applied = joined.apply_commit(&rotation.commit).unwrap();

    assert_eq!(
        applied.fingerprint(),
        rotation.key.fingerprint(),
        "applying a commit must land on the same epoch key as producing it"
    );
    assert_eq!(joined.epoch(), founder.epoch());
}

#[test]
fn a_malformed_commit_is_refused() {
    let mut session = GroupSession::create(b"member").unwrap();
    assert!(session.apply_commit(b"not a commit").is_err());
}

// ---------------------------------------------------------------------------
// Retention and finality (§3.3)
// ---------------------------------------------------------------------------

/// A governance log with `rotations` rotation entries followed by `padding`
/// ordinary capability-gated actions, so finality can be driven precisely.
fn log_with(rotations: usize, padding: usize) -> (GovernanceLog, Vec<Hash>) {
    let founder = identity(1);
    let mut log = GovernanceLog::new();
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
    let mut parent = log.insert(genesis).unwrap();
    let mut rotation_refs = Vec::new();

    for i in 0..rotations {
        let entry = LogEntry::create(
            &founder,
            Some(parent),
            at(10 + i as i64),
            EntryBody::EpochRotation {
                reason: RotationReason::MemberRevoked,
                commit: Vec::new(),
            },
        );
        parent = log.insert(entry).unwrap();
        rotation_refs.push(parent);
    }

    for i in 0..padding {
        let entry = LogEntry::create(
            &founder,
            Some(parent),
            at(100 + i as i64),
            EntryBody::DefineGroup {
                group: GroupId::new(format!("pad{i}")),
                capabilities: intranet_governance::CapabilitySet::explicit([
                    Capability::ReadContent,
                ]),
            },
        );
        parent = log.insert(entry).unwrap();
    }

    (log, rotation_refs)
}

#[test]
fn a_rotation_starts_tentative_and_the_prior_key_is_retained() {
    // The core requirement: a member may use the new key immediately, but must
    // not let forward secrecy discard the one it replaced.
    let (mut log, refs) = log_with(2, 0);
    let mut keyring = EpochKeyring::new();
    keyring.record(refs[0], 1, key(1));
    keyring.record(refs[1], 2, key(2));

    log.reconcile(at(1_000));
    keyring.reconcile(&log);

    assert_eq!(keyring.status(&refs[0]), Some(RotationStatus::Tentative));
    assert_eq!(keyring.status(&refs[1]), Some(RotationStatus::Tentative));
    assert!(
        keyring.holds(&refs[0]),
        "the superseded key must be retained while its successor is tentative"
    );
    assert_eq!(keyring.current().unwrap().0, &refs[1]);
}

#[test]
fn superseded_keys_are_pruned_only_once_the_successor_is_final() {
    // Ordinary forward secrecy resumes at finality, and not one moment sooner.
    let t = Timestamp::minutes(30);
    // Enough padding that the first rotation's successor is buried past k = 10.
    let (mut log, refs) = log_with(2, 12);
    let mut keyring = EpochKeyring::new();
    keyring.record(refs[0], 1, key(1));
    keyring.record(refs[1], 2, key(2));

    // Before finality: nothing pruned.
    log.reconcile(at(t / 2));
    let early = keyring.reconcile(&log);
    assert!(early.pruned.is_empty());
    assert!(keyring.holds(&refs[0]));

    // After both thresholds: the superseded key goes.
    log.reconcile(at(t * 4));
    let late = keyring.reconcile(&log);
    assert_eq!(keyring.status(&refs[1]), Some(RotationStatus::Final));
    assert!(
        late.pruned.contains(&refs[0]),
        "a superseded key must be dropped once its successor is final"
    );
    assert!(!keyring.holds(&refs[0]));
    assert!(keyring.holds(&refs[1]));
}

#[test]
fn a_voided_rotation_drops_its_key_and_flags_a_rewelcome() {
    // The compounding case: a member tentatively applied a rotation that turns
    // out to sit on a losing branch.
    let founder = identity(1);
    let mut log = GovernanceLog::new();
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
    let root = log.insert(genesis).unwrap();

    // Losing branch: one rotation.
    let losing = LogEntry::create(
        &founder,
        Some(root),
        at(10),
        EntryBody::EpochRotation {
            reason: RotationReason::MemberRevoked,
            commit: Vec::new(),
        },
    );
    let losing_ref = log.insert(losing).unwrap();

    // Winning branch: a rotation plus more capability-gated actions.
    let winning = LogEntry::create(
        &founder,
        Some(root),
        at(11),
        EntryBody::EpochRotation {
            reason: RotationReason::MemberRevoked,
            commit: Vec::new(),
        },
    );
    let winning_ref = log.insert(winning).unwrap();
    let mut parent = winning_ref;
    for i in 0..3 {
        let entry = LogEntry::create(
            &founder,
            Some(parent),
            at(20 + i),
            EntryBody::DefineGroup {
                group: GroupId::new(format!("w{i}")),
                capabilities: intranet_governance::CapabilitySet::explicit([
                    Capability::ReadContent,
                ]),
            },
        );
        parent = log.insert(entry).unwrap();
    }

    // This member applied the losing rotation.
    let mut keyring = EpochKeyring::new();
    keyring.record(losing_ref, 1, key(1));
    assert_eq!(keyring.current().unwrap().0, &losing_ref);

    log.reconcile(at(1_000));
    let outcome = keyring.reconcile(&log);

    assert!(outcome.voided.contains(&losing_ref));
    assert!(!keyring.holds(&losing_ref), "a voided epoch never happened");
    assert!(
        outcome.needs_rewelcome,
        "this member sits on a dead branch and must be welcomed back"
    );
}

#[test]
fn a_member_on_the_canonical_branch_needs_no_rewelcome() {
    let t = Timestamp::minutes(30);
    let (mut log, refs) = log_with(1, 12);
    let mut keyring = EpochKeyring::new();
    keyring.record(refs[0], 1, key(1));

    log.reconcile(at(t * 4));
    let outcome = keyring.reconcile(&log);

    assert!(outcome.voided.is_empty());
    assert!(!outcome.needs_rewelcome);
    assert!(keyring.holds(&refs[0]));
}

#[test]
fn a_rewelcome_restores_a_member_onto_the_canonical_branch() {
    // The MLS side of recovery: a member on a dead branch is brought back by
    // being welcomed again, which is exactly what "re-welcome" names.
    let mut canonical = GroupSession::create(b"founder").unwrap();
    let stranded = GroupSession::prepare_join(b"stranded").unwrap();

    let rotation = canonical.add_member(&stranded.key_package().unwrap()).unwrap();
    let recovered = stranded.join(rotation.welcome.as_ref().unwrap()).unwrap();

    assert_eq!(
        recovered.epoch_key().unwrap().fingerprint(),
        canonical.epoch_key().unwrap().fingerprint(),
        "after a re-welcome the member holds the canonical epoch key"
    );
    assert_eq!(recovered.epoch(), canonical.epoch());
}

#[test]
fn retained_keys_still_open_content_from_the_tentative_window() {
    // Why retention matters concretely: a wrapping made under the superseded
    // epoch must stay openable while the rotation that replaced it is tentative.
    let (mut log, refs) = log_with(2, 0);
    let old = key(1);
    let new = key(2);

    let mut keyring = EpochKeyring::new();
    keyring.record(refs[0], 1, old.clone());
    keyring.record(refs[1], 2, new);

    let dek = Dek::generate().unwrap();
    let pointer = intranet_storage::new_pointer_id().unwrap();
    let wrapped_under_old = old.wrap(&pointer, &dek);

    log.reconcile(at(1_000));
    keyring.reconcile(&log);

    let retained = keyring
        .key_for(&refs[0])
        .expect("the superseded key must still be held");
    assert!(retained.unwrap_dek(&pointer, &wrapped_under_old).is_ok());
}

// ---------------------------------------------------------------------------
// History access policy (§3.4)
// ---------------------------------------------------------------------------

#[test]
fn current_epoch_forward_delivers_only_the_current_key() {
    let mut keyring = EpochKeyring::new();
    keyring.record(Hash::from_bytes([1u8; 32]), 1, key(1));
    keyring.record(Hash::from_bytes([2u8; 32]), 2, key(2));
    keyring.record(Hash::from_bytes([3u8; 32]), 3, key(3));

    let delivered = keyring.keys_for_new_member(HistoryAccess::CurrentEpochForward);
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].0, Hash::from_bytes([3u8; 32]));
}

#[test]
fn full_history_delivers_every_retained_key() {
    let mut keyring = EpochKeyring::new();
    for i in 1u8..=3 {
        keyring.record(Hash::from_bytes([i; 32]), u64::from(i), key(i));
    }

    let delivered = keyring.keys_for_new_member(HistoryAccess::FullHistory);
    assert_eq!(delivered.len(), 3);
}

#[test]
fn a_joiner_accepts_delivered_keys_and_can_read_with_them() {
    let mut publisher = EpochKeyring::new();
    let rotation = Hash::from_bytes([7u8; 32]);
    publisher.record(rotation, 1, key(9));

    let mut joiner = EpochKeyring::new();
    joiner
        .accept_delivered(publisher.keys_for_new_member(HistoryAccess::CurrentEpochForward))
        .unwrap();

    let dek = Dek::generate().unwrap();
    let pointer = intranet_storage::new_pointer_id().unwrap();
    let wrapped = key(9).wrap(&pointer, &dek);

    let held = joiner.key_for(&rotation).expect("joiner should hold the key");
    assert!(held.unwrap_dek(&pointer, &wrapped).is_ok());
}

#[test]
fn an_empty_key_delivery_is_refused() {
    // Fail-closed: a member with no keys can read nothing, and silently
    // accepting that would leave them wondering why. It is also the correct
    // state for a waiting-room node, which is why delivery happens on
    // admission rather than on join.
    let mut keyring = EpochKeyring::new();
    assert!(keyring.accept_delivered(Vec::new()).is_err());
}

// ---------------------------------------------------------------------------
// End to end: rotation is cheap (§5.2)
// ---------------------------------------------------------------------------

#[test]
fn rotation_cost_scales_with_live_objects_not_content_volume() {
    // The measurable form of the cheap-rotation claim: rotating re-wraps one
    // small record per object regardless of how much content those objects hold.
    let owner = identity(2);
    let dek = Dek::generate().unwrap();

    // A deliberately large object.
    let content = vec![7u8; 2_000_000];
    let object = encode(&content, &dek, ChunkSpec::default());
    let pointer_id = intranet_storage::new_pointer_id().unwrap();

    let before = EpochKey::from_bytes([1u8; 32]);
    let after = EpochKey::from_bytes([2u8; 32]);

    let old_wrapping = DekWrapping::create(
        &owner,
        pointer_id,
        &dek,
        &before,
        Hash::from_bytes([1u8; 32]),
    );
    let new_wrapping = DekWrapping::create(
        &owner,
        pointer_id,
        &dek,
        &after,
        Hash::from_bytes([2u8; 32]),
    );

    // Rotation touched only the key record; every chunk address is unchanged.
    let reencoded = encode(&content, &dek, ChunkSpec::default());
    assert_eq!(
        reencoded.manifest.chunks, object.manifest.chunks,
        "rotation must not move a single content address"
    );
    assert!(
        new_wrapping.wrapped_dek.len() < 128,
        "a re-wrap is a small key record, not content"
    );
    assert_ne!(old_wrapping.wrapped_dek, new_wrapping.wrapped_dek);
    assert!(object.stored_len() > 1_000_000, "the object really is large");
}

#[test]
fn an_owner_offline_during_rotation_blocks_nothing() {
    // The blackout the commitment/wrapping split eliminates, exercised through
    // a real rotation rather than in the abstract.
    let owner = identity(2);
    let bystander = identity(3);

    let mut founder_session = GroupSession::create(b"founder").unwrap();
    let first_key = founder_session.epoch_key().unwrap();
    let rotated = founder_session.rotate().unwrap();

    let dek = Dek::generate().unwrap();
    let object = encode(b"a document", &dek, ChunkSpec::default());
    let state = {
        // Minimal network in which the owner may publish text.
        let founder = identity(1);
        let genesis = LogEntry::create(
            &founder,
            None,
            at(0),
            EntryBody::Genesis {
                network: NETWORK,
                policy: NetworkPolicy::conservative_default(),
                everyone_capabilities: [Capability::ReadContent, Capability::publish("text")]
                    .into_iter()
                    .collect(),
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
                identity: owner.id(),
                action: MembershipAction::Add { via_invite: None },
            },
        ));
        intranet_governance::GovernanceState::replay(&chain).unwrap()
    };

    let pointer = MutablePointer::publish(
        &owner,
        intranet_storage::new_pointer_id().unwrap(),
        intranet_governance::ContentType::new("text"),
        object.manifest_cid(),
        dek.commitment(),
        &state,
    )
    .unwrap();

    // The owner is offline. A bystander re-wraps under the new epoch.
    let rewrap = DekWrapping::create(
        &bystander,
        pointer.pointer_id,
        &dek,
        &rotated.key,
        Hash::from_bytes([9u8; 32]),
    );

    assert!(
        rewrap.unwrap(&rotated.key, &pointer.dek_commitment).is_ok(),
        "a bystander's re-wrap must be accepted with the owner absent"
    );
    assert_ne!(first_key.fingerprint(), rotated.key.fingerprint());
}
