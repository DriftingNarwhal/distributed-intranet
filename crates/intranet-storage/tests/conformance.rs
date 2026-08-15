//! Storage conformance tests — Storage Spec §2, §4, §5.
//!
//! Covers the parts a review pass identified as needing dedicated regression
//! coverage: the DEK commitment/wrapping split, the same-version pointer
//! tie-break, three-part append-set validation, and the `read-content` gate.

use intranet_crypto::{Hash, Timestamp, hash_bytes};
use intranet_governance::{
    Capability, CapabilitySet, ContentType, EntryBody, GovernanceState, GroupId, LogEntry,
    MembershipAction, ModerationAction, ModerationEntry, NetworkPolicy, PointerId,
};
use intranet_identity::{MasterSeed, NetworkId, PerNetworkIdentity};
use intranet_storage::{
    AppendSetEntry, AppendSetView, ChunkSpec, Cid, Dek, DekWrapping, EpochKey, MutablePointer,
    ServingRefusal, StorageError, collection_id, encode, may_serve, new_pointer_id,
    serving::{SourceCandidate, rarest_first, select_sources},
};

const NETWORK: NetworkId = NetworkId::from_bytes([42u8; 32]);

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

/// A network where `everyone` may read and publish text, plus named members.
fn network(members: &[&PerNetworkIdentity]) -> Vec<LogEntry> {
    let founder = identity(1);
    let mut chain = vec![LogEntry::create(
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

/// Publishes a text object and returns its pointer plus the DEK.
fn publish_text(
    owner: &PerNetworkIdentity,
    body: &[u8],
    state: &GovernanceState,
) -> (MutablePointer, Dek) {
    let dek = Dek::generate().unwrap();
    let object = encode(body, &dek, ChunkSpec::default());
    let pointer = MutablePointer::publish(
        owner,
        new_pointer_id().unwrap(),
        ContentType::new("text"),
        object.manifest_cid(),
        dek.commitment(),
        state,
    )
    .expect("publishing text should be permitted");
    (pointer, dek)
}

#[test]
fn losing_the_publish_capability_freezes_an_owners_existing_pointers() {
    // §2.3, corrected. `publish:<content_type>` is a *continuing* requirement,
    // not a creation-time gate, because a creation-time-only rule cannot be
    // enforced by receiving nodes: they cannot tell a creation from an update
    // for a pointer they have never seen, so the gate is bypassed by publishing
    // a first record above version zero.
    //
    // The consequence is deliberate and worth pinning, since it is easy to
    // trigger by accident: narrowing a publish grant freezes existing content
    // owned by whoever lost it.
    let author = identity(2);
    let mut chain = network(&[&author]);
    let state = state_of(&chain);

    let (pointer, _dek) = publish_text(&author, b"first version", &state);
    let updated = pointer
        .update(&author, pointer.current_cid, &state)
        .expect("an owner holding publish:text may update");
    assert_eq!(updated.version, 1);

    // Narrow the grant: `everyone` keeps read-content but loses publish:text,
    // the routine governance action that triggers this.
    push(
        &mut chain,
        &identity(1),
        100,
        EntryBody::DefineGroup {
            group: GroupId::everyone(),
            capabilities: CapabilitySet::explicit([Capability::ReadContent]),
        },
    );
    let narrowed = state_of(&chain);

    // The existing record is untouched: still valid, still readable, still
    // servable. Only *further* versions are refused.
    assert!(pointer.verify().is_ok());
    assert!(may_serve(&author.id(), &narrowed).is_ok());

    let refused = pointer
        .update(&author, pointer.current_cid, &narrowed)
        .expect_err("an owner who lost publish:text may no longer update");
    assert!(matches!(
        refused,
        StorageError::PublishNotPermitted { .. }
    ));

    // And ownership is unaffected by the correction: passing the publish gates
    // never lets a non-owner update somebody else's pointer.
    let interloper = identity(3);
    let chain_with_interloper = network(&[&author, &interloper]);
    let permissive = state_of(&chain_with_interloper);
    assert!(matches!(
        pointer
            .update(&interloper, pointer.current_cid, &permissive)
            .expect_err("a non-owner may never update"),
        StorageError::NotPointerOwner { .. }
    ));
}

// ---------------------------------------------------------------------------
// Publish gates (§2.2, Core Protocol Spec §2.8)
// ---------------------------------------------------------------------------

#[test]
fn publishing_requires_both_gates() {
    let author = identity(2);
    let state = state_of(&network(&[&author]));
    let dek = Dek::generate().unwrap();
    let cid = encode(b"hello", &dek, ChunkSpec::default()).manifest_cid();

    // Allowed type, held capability.
    assert!(
        MutablePointer::publish(
            &author,
            new_pointer_id().unwrap(),
            ContentType::new("text"),
            cid,
            dek.commitment(),
            &state,
        )
        .is_ok()
    );

    // Allowed type, capability NOT held — the two gates are independent.
    assert!(matches!(
        MutablePointer::publish(
            &author,
            new_pointer_id().unwrap(),
            ContentType::new("app-bundle"),
            cid,
            dek.commitment(),
            &state,
        ),
        Err(StorageError::PublishNotPermitted { .. })
    ));
}

#[test]
fn a_type_off_the_allowlist_cannot_be_published_under_any_capability() {
    // The mechanism that lets a network scope itself away from app hosting
    // entirely: no capability configuration can reopen it.
    let founder = identity(1);
    let mut chain = network(&[]);

    let mut chat_only = intranet_governance::starter_content_types();
    chat_only.remove(&ContentType::new("app-bundle"));
    push(
        &mut chain,
        &founder,
        50,
        EntryBody::ContentTypePolicy {
            allowlist: chat_only,
        },
    );
    // Founders hold every capability, including publish:app-bundle.
    let state = state_of(&chain);
    assert!(state.identity_holds(&founder.id(), &Capability::publish("app-bundle")));

    let dek = Dek::generate().unwrap();
    let cid = encode(b"x", &dek, ChunkSpec::default()).manifest_cid();
    assert!(matches!(
        MutablePointer::publish(
            &founder,
            new_pointer_id().unwrap(),
            ContentType::new("app-bundle"),
            cid,
            dek.commitment(),
            &state,
        ),
        Err(StorageError::ContentTypeNotAllowed { .. })
    ));
}

// ---------------------------------------------------------------------------
// Pointer updates and version collisions (§2.2)
// ---------------------------------------------------------------------------

#[test]
fn only_the_owner_may_update_a_pointer() {
    let owner = identity(2);
    let other = identity(3);
    let state = state_of(&network(&[&owner, &other]));
    let (pointer, dek) = publish_text(&owner, b"original", &state);

    let revised = encode(b"revised", &dek, ChunkSpec::default()).manifest_cid();
    assert!(pointer.update(&owner, revised, &state).is_ok());
    assert!(matches!(
        pointer.update(&other, revised, &state),
        Err(StorageError::NotPointerOwner { .. })
    ));
}

#[test]
fn updates_carry_the_commitment_forward_and_advance_the_version() {
    let owner = identity(2);
    let state = state_of(&network(&[&owner]));
    let (pointer, dek) = publish_text(&owner, b"v0", &state);

    let next = pointer
        .update(
            &owner,
            encode(b"v1", &dek, ChunkSpec::default()).manifest_cid(),
            &state,
        )
        .unwrap();

    assert_eq!(next.version, pointer.version + 1);
    assert_eq!(
        next.dek_commitment, pointer.dek_commitment,
        "the DEK never changes across an object's life"
    );
    assert!(next.verify().is_ok());
    assert!(next.supersedes(&pointer));
}

#[test]
fn a_stale_lower_version_never_supersedes() {
    let owner = identity(2);
    let state = state_of(&network(&[&owner]));
    let (v0, dek) = publish_text(&owner, b"v0", &state);
    let v1 = v0
        .update(&owner, encode(b"v1", &dek, ChunkSpec::default()).manifest_cid(), &state)
        .unwrap();

    assert!(!v0.supersedes(&v1), "replaying an old record must not roll content back");
    assert_eq!(MutablePointer::resolve(&v0, &v1), &v1);
}

#[test]
fn same_version_collisions_resolve_by_lower_record_hash() {
    // Two publishers each building on the same prior version concurrently.
    // The tie-break is the same rule sibling governance entries use.
    let owner = identity(2);
    let state = state_of(&network(&[&owner]));
    let (v0, dek) = publish_text(&owner, b"v0", &state);

    let branch_a = v0
        .update(&owner, encode(b"branch a", &dek, ChunkSpec::default()).manifest_cid(), &state)
        .unwrap();
    let branch_b = v0
        .update(&owner, encode(b"branch b", &dek, ChunkSpec::default()).manifest_cid(), &state)
        .unwrap();

    assert_eq!(branch_a.version, branch_b.version, "a genuine collision");
    let expected = if branch_a.record_hash() <= branch_b.record_hash() {
        &branch_a
    } else {
        &branch_b
    };

    // Both arrival orders must give the same winner on every node.
    assert_eq!(MutablePointer::resolve(&branch_a, &branch_b), expected);
    assert_eq!(MutablePointer::resolve(&branch_b, &branch_a), expected);
}

#[test]
fn the_losing_record_is_retryable_at_an_incremented_version() {
    let owner = identity(2);
    let state = state_of(&network(&[&owner]));
    let (v0, dek) = publish_text(&owner, b"v0", &state);

    let a = v0
        .update(&owner, encode(b"a", &dek, ChunkSpec::default()).manifest_cid(), &state)
        .unwrap();
    let b = v0
        .update(&owner, encode(b"b", &dek, ChunkSpec::default()).manifest_cid(), &state)
        .unwrap();
    let winner = MutablePointer::resolve(&a, &b).clone();

    // The loser retries against the now-canonical record rather than merging.
    let retry = winner
        .update(&owner, encode(b"b again", &dek, ChunkSpec::default()).manifest_cid(), &state)
        .unwrap();
    assert_eq!(retry.version, winner.version + 1);
    assert!(retry.supersedes(&winner));
}

#[test]
fn tampering_with_a_pointer_breaks_its_signature() {
    let owner = identity(2);
    let state = state_of(&network(&[&owner]));
    let (pointer, dek) = publish_text(&owner, b"v0", &state);

    let mut forged = pointer.clone();
    forged.current_cid = encode(b"substituted", &dek, ChunkSpec::default()).manifest_cid();
    assert_eq!(forged.verify(), Err(StorageError::BadSignature));

    let mut bumped = pointer;
    bumped.version = 99;
    assert_eq!(bumped.verify(), Err(StorageError::BadSignature));
}

// ---------------------------------------------------------------------------
// The commitment/wrapping split (§2.2, §5.3)
// ---------------------------------------------------------------------------

#[test]
fn a_non_owner_can_produce_a_valid_wrapping() {
    // The regression test for the owner-signature contradiction. A wrapping is
    // valid because it matches the owner's commitment, not because the owner
    // signed it — which is what eliminates the owner-offline blackout.
    let owner = identity(2);
    let bystander = identity(3);
    let state = state_of(&network(&[&owner, &bystander]));
    let (pointer, dek) = publish_text(&owner, b"content", &state);

    let epoch = EpochKey::from_bytes([9u8; 32]);
    let rotation = hash_bytes(b"rotation-1");

    let wrapping = DekWrapping::create(&bystander, pointer.pointer_id, &dek, &epoch, rotation);
    let recovered = wrapping
        .unwrap(&epoch, &pointer.dek_commitment)
        .expect("a non-owner's wrapping must be accepted");

    assert_eq!(recovered.commitment(), dek.commitment());
    assert_ne!(
        wrapping.wrapper_identity, pointer.owner_identity,
        "this test is only meaningful if the wrapper is not the owner"
    );
}

#[test]
fn a_wrapping_that_does_not_match_the_commitment_is_rejected() {
    // Regardless of whose signature is on it — including the owner's.
    let owner = identity(2);
    let state = state_of(&network(&[&owner]));
    let (pointer, _) = publish_text(&owner, b"content", &state);

    let epoch = EpochKey::from_bytes([9u8; 32]);
    let wrong_dek = Dek::from_bytes([123u8; 32]);
    let wrapping = DekWrapping::create(
        &owner,
        pointer.pointer_id,
        &wrong_dek,
        &epoch,
        hash_bytes(b"rotation-1"),
    );

    // `matches!` rather than `assert_eq!` because `Dek` deliberately implements
    // no `Debug` — secret material should be awkward to print, including from a
    // failing assertion.
    assert!(matches!(
        wrapping.unwrap(&epoch, &pointer.dek_commitment),
        Err(StorageError::CommitmentMismatch)
    ));
}

#[test]
fn concurrent_rewraps_by_different_members_are_byte_identical() {
    // Redundant re-wrapping must produce no conflict to resolve, which is what
    // lets every tracking node re-wrap independently and asynchronously.
    let owner = identity(2);
    let first = identity(3);
    let second = identity(4);
    let state = state_of(&network(&[&owner, &first, &second]));
    let (pointer, dek) = publish_text(&owner, b"content", &state);

    let epoch = EpochKey::from_bytes([9u8; 32]);
    let rotation = hash_bytes(b"rotation-2");

    let a = DekWrapping::create(&first, pointer.pointer_id, &dek, &epoch, rotation);
    let b = DekWrapping::create(&second, pointer.pointer_id, &dek, &epoch, rotation);

    assert_eq!(
        a.wrapped_dek, b.wrapped_dek,
        "the wrapped bytes must be identical even though the wrappers differ"
    );
}

#[test]
fn a_forged_wrapper_signature_is_refused() {
    let owner = identity(2);
    let attacker = identity(3);
    let state = state_of(&network(&[&owner, &attacker]));
    let (pointer, dek) = publish_text(&owner, b"content", &state);

    let epoch = EpochKey::from_bytes([9u8; 32]);
    let mut wrapping = DekWrapping::create(
        &attacker,
        pointer.pointer_id,
        &dek,
        &epoch,
        hash_bytes(b"rotation-1"),
    );
    wrapping.wrapper_identity = owner.id();

    assert!(matches!(
        wrapping.unwrap(&epoch, &pointer.dek_commitment),
        Err(StorageError::BadSignature)
    ));
}

#[test]
fn rotation_is_cheap_content_and_cids_never_move() {
    // The payoff the whole envelope model exists for: rotating an epoch touches
    // a 32-byte key record and nothing else.
    let owner = identity(2);
    let state = state_of(&network(&[&owner]));
    let (pointer, dek) = publish_text(&owner, b"a reasonably sized document", &state);
    let object = encode(b"a reasonably sized document", &dek, ChunkSpec::default());

    let old_epoch = EpochKey::from_bytes([1u8; 32]);
    let new_epoch = EpochKey::from_bytes([2u8; 32]);
    let old_rotation = hash_bytes(b"rotation-1");
    let new_rotation = hash_bytes(b"rotation-2");

    let before = DekWrapping::create(&owner, pointer.pointer_id, &dek, &old_epoch, old_rotation);
    let after = DekWrapping::create(&owner, pointer.pointer_id, &dek, &new_epoch, new_rotation);

    // The pointer is untouched: same version, same CID, same commitment.
    assert_eq!(pointer.version, 0);
    assert_eq!(pointer.current_cid, object.manifest_cid());
    assert_eq!(pointer.dek_commitment, dek.commitment());

    // Only the wrapping changed, and the new one still opens the same content.
    assert_ne!(before.wrapped_dek, after.wrapped_dek);
    let recovered = after.unwrap(&new_epoch, &pointer.dek_commitment).unwrap();
    assert_eq!(recovered.commitment(), dek.commitment());
}

#[test]
fn a_revoked_member_cannot_open_a_wrapping_made_after_removal() {
    // The honest, achievable half of the revocation guarantee.
    let owner = identity(2);
    let state = state_of(&network(&[&owner]));
    let (pointer, dek) = publish_text(&owner, b"content", &state);

    let held_by_revoked = EpochKey::from_bytes([1u8; 32]);
    let post_revocation = EpochKey::from_bytes([2u8; 32]);

    let rewrapped = DekWrapping::create(
        &owner,
        pointer.pointer_id,
        &dek,
        &post_revocation,
        hash_bytes(b"rotation-after-revocation"),
    );

    assert!(
        rewrapped.unwrap(&held_by_revoked, &pointer.dek_commitment).is_err(),
        "the old epoch key must not open a wrapping made after removal"
    );
}

#[test]
fn a_wrapping_for_a_voided_rotation_is_detected_as_stale() {
    let owner = identity(2);
    let state = state_of(&network(&[&owner]));
    let (pointer, dek) = publish_text(&owner, b"content", &state);

    let epoch = EpochKey::from_bytes([1u8; 32]);
    let voided = hash_bytes(b"rotation-on-losing-branch");
    let canonical = hash_bytes(b"rotation-on-winning-branch");

    let wrapping = DekWrapping::create(&owner, pointer.pointer_id, &dek, &epoch, voided);
    assert!(wrapping.is_stale(&canonical));
    assert!(!wrapping.is_stale(&voided));
}

// ---------------------------------------------------------------------------
// Append-sets (§2.5)
// ---------------------------------------------------------------------------

#[test]
fn many_publishers_coexist_in_one_collection() {
    let a = identity(2);
    let b = identity(3);
    let c = identity(4);
    let state = state_of(&network(&[&a, &b, &c]));
    let collection = collection_id(&NETWORK, "search:rust");

    let mut view = AppendSetView::new(collection);
    for publisher in [&a, &b, &c] {
        view.insert(
            AppendSetEntry::create(publisher, collection, b"posting".to_vec(), None),
            &state,
        )
        .unwrap();
    }

    assert_eq!(view.len(), 3, "nothing is overwritten; entries coexist");
}

#[test]
fn entry_validation_requires_all_three_checks() {
    let publisher = identity(2);
    let outsider = identity(9);
    let mut chain = network(&[&publisher]);
    let state = state_of(&chain);
    let collection = collection_id(&NETWORK, "search:term");
    let pointer = PointerId::from_bytes([77u8; 32]);

    // 1. Signature.
    let mut forged = AppendSetEntry::create(&publisher, collection, b"x".to_vec(), None);
    forged.payload = b"tampered".to_vec();
    assert_eq!(forged.validate(&state), Err(StorageError::BadSignature));

    // 2. Current membership.
    let from_outsider = AppendSetEntry::create(&outsider, collection, b"x".to_vec(), None);
    assert!(matches!(
        from_outsider.validate(&state),
        Err(StorageError::PublisherNotAMember { .. })
    ));

    // 3. Referenced content not delisted — the check two review passes were
    //    needed to find, and the only one that catches a *still-current*
    //    member keeping an index entry alive for moderated content.
    let referencing = AppendSetEntry::create(&publisher, collection, b"x".to_vec(), Some(pointer));
    assert!(referencing.validate(&state).is_ok());

    push(
        &mut chain,
        &identity(1),
        200,
        EntryBody::Moderation(ModerationEntry {
            action: ModerationAction::Delist,
            target_pointer_id: pointer,
        }),
    );
    let after = state_of(&chain);

    assert!(
        matches!(
            referencing.validate(&after),
            Err(StorageError::ReferencesDelistedContent { .. })
        ),
        "the publisher's signature and membership are both still valid here"
    );
}

#[test]
fn revalidation_drops_entries_that_moderation_has_since_invalidated() {
    let publisher = identity(2);
    let mut chain = network(&[&publisher]);
    let state = state_of(&chain);
    let collection = collection_id(&NETWORK, "search:term");
    let pointer = PointerId::from_bytes([77u8; 32]);

    let mut view = AppendSetView::new(collection);
    view.insert(
        AppendSetEntry::create(&publisher, collection, b"posting".to_vec(), Some(pointer)),
        &state,
    )
    .unwrap();
    assert_eq!(view.len(), 1);

    push(
        &mut chain,
        &identity(1),
        200,
        EntryBody::Moderation(ModerationEntry {
            action: ModerationAction::Delist,
            target_pointer_id: pointer,
        }),
    );

    assert_eq!(view.revalidate(&state_of(&chain)), 1);
    assert!(
        view.is_empty(),
        "delisting must take effect without the publisher's cooperation"
    );
}

#[test]
fn relisting_restores_an_entrys_validity() {
    let publisher = identity(2);
    let mut chain = network(&[&publisher]);
    let collection = collection_id(&NETWORK, "search:term");
    let pointer = PointerId::from_bytes([77u8; 32]);
    let entry = AppendSetEntry::create(&publisher, collection, b"x".to_vec(), Some(pointer));

    push(
        &mut chain,
        &identity(1),
        200,
        EntryBody::Moderation(ModerationEntry {
            action: ModerationAction::Delist,
            target_pointer_id: pointer,
        }),
    );
    assert!(entry.validate(&state_of(&chain)).is_err());

    push(
        &mut chain,
        &identity(1),
        300,
        EntryBody::Moderation(ModerationEntry {
            action: ModerationAction::Relist,
            target_pointer_id: pointer,
        }),
    );
    assert!(entry.validate(&state_of(&chain)).is_ok());
}

#[test]
fn collections_are_scoped_per_network_and_per_name() {
    let other = NetworkId::from_bytes([43u8; 32]);
    assert_ne!(
        collection_id(&NETWORK, "app-registry"),
        collection_id(&other, "app-registry")
    );
    assert_ne!(
        collection_id(&NETWORK, "app-registry"),
        collection_id(&NETWORK, "search:rust")
    );
}

#[test]
fn an_entry_cannot_be_inserted_into_the_wrong_collection() {
    let publisher = identity(2);
    let state = state_of(&network(&[&publisher]));
    let mut view = AppendSetView::new(collection_id(&NETWORK, "a"));
    let entry = AppendSetEntry::create(
        &publisher,
        collection_id(&NETWORK, "b"),
        b"x".to_vec(),
        None,
    );
    assert_eq!(view.insert(entry, &state), Err(StorageError::WrongCollection));
}

#[test]
fn truncated_enumeration_is_visible_rather_than_silent() {
    // Consumers must be able to degrade honestly instead of assuming they saw
    // everything — the difference between a partial answer and a wrong one.
    let mut view = AppendSetView::new(collection_id(&NETWORK, "big"));
    assert!(!view.is_truncated());
    view.mark_truncated();
    assert!(view.is_truncated());
}

// ---------------------------------------------------------------------------
// Serving (§4.3, §4.4, §5.4)
// ---------------------------------------------------------------------------

#[test]
fn a_member_holding_read_content_is_served() {
    let member = identity(2);
    let state = state_of(&network(&[&member]));
    assert!(may_serve(&member.id(), &state).is_ok());
}

#[test]
fn a_waiting_room_identity_is_refused_despite_being_valid() {
    // The distinction gating on identity validity would miss: a waiting-room
    // node under explicit intake is a valid, non-revoked identity that holds no
    // group membership and therefore no read-content.
    let waiting = identity(9);
    let state = state_of(&network(&[]));

    assert!(!state.is_member(&waiting.id()), "valid identity, no membership");
    assert!(matches!(
        may_serve(&waiting.id(), &state),
        Err(ServingRefusal::NoReadContent { .. })
    ));
}

#[test]
fn a_revoked_member_stops_being_served_once_replay_converges() {
    let member = identity(2);
    let mut chain = network(&[&member]);
    assert!(may_serve(&member.id(), &state_of(&chain)).is_ok());

    push(
        &mut chain,
        &identity(1),
        500,
        EntryBody::MembershipChange {
            group: GroupId::everyone(),
            identity: member.id(),
            action: MembershipAction::Remove { cascade: None },
        },
    );

    assert!(
        may_serve(&member.id(), &state_of(&chain)).is_err(),
        "convergence, not instantaneity, is the guarantee \u{2014} but once a node \
         has replayed the revocation it must refuse"
    );
}

#[test]
fn a_network_can_withhold_read_content_from_everyone() {
    // The gate is genuinely network-configurable, not a formality.
    let founder = identity(1);
    let member = identity(2);
    let mut chain = network(&[&member]);
    push(
        &mut chain,
        &founder,
        60,
        EntryBody::DefineGroup {
            group: GroupId::everyone(),
            capabilities: CapabilitySet::explicit([Capability::publish("text")]),
        },
    );

    let state = state_of(&chain);
    assert!(state.is_member(&member.id()));
    assert!(may_serve(&member.id(), &state).is_err());
}

#[test]
fn rarest_chunks_are_fetched_first() {
    let common = Cid::from_hash(Hash::from_bytes([1u8; 32]));
    let scarce = Cid::from_hash(Hash::from_bytes([2u8; 32]));
    let middling = Cid::from_hash(Hash::from_bytes([3u8; 32]));

    assert_eq!(
        rarest_first(&[(common, 40), (scarce, 1), (middling, 7)]),
        vec![scarce, middling, common]
    );
}

#[test]
fn rarest_first_is_deterministic_on_ties() {
    let a = Cid::from_hash(Hash::from_bytes([1u8; 32]));
    let b = Cid::from_hash(Hash::from_bytes([2u8; 32]));
    assert_eq!(rarest_first(&[(b, 3), (a, 3)]), rarest_first(&[(a, 3), (b, 3)]));
}

#[test]
fn source_selection_prefers_reliable_lightly_loaded_peers() {
    use intranet_ledger::{
        BandwidthCap, CapabilityAdvertisement, CapabilityLedger, ComputeClass,
        ReliabilityObservations,
    };

    let good = identity(2);
    let busy = identity(3);
    let flaky = identity(4);
    let state = state_of(&network(&[&good, &busy, &flaky]));

    let mut ledger = CapabilityLedger::new(NETWORK);
    for node in [&good, &busy, &flaky] {
        ledger
            .insert(
                CapabilityAdvertisement::create(
                    node,
                    1_000,
                    BandwidthCap {
                        up_bytes_per_sec: 1_000_000,
                        down_bytes_per_sec: 4_000_000,
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

    let mut observations = ReliabilityObservations::new();
    for _ in 0..10 {
        observations.record_failed(flaky.id());
    }

    let candidates = vec![
        SourceCandidate {
            peer: flaky.id(),
            latency_millis: Some(1),
            current_load: 0,
        },
        SourceCandidate {
            peer: busy.id(),
            latency_millis: Some(5),
            current_load: 50,
        },
        SourceCandidate {
            peer: good.id(),
            latency_millis: Some(20),
            current_load: 1,
        },
    ];

    let chosen = select_sources(&candidates, &ledger, &observations, 0.5, 3);
    assert_eq!(
        chosen[0],
        good.id(),
        "a reliable peer outranks a fast but flaky one"
    );
    assert_eq!(chosen.last(), Some(&flaky.id()));
}

#[test]
fn a_peer_advertising_no_upload_capacity_is_not_offered_as_a_source() {
    use intranet_ledger::CapabilityLedger;

    let peer = identity(2);
    let ledger = CapabilityLedger::new(NETWORK); // no advertisement at all

    let candidates = vec![SourceCandidate {
        peer: peer.id(),
        latency_millis: Some(1),
        current_load: 0,
    }];

    assert!(
        select_sources(&candidates, &ledger, &intranet_ledger::ReliabilityObservations::new(), 0.5, 3)
            .is_empty(),
        "a node that never advertised capacity has not volunteered to serve"
    );
}
