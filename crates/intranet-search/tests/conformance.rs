//! Search conformance tests — Search Spec, Harness §5.

use intranet_crypto::Timestamp;
use intranet_governance::{
    Capability, EntryBody, GovernanceState, GroupId, LogEntry, MembershipAction, ModerationAction,
    ModerationEntry, NetworkPolicy, PointerId,
};
use intranet_identity::{MasterSeed, NetworkId, PerNetworkIdentity};
use intranet_search::{
    ContentMetadata, IndexDocument, IndexableContent, LocalIndex, Posting, SearchError, Term,
    search,
};

const NETWORK: NetworkId = NetworkId::from_bytes([42u8; 32]);
const OTHER_NETWORK: NetworkId = NetworkId::from_bytes([43u8; 32]);

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

fn network_in(network: NetworkId, members: &[&PerNetworkIdentity]) -> Vec<LogEntry> {
    let founder = MasterSeed::from_entropy([1u8; 32])
        .identity_for(&network)
        .unwrap();
    let mut chain = vec![LogEntry::create(
        &founder,
        None,
        at(0),
        EntryBody::Genesis {
            network,
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

fn network(members: &[&PerNetworkIdentity]) -> Vec<LogEntry> {
    network_in(NETWORK, members)
}

fn state_of(chain: &[LogEntry]) -> GovernanceState {
    GovernanceState::replay(chain).unwrap()
}

/// Builds a posting from metadata alone, as an ordinary publish produces.
fn posting_from_metadata(
    publisher: &PerNetworkIdentity,
    pointer: PointerId,
    title: &str,
    description: &str,
) -> Posting {
    let metadata = ContentMetadata::new(title, description);
    let content = IndexableContent {
        pointer_id: pointer,
        metadata: &metadata,
        document: None,
    };
    Posting::build(publisher, &content, at(100))
}

// ---------------------------------------------------------------------------
// Indexing as a publishing side effect (§2.1, §4)
// ---------------------------------------------------------------------------

#[test]
fn every_publish_is_indexed_from_its_default_metadata_alone() {
    // No publisher action beyond publishing, and no crawler ever visits.
    let publisher = identity(2);
    let state = state_of(&network(&[&publisher]));
    let pointer = PointerId::from_bytes([7u8; 32]);

    let posting = posting_from_metadata(
        &publisher,
        pointer,
        "Replication Strategy",
        "How replicas are placed and repaired",
    );

    let mut index = LocalIndex::new(NETWORK);
    index.insert(posting, &state).unwrap();

    let results = search(&index, "replication");
    assert_eq!(results.results.len(), 1);
    assert_eq!(results.results[0].pointer_id, pointer);
}

#[test]
fn an_opt_in_index_document_adds_searchable_body_and_tags() {
    let publisher = identity(2);
    let state = state_of(&network(&[&publisher]));
    let pointer = PointerId::from_bytes([7u8; 32]);

    let metadata = ContentMetadata::new("Page", "a page");
    let document = IndexDocument::create(
        &publisher,
        pointer,
        "Page",
        vec!["rendezvous".into()],
        "the body mentions hashing and placement",
    );
    let content = IndexableContent {
        pointer_id: pointer,
        metadata: &metadata,
        document: Some(&document),
    };

    let mut index = LocalIndex::new(NETWORK);
    index
        .insert(Posting::build(&publisher, &content, at(100)), &state)
        .unwrap();

    assert_eq!(search(&index, "rendezvous").results.len(), 1, "tags searchable");
    assert_eq!(search(&index, "hashing").results.len(), 1, "body searchable");
    assert!(
        search(&index, "unmentioned").results.is_empty(),
        "only what the publisher mapped in is searchable"
    );
}

#[test]
fn content_with_no_metadata_still_publishes_and_simply_matches_nothing() {
    // Indexing must never become a gate on publishing.
    let publisher = identity(2);
    let state = state_of(&network(&[&publisher]));
    let posting = posting_from_metadata(&publisher, PointerId::from_bytes([7u8; 32]), "", "");

    let mut index = LocalIndex::new(NETWORK);
    assert!(index.insert(posting, &state).is_ok());
    assert!(search(&index, "anything").results.is_empty());
}

#[test]
fn one_posting_carries_every_term_rather_than_one_object_per_term() {
    // The efficiency shape the spec calls out: the object and its key material
    // are created once; only the lightweight announcement repeats per term.
    let publisher = identity(2);
    let posting = posting_from_metadata(
        &publisher,
        PointerId::from_bytes([7u8; 32]),
        "Rendezvous Hashing",
        "deterministic placement without coordination",
    );

    assert!(posting.terms.len() >= 5, "one object holds all its terms");
    assert_eq!(
        posting.announcements(&NETWORK).len(),
        posting.terms.len(),
        "one announcement per term, from a single object"
    );
}

#[test]
fn announcements_are_scoped_to_the_publishing_network() {
    let publisher = identity(2);
    let posting =
        posting_from_metadata(&publisher, PointerId::from_bytes([7u8; 32]), "shared", "term");

    let here = posting.announcements(&NETWORK);
    let there = posting.announcements(&OTHER_NETWORK);
    assert_eq!(here.len(), there.len());
    assert!(
        here.iter().all(|key| !there.contains(key)),
        "identical terms must produce disjoint collection keys per network"
    );
}

// ---------------------------------------------------------------------------
// Mandatory validation (§3.1, §6.1)
// ---------------------------------------------------------------------------

#[test]
fn a_forged_posting_is_rejected() {
    let publisher = identity(2);
    let state = state_of(&network(&[&publisher]));
    let mut posting =
        posting_from_metadata(&publisher, PointerId::from_bytes([7u8; 32]), "honest", "content");

    // Keyword stuffing after signing.
    posting.terms.insert(
        Term::new("unrelated"),
        intranet_search::TermStats {
            frequency: 9_999,
            best_field: intranet_search::Field::Title,
        },
    );

    let mut index = LocalIndex::new(NETWORK);
    assert_eq!(index.insert(posting, &state), Err(SearchError::BadSignature));
}

#[test]
fn a_non_members_posting_is_rejected() {
    let outsider = identity(9);
    let state = state_of(&network(&[]));
    let posting =
        posting_from_metadata(&outsider, PointerId::from_bytes([7u8; 32]), "spam", "spam");

    let mut index = LocalIndex::new(NETWORK);
    assert!(matches!(
        index.insert(posting, &state),
        Err(SearchError::Rejected(_))
    ));
}

#[test]
fn delisted_content_is_excluded_even_though_its_publisher_remains_valid() {
    // The check two review passes were needed to find, isolated: the publisher's
    // signature and membership both stay valid throughout, so only the
    // referenced content's moderation state can be doing the work.
    let publisher = identity(2);
    let mut chain = network(&[&publisher]);
    let state = state_of(&chain);
    let pointer = PointerId::from_bytes([7u8; 32]);

    let mut index = LocalIndex::new(NETWORK);
    index
        .insert(
            posting_from_metadata(&publisher, pointer, "Findable Page", "content"),
            &state,
        )
        .unwrap();
    assert_eq!(search(&index, "findable").results.len(), 1);

    push(
        &mut chain,
        &MasterSeed::from_entropy([1u8; 32]).identity_for(&NETWORK).unwrap(),
        500,
        EntryBody::Moderation(ModerationEntry {
            action: ModerationAction::Delist,
            target_pointer_id: pointer,
        }),
    );
    let after = state_of(&chain);

    assert!(
        after.is_member(&publisher.id()),
        "the publisher is still a perfectly valid current member"
    );
    assert_eq!(index.revalidate(&after), 1);
    assert!(
        search(&index, "findable").results.is_empty(),
        "delisting must take effect without the publisher's cooperation"
    );
}

#[test]
fn a_revoked_publishers_postings_fall_out_of_the_index() {
    let publisher = identity(2);
    let mut chain = network(&[&publisher]);
    let state = state_of(&chain);

    let mut index = LocalIndex::new(NETWORK);
    index
        .insert(
            posting_from_metadata(
                &publisher,
                PointerId::from_bytes([7u8; 32]),
                "Departing Member",
                "content",
            ),
            &state,
        )
        .unwrap();

    push(
        &mut chain,
        &MasterSeed::from_entropy([1u8; 32]).identity_for(&NETWORK).unwrap(),
        500,
        EntryBody::MembershipChange {
            group: GroupId::everyone(),
            identity: publisher.id(),
            action: MembershipAction::Remove { cascade: None },
        },
    );

    assert_eq!(index.revalidate(&state_of(&chain)), 1);
    assert!(index.is_empty());
}

#[test]
fn relisting_lets_content_be_indexed_again() {
    let publisher = identity(2);
    let mut chain = network(&[&publisher]);
    let pointer = PointerId::from_bytes([7u8; 32]);
    let posting = posting_from_metadata(&publisher, pointer, "Restored", "content");
    let founder = MasterSeed::from_entropy([1u8; 32]).identity_for(&NETWORK).unwrap();

    push(
        &mut chain,
        &founder,
        500,
        EntryBody::Moderation(ModerationEntry {
            action: ModerationAction::Delist,
            target_pointer_id: pointer,
        }),
    );
    let mut index = LocalIndex::new(NETWORK);
    assert!(index.insert(posting.clone(), &state_of(&chain)).is_err());

    push(
        &mut chain,
        &founder,
        600,
        EntryBody::Moderation(ModerationEntry {
            action: ModerationAction::Relist,
            target_pointer_id: pointer,
        }),
    );
    assert!(index.insert(posting, &state_of(&chain)).is_ok());
}

// ---------------------------------------------------------------------------
// Network isolation (§1, §5) — a hard invariant
// ---------------------------------------------------------------------------

#[test]
fn a_query_never_returns_results_from_another_network() {
    // Permanent by design, not a current limitation. Enforced structurally:
    // an index is scoped to one network at construction, and there is no API
    // through which a cross-network query could even be expressed.
    let here = identity(2);
    let there = MasterSeed::from_entropy([2u8; 32])
        .identity_for(&OTHER_NETWORK)
        .unwrap();

    let here_state = state_of(&network(&[&here]));
    let there_state = state_of(&network_in(OTHER_NETWORK, &[&there]));

    let mut here_index = LocalIndex::new(NETWORK);
    here_index
        .insert(
            posting_from_metadata(&here, PointerId::from_bytes([1u8; 32]), "Shared Term", "here"),
            &here_state,
        )
        .unwrap();

    let mut there_index = LocalIndex::new(OTHER_NETWORK);
    there_index
        .insert(
            posting_from_metadata(&there, PointerId::from_bytes([2u8; 32]), "Shared Term", "there"),
            &there_state,
        )
        .unwrap();

    // The same query in each network returns only that network's content.
    let from_here = search(&here_index, "shared");
    let from_there = search(&there_index, "shared");
    assert_eq!(from_here.results.len(), 1);
    assert_eq!(from_there.results.len(), 1);
    assert_ne!(from_here.results[0].pointer_id, from_there.results[0].pointer_id);
}

#[test]
fn a_posting_from_another_network_cannot_be_inserted() {
    let here = identity(2);
    let there_state = state_of(&network_in(
        OTHER_NETWORK,
        &[&MasterSeed::from_entropy([2u8; 32])
            .identity_for(&OTHER_NETWORK)
            .unwrap()],
    ));

    let mut index = LocalIndex::new(NETWORK);
    let posting =
        posting_from_metadata(&here, PointerId::from_bytes([1u8; 32]), "term", "content");

    assert_eq!(index.insert(posting, &there_state), Err(SearchError::WrongNetwork));
}

// ---------------------------------------------------------------------------
// Freshness and re-indexing (§3.2, §3.3)
// ---------------------------------------------------------------------------

#[test]
fn unrefreshed_postings_expire() {
    let publisher = identity(2);
    let state = state_of(&network(&[&publisher]));
    let mut index = LocalIndex::new(NETWORK).with_ttl(1_000);
    index
        .insert(
            posting_from_metadata(&publisher, PointerId::from_bytes([7u8; 32]), "Ephemeral", "x"),
            &state,
        )
        .unwrap();

    assert_eq!(index.expire(at(1_100)), 0, "still inside its TTL");
    assert_eq!(index.expire(at(1_101)), 1);
    assert!(index.is_empty());
}

#[test]
fn republishing_supersedes_the_previous_posting() {
    // §3.3: a re-publish is the natural trigger for re-indexing, and must
    // replace rather than accumulate.
    let publisher = identity(2);
    let state = state_of(&network(&[&publisher]));
    let pointer = PointerId::from_bytes([7u8; 32]);

    let mut index = LocalIndex::new(NETWORK);
    index
        .insert(
            posting_from_metadata(&publisher, pointer, "Original Title", "first"),
            &state,
        )
        .unwrap();
    index
        .reindex(
            posting_from_metadata(&publisher, pointer, "Revised Title", "second"),
            &state,
        )
        .unwrap();

    assert_eq!(index.len(), 1, "one posting per pointer, not two");
    assert_eq!(search(&index, "revised").results.len(), 1);
    assert!(
        search(&index, "original").results.is_empty(),
        "superseded terms must stop matching"
    );
}

// ---------------------------------------------------------------------------
// Query resolution and ranking (§5)
// ---------------------------------------------------------------------------

#[test]
fn a_title_match_outranks_a_body_only_match() {
    let publisher = identity(2);
    let state = state_of(&network(&[&publisher]));
    let titled = PointerId::from_bytes([1u8; 32]);
    let mentioned = PointerId::from_bytes([2u8; 32]);

    let mut index = LocalIndex::new(NETWORK);
    index
        .insert(
            posting_from_metadata(&publisher, titled, "Kademlia Routing", "about routing"),
            &state,
        )
        .unwrap();

    let metadata = ContentMetadata::new("Something Else", "unrelated summary");
    let document = IndexDocument::create(
        &publisher,
        mentioned,
        "Something Else",
        vec![],
        "this body happens to mention kademlia once",
    );
    index
        .insert(
            Posting::build(
                &publisher,
                &IndexableContent {
                    pointer_id: mentioned,
                    metadata: &metadata,
                    document: Some(&document),
                },
                at(100),
            ),
            &state,
        )
        .unwrap();

    let results = search(&index, "kademlia");
    assert_eq!(results.results.len(), 2);
    assert_eq!(
        results.results[0].pointer_id, titled,
        "a title match should rank above an incidental body mention"
    );
}

#[test]
fn matching_more_query_terms_ranks_higher() {
    let publisher = identity(2);
    let state = state_of(&network(&[&publisher]));
    let both = PointerId::from_bytes([1u8; 32]);
    let one = PointerId::from_bytes([2u8; 32]);

    let mut index = LocalIndex::new(NETWORK);
    index
        .insert(
            posting_from_metadata(&publisher, both, "Storage Replication", "both terms"),
            &state,
        )
        .unwrap();
    index
        .insert(
            posting_from_metadata(&publisher, one, "Storage Only", "one term"),
            &state,
        )
        .unwrap();

    let results = search(&index, "storage replication");
    assert_eq!(results.results[0].pointer_id, both);
    assert_eq!(results.results[0].matched_terms.len(), 2);
}

#[test]
fn ranking_is_deterministic_across_repeated_queries() {
    let publisher = identity(2);
    let state = state_of(&network(&[&publisher]));
    let mut index = LocalIndex::new(NETWORK);
    for i in 1u8..=5 {
        index
            .insert(
                posting_from_metadata(
                    &publisher,
                    PointerId::from_bytes([i; 32]),
                    "shared term here",
                    "identical",
                ),
                &state,
            )
            .unwrap();
    }

    let first = search(&index, "shared");
    let second = search(&index, "shared");
    assert_eq!(first, second, "a query must be reproducible");
    assert_eq!(first.results.len(), 5);
}

#[test]
fn repeating_a_query_term_does_not_inflate_its_weight() {
    let publisher = identity(2);
    let state = state_of(&network(&[&publisher]));
    let mut index = LocalIndex::new(NETWORK);
    index
        .insert(
            posting_from_metadata(&publisher, PointerId::from_bytes([1u8; 32]), "Relay", "x"),
            &state,
        )
        .unwrap();

    let once = search(&index, "relay");
    let thrice = search(&index, "relay relay relay");
    assert_eq!(once.results[0].score, thrice.results[0].score);
}

#[test]
fn an_empty_or_stop_word_only_query_returns_nothing() {
    let publisher = identity(2);
    let state = state_of(&network(&[&publisher]));
    let mut index = LocalIndex::new(NETWORK);
    index
        .insert(
            posting_from_metadata(&publisher, PointerId::from_bytes([1u8; 32]), "Content", "x"),
            &state,
        )
        .unwrap();

    assert!(search(&index, "").results.is_empty());
    assert!(search(&index, "the and of").results.is_empty());
}

#[test]
fn a_query_matching_nothing_returns_empty_rather_than_erroring() {
    let index = LocalIndex::new(NETWORK);
    let results = search(&index, "nothing here");
    assert!(results.results.is_empty());
    assert!(!results.incomplete);
}

#[test]
fn truncated_enumeration_is_reported_to_the_caller() {
    // A partial answer and a wrong one are different things, and only the first
    // is acceptable — but only if the caller can tell which it got.
    let publisher = identity(2);
    let state = state_of(&network(&[&publisher]));
    let mut index = LocalIndex::new(NETWORK);
    index
        .insert(
            posting_from_metadata(&publisher, PointerId::from_bytes([1u8; 32]), "Popular", "x"),
            &state,
        )
        .unwrap();

    assert!(!search(&index, "popular").incomplete);
    index.mark_truncated(Term::new("popular"));
    assert!(
        search(&index, "popular").incomplete,
        "an incomplete enumeration must be visible, not silently partial"
    );
}

#[test]
fn queries_tokenise_the_same_way_publishes_do() {
    // If these diverged, a published term would silently become unqueryable.
    let publisher = identity(2);
    let state = state_of(&network(&[&publisher]));
    let mut index = LocalIndex::new(NETWORK);
    index
        .insert(
            posting_from_metadata(
                &publisher,
                PointerId::from_bytes([1u8; 32]),
                "Distributed Networks",
                "",
            ),
            &state,
        )
        .unwrap();

    for query in ["networks", "NETWORK", "Network", "  network!  "] {
        assert_eq!(
            search(&index, query).results.len(),
            1,
            "query '{query}' should match"
        );
    }
}
