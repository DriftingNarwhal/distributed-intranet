//! App name registry across nodes — App Hosting Spec §4.3–4.4.
//!
//! # The split these exist to pin
//!
//! §4.3 is a correction of a correction: names were first "just write to a
//! shared key", then "use the append-set", and finally **governance log for
//! ownership, append-set for discovery only**. Both halves already propagate —
//! the log through governance sync, the directory through the append-set
//! collection protocol — so what needs testing is not that either works but that
//! the *division of labour between them* holds on a real network.
//!
//! Two failures would each be invisible in a single-node test. A directory index
//! that could establish ownership would let a squatter claim a name by
//! announcing it. And a registry that depended on the index being complete would
//! let a name silently lapse when its registrant went offline, since append-set
//! entries expire by TTL. The tests below are aimed at exactly those.

use intranet_app::{DirectoryListing, browse, name_registration_entry, resolve};
use intranet_crypto::{Hash, Timestamp};
use intranet_governance::{
    AppName, Capability, EntryBody, GroupId, LogEntry, MembershipAction,
    NetworkPolicy, PointerId,
};
use intranet_identity::{MasterSeed, NetworkId, PerNetworkIdentity};
use intranet_storage::{AppendSetEntry, AppendSetView, decode_entry, encode_entry};
use intranet_transport::{MemberNode, NodeEvent};
use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;
use std::time::Duration;

const NETWORK: NetworkId = NetworkId::from_bytes([42u8; 32]);

fn identity(n: u8) -> PerNetworkIdentity {
    MasterSeed::from_entropy([n; 32]).identity_for(&NETWORK).unwrap()
}

/// Genesis granting `everyone` read plus the ordinary registration capability.
///
/// `register-app-name` is deliberately broadly granted, as §4.3 expects for an
/// open network — which is exactly the setting in which conflating it with
/// reclaim would have made hijacking trivial.
fn genesis(founder: &PerNetworkIdentity) -> LogEntry {
    let mut policy = NetworkPolicy::conservative_default();
    intranet_app::register_capabilities(&mut policy);
    LogEntry::create(
        founder,
        None,
        Timestamp::from_millis(0),
        EntryBody::Genesis {
            network: NETWORK,
            policy,
            everyone_capabilities: [
                Capability::ReadContent,
                Capability::Extension(intranet_governance::REGISTER_APP_NAME.to_owned()),
            ]
            .into_iter()
            .collect(),
        },
    )
}

fn admit(founder: &PerNetworkIdentity, parent: Hash, who: &PerNetworkIdentity, at: i64) -> LogEntry {
    LogEntry::create(
        founder,
        Some(parent),
        Timestamp::from_millis(at),
        EntryBody::MembershipChange {
            group: GroupId::everyone(),
            identity: who.id(),
            action: MembershipAction::Add { via_invite: None },
        },
    )
}

async fn node(seed: u8) -> (MemberNode, Multiaddr) {
    let identity = identity(seed);
    let mut node = MemberNode::new(&identity).unwrap();
    node.set_dht_server_mode(true);
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

async fn settle(a: &mut MemberNode, b: &mut MemberNode, how_long: Duration) {
    let _ = drive(a, b, how_long, |_, _| false).await;
}

/// A publisher and a browser that agree on governance.
async fn pair() -> (MemberNode, MemberNode) {
    let founder = identity(1);
    let visitor = identity(2);
    let (mut publisher, _) = node(1).await;
    let (mut browser, browser_addr) = node(2).await;

    let root = publisher.append_entry(genesis(&founder)).unwrap();
    publisher
        .append_entry(admit(&founder, root, &visitor, 5))
        .unwrap();

    publisher.dial_candidates([browser_addr]).unwrap();
    assert!(
        drive(&mut publisher, &mut browser, Duration::from_secs(20), |a, b| {
            a.governance_log().len() == 2 && b.governance_log().len() == 2
        })
        .await
    );

    (publisher, browser)
}

fn listing(name: &str, app: PointerId) -> DirectoryListing {
    DirectoryListing {
        name: AppName::new(name),
        app_id: app,
        title: "Game Night Tracker".into(),
        description: "Who is bringing what".into(),
    }
}

/// Registers a name in the log and announces it to the directory index.
///
/// Both, because §4.4 says a registration is recorded in the log *and* publishes
/// a corresponding index entry — the log being what is trusted and the index
/// being what makes browsing cheap.
fn publish_app(
    node: &mut MemberNode,
    owner: &PerNetworkIdentity,
    name: &str,
    app: PointerId,
    at: i64,
) {
    let parent = *node.governance_log().canonical_chain().last().unwrap();
    let entry = name_registration_entry(
        owner,
        parent,
        Timestamp::from_millis(at),
        AppName::new(name),
        app,
    );
    node.append_entry(entry).unwrap();

    let announcement = listing(name, app).announce(owner, &NETWORK);
    node.publish_to_collection(
        announcement.collection_id,
        announcement.entry_id(),
        encode_entry(&announcement),
    );
}

/// Enumerates the directory index across the network into a view.
async fn browse_directory(
    browser: &mut MemberNode,
    other: &mut MemberNode,
    requester: &PerNetworkIdentity,
) -> AppendSetView {
    let collection = intranet_app::directory_collection(&NETWORK);
    let mut view = AppendSetView::new(collection);
    let state = browser.governance_log().replay_canonical().unwrap();

    // Start from what this node already holds. Enumeration finds *other*
    // providers, so a browser that skipped its own entries would be the one node
    // on the network unable to see what it had published — and, less obviously,
    // would let a hostile local entry escape the validation every remote entry
    // gets.
    for payload in browser.collection_entries(&collection) {
        if let Ok(entry) = decode_entry(payload) {
            let _ = view.insert(entry, &state);
        }
    }
    browser.enumerate_collection(collection);
    let _ = tokio::time::timeout(Duration::from_secs(20), async {
        let mut asked = 0usize;
        let mut answered = 0usize;
        loop {
            tokio::select! {
                event = browser.next_event() => match event {
                    NodeEvent::CollectionProviders { providers, .. } => {
                        if providers.is_empty() {
                            return;
                        }
                        asked = providers.len();
                        for peer in providers {
                            browser.request_collection(peer, collection, requester);
                        }
                    }
                    NodeEvent::CollectionEnumerated { payloads, truncated, .. } => {
                        if truncated {
                            view.mark_truncated();
                        }
                        for payload in payloads {
                            // Signature checked on decode; membership and
                            // delisting checked by `insert`, which is where
                            // §2.5's other two mandatory checks live.
                            if let Ok(entry) = decode_entry(&payload) {
                                let _ = view.insert(entry, &state);
                            }
                        }
                        answered += 1;
                        if answered >= asked {
                            return;
                        }
                    }
                    _ => {}
                },
                _ = other.next_event() => {}
            }
        }
    })
    .await;
    view
}

#[tokio::test]
async fn a_name_registered_on_one_node_resolves_on_another() {
    // Ownership travels through the governance log, which already propagates —
    // so this is really asserting that name registration is an ordinary
    // governance action and needed no registry-specific transport.
    let (mut publisher, mut browser) = pair().await;
    let founder = identity(1);
    let app = PointerId::from_bytes([7u8; 32]);

    publish_app(&mut publisher, &founder, "game-night-tracker", app, 10);
    let publisher_peer = publisher.peer_id();
    browser.sync_with(publisher_peer);
    assert!(
        drive(&mut publisher, &mut browser, Duration::from_secs(20), |_, b| {
            b.governance_log().len() == 3
        })
        .await,
        "the registration should reach the other node"
    );

    let state = browser.governance_log().replay_canonical().unwrap();
    let resolved = resolve(&AppName::new("game-night-tracker"), &state)
        .expect("the name should resolve from replayed state alone");
    assert_eq!(resolved.record.app_id, app);
    assert_eq!(resolved.record.owner, founder.id());
    assert!(!resolved.delisted);
}

#[tokio::test]
async fn the_directory_index_makes_a_published_app_browsable() {
    // §4.4's fast path: a node learns what exists without walking the log.
    let (mut publisher, mut browser) = pair().await;
    let founder = identity(1);
    let visitor = identity(2);
    let app = PointerId::from_bytes([7u8; 32]);

    publish_app(&mut publisher, &founder, "game-night-tracker", app, 10);
    let publisher_peer = publisher.peer_id();
    browser.sync_with(publisher_peer);
    assert!(
        drive(&mut publisher, &mut browser, Duration::from_secs(20), |_, b| {
            b.governance_log().len() == 3
        })
        .await
    );
    settle(&mut publisher, &mut browser, Duration::from_secs(3)).await;

    let view = browse_directory(&mut browser, &mut publisher, &visitor).await;
    let state = browser.governance_log().replay_canonical().unwrap();
    let (listings, truncated) = browse(&view, &state);

    assert!(!truncated);
    assert_eq!(listings.len(), 1, "the app should be browsable");
    assert_eq!(listings[0].0.name.as_str(), "game-night-tracker");
    assert_eq!(listings[0].0.title, "Game Night Tracker");
    assert_eq!(listings[0].1.record.app_id, app);
}

#[tokio::test]
async fn a_name_still_resolves_when_the_directory_index_is_empty() {
    // The durability property §4.3's correction exists to provide. Append-set
    // entries expire by TTL, so a registrant whose node goes offline loses its
    // index entry — and under the earlier design would have lost the *name*.
    // Ownership must survive the index vanishing entirely.
    let (mut publisher, mut browser) = pair().await;
    let founder = identity(1);
    let visitor = identity(2);
    let app = PointerId::from_bytes([7u8; 32]);

    // Register in the log, but never announce to the index at all — the same
    // observable state as an entry that expired.
    let parent = *publisher.governance_log().canonical_chain().last().unwrap();
    publisher
        .append_entry(name_registration_entry(
            &founder,
            parent,
            Timestamp::from_millis(10),
            AppName::new("game-night-tracker"),
            app,
        ))
        .unwrap();
    let publisher_peer = publisher.peer_id();
    browser.sync_with(publisher_peer);
    assert!(
        drive(&mut publisher, &mut browser, Duration::from_secs(20), |_, b| {
            b.governance_log().len() == 3
        })
        .await
    );
    settle(&mut publisher, &mut browser, Duration::from_secs(2)).await;

    let view = browse_directory(&mut browser, &mut publisher, &visitor).await;
    let state = browser.governance_log().replay_canonical().unwrap();
    assert!(
        browse(&view, &state).0.is_empty(),
        "precondition: nothing is in the discovery index"
    );

    assert!(
        resolve(&AppName::new("game-night-tracker"), &state).is_some(),
        "ownership must survive the index being empty — a registrant going \
         offline must never cost them their name"
    );
}

#[tokio::test]
async fn a_directory_entry_cannot_claim_a_name_its_publisher_does_not_own() {
    // The squatting attack §4.3's correction closes. A member in good standing,
    // holding the broadly-granted `register-app-name`, announces a directory
    // entry for a name someone else owns — pointing at their own app. The entry
    // is validly signed by a current member and references live content, so
    // §2.5's three checks all pass; only the log settles ownership.
    let (mut publisher, mut browser) = pair().await;
    let founder = identity(1);
    let squatter = identity(2);
    let real_app = PointerId::from_bytes([7u8; 32]);
    let squatted_app = PointerId::from_bytes([8u8; 32]);

    publish_app(&mut publisher, &founder, "game-night-tracker", real_app, 10);
    let publisher_peer = publisher.peer_id();
    browser.sync_with(publisher_peer);
    assert!(
        drive(&mut publisher, &mut browser, Duration::from_secs(20), |_, b| {
            b.governance_log().len() == 3
        })
        .await
    );

    // The squatter announces a competing index entry for the same name. Note it
    // is announced from the *browser's* own node, so there is no question of it
    // failing to propagate — it is already local.
    let hostile: AppendSetEntry =
        listing("game-night-tracker", squatted_app).announce(&squatter, &NETWORK);
    browser.publish_to_collection(
        hostile.collection_id,
        hostile.entry_id(),
        encode_entry(&hostile),
    );
    settle(&mut publisher, &mut browser, Duration::from_secs(3)).await;

    let view = browse_directory(&mut browser, &mut publisher, &squatter).await;
    let state = browser.governance_log().replay_canonical().unwrap();

    // The hostile entry is genuinely present in the enumerated index.
    assert!(
        view.entries().count() >= 2,
        "precondition: the hostile entry is in the index, so what follows is \
         the log overruling it rather than the entry never arriving"
    );

    let (listings, _) = browse(&view, &state);
    assert_eq!(
        listings.len(),
        1,
        "the misdirecting entry must be discarded, not shown alongside"
    );
    assert_eq!(listings[0].0.app_id, real_app);

    let resolved = resolve(&AppName::new("game-night-tracker"), &state).unwrap();
    assert_eq!(
        resolved.record.app_id, real_app,
        "resolution answers from the log, which the index cannot influence"
    );
    assert_eq!(resolved.record.owner, founder.id());
}
