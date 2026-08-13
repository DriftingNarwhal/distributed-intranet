//! The application name registry — App Hosting Spec §4.3–4.4.
//!
//! # Two layers, and which one is authoritative
//!
//! - **Ownership** lives in the governance log. Registering or reclaiming a name
//!   is an ordinary governance entry, resolved by replay.
//! - **Discovery** lives in a distributed append-set, purely as a best-effort
//!   index so a node can find out a name exists without walking the whole log.
//!
//! The direction matters and was corrected once: an earlier design had the
//! append-set be authoritative. Two of its properties — both correct for a
//! discovery index — are actively wrong for ownership:
//!
//! - **Ordering is self-attested.** "First registration wins by timestamp" lets
//!   a squatter backdate a claim, because nothing constrains the timestamp a
//!   submitter writes.
//! - **Liveness is TTL-based.** An entry lapses unless re-announced. For a
//!   search posting that is desirable; for a name it means a legitimate
//!   registrant whose node is merely offline loses their claim, and a squatter
//!   keeping a standing competing entry announced becomes the resolved owner by
//!   default.
//!
//! So the index may be stale, incomplete, or missing entirely, and none of that
//! affects who owns a name. Resolution always falls back to log replay.

use crate::AppError;
use intranet_crypto::{Enc, Hash, Timestamp};
use intranet_governance::{
    APPROVE_APP_PUBLISH, AppName, AppNameRecord, EntryBody, GovernanceState, LogEntry,
    NetworkPolicy, PointerId, RECLAIM_APP_NAME, REGISTER_APP_NAME, Tier,
};
use intranet_identity::{NetworkId, PerNetworkIdentity};
use intranet_storage::{AppendSetEntry, AppendSetView, collection_id};

/// Collection name for a network's app directory.
const DIRECTORY_COLLECTION: &str = "app-registry";

/// Registers this spec's capabilities in a network's policy, with their tiers.
///
/// The tier registry is what lets the `everyone` ceiling cover capabilities that
/// did not exist when the base spec was written. A network that skips this
/// cannot host apps: an unregistered extension capability has no resolvable
/// tier, so any attempt to grant or exercise it is refused rather than assumed
/// harmless.
///
/// Note the asymmetry, which is the point: claiming an unclaimed name is
/// **ordinary** and can be granted broadly, while reassigning one somebody
/// already holds is **governance-tier**. Collapsing them into a single
/// capability is what made name hijacking trivial in an earlier design.
pub fn register_capabilities(policy: &mut NetworkPolicy) {
    policy
        .extension_capabilities
        .insert(REGISTER_APP_NAME.to_string(), Tier::Ordinary);
    policy
        .extension_capabilities
        .insert(RECLAIM_APP_NAME.to_string(), Tier::Governance);
    policy
        .extension_capabilities
        .insert(APPROVE_APP_PUBLISH.to_string(), Tier::Governance);
}

/// Builds the governance entry that claims or reassigns a name.
///
/// Whether this needs `register-app-name` or `reclaim-app-name` is decided by
/// governance from replayed state at the moment it is applied, not by the
/// caller — so a client cannot select the weaker capability by mislabelling a
/// reassignment as a fresh claim.
pub fn name_registration_entry(
    registrant: &PerNetworkIdentity,
    parent: Hash,
    timestamp: Timestamp,
    name: AppName,
    app_id: PointerId,
) -> LogEntry {
    LogEntry::create(
        registrant,
        Some(parent),
        timestamp,
        EntryBody::AppNameRegistration { name, app_id },
    )
}

/// The collection key for a network's app directory.
pub fn directory_collection(network: &NetworkId) -> Hash {
    collection_id(network, DIRECTORY_COLLECTION)
}

/// What a directory entry advertises about an app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryListing {
    /// The registered name.
    pub name: AppName,
    /// The app this name points at.
    pub app_id: PointerId,
    /// Human-readable title.
    pub title: String,
    /// Human-readable description.
    pub description: String,
}

impl DirectoryListing {
    /// Encodes this listing as an append-set payload.
    pub fn to_payload(&self) -> Vec<u8> {
        let mut e = Enc::domain("intranet.app-directory-listing.v1");
        e.str(self.name.as_str())
            .fixed(self.app_id.as_bytes())
            .str(&self.title)
            .str(&self.description);
        e.finish()
    }

    /// Publishes this listing to a network's directory index.
    ///
    /// The entry references the app's pointer, so it inherits the append-set's
    /// three-part validation — including that a delisted app's listing stops
    /// being honoured without anyone having to withdraw it.
    pub fn announce(
        &self,
        publisher: &PerNetworkIdentity,
        network: &NetworkId,
    ) -> AppendSetEntry {
        AppendSetEntry::create(
            publisher,
            directory_collection(network),
            self.to_payload(),
            Some(self.app_id),
        )
    }
}

/// Resolution of a name to the app it currently points at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedName {
    /// The name resolved.
    pub name: AppName,
    /// Its authoritative record from replayed governance state.
    pub record: AppNameRecord,
    /// Whether the app it points at is currently delisted.
    ///
    /// Delisting affects whether the *app* is servable and surfaced; it does not
    /// change who owns the name. The two stay separate concerns, and a `relist`
    /// restores the app without any re-registration.
    pub delisted: bool,
}

/// Resolves a name to its current owner and target — §4.3.
///
/// Answered purely from replayed governance state. The discovery index is never
/// consulted: it is a hint about *which names exist*, never the truth about who
/// owns one, so a stale, missing, or hostile index cannot affect this answer.
pub fn resolve(name: &AppName, state: &GovernanceState) -> Option<ResolvedName> {
    state.resolve_app_name(name).map(|record| ResolvedName {
        name: name.clone(),
        record: record.clone(),
        delisted: state.is_delisted(&record.app_id),
    })
}

/// Browses a network's app directory — §4.4.
///
/// Enumerating the index is a fast path for "what exists here" that avoids
/// walking the whole governance log. Every listing it returns is then confirmed
/// against authoritative state, so a hostile or stale index can omit apps but
/// can never invent one or misattribute a name.
///
/// Returns listings paired with their authoritative resolution, and a flag for
/// whether enumeration was known to be incomplete.
pub fn browse(
    view: &AppendSetView,
    state: &GovernanceState,
) -> (Vec<(DirectoryListing, ResolvedName)>, bool) {
    let mut listings = Vec::new();

    for entry in view.entries() {
        let Some(listing) = parse_listing(&entry.payload) else {
            continue;
        };
        // The index claims this name exists; governance decides what it means.
        let Some(resolved) = resolve(&listing.name, state) else {
            continue;
        };
        // An index entry pointing somewhere other than the authoritative record
        // is discarded rather than shown: that is precisely an attempted
        // misdirection, and the log is what settles it.
        if resolved.record.app_id != listing.app_id {
            continue;
        }
        listings.push((listing, resolved));
    }

    listings.sort_by(|a, b| a.0.name.cmp(&b.0.name));
    (listings, view.is_truncated())
}

/// Parses a directory listing payload.
///
/// Rejects anything that does not consume the payload exactly, so trailing
/// bytes cannot smuggle content past a listing that otherwise looks well-formed.
pub fn parse_listing(payload: &[u8]) -> Option<DirectoryListing> {
    const TAG: &str = "intranet.app-directory-listing.v1";

    /// Reads a length-prefixed string, advancing the cursor.
    fn framed(payload: &[u8], cursor: &mut usize) -> Option<String> {
        let len_bytes = slice(payload, cursor, 8)?;
        let len = u64::from_be_bytes(len_bytes.try_into().ok()?) as usize;
        // A declared length the payload cannot back is rejected before any
        // allocation, so a hostile listing cannot drive a large one.
        String::from_utf8(slice(payload, cursor, len)?.to_vec()).ok()
    }

    fn slice<'a>(payload: &'a [u8], cursor: &mut usize, len: usize) -> Option<&'a [u8]> {
        let end = cursor.checked_add(len)?;
        let taken = payload.get(*cursor..end)?;
        *cursor = end;
        Some(taken)
    }

    let mut cursor = 0usize;
    if framed(payload, &mut cursor)? != TAG {
        return None;
    }
    let name = framed(payload, &mut cursor)?;
    let app_id: [u8; 32] = slice(payload, &mut cursor, 32)?.try_into().ok()?;
    let title = framed(payload, &mut cursor)?;
    let description = framed(payload, &mut cursor)?;

    (cursor == payload.len()).then(|| DirectoryListing {
        name: AppName::new(name),
        app_id: PointerId::from_bytes(app_id),
        title,
        description,
    })
}

/// Confirms a name is available before attempting to claim it.
///
/// Purely advisory. The authoritative check happens when the entry is applied,
/// where governance requires `reclaim-app-name` for an already-claimed name —
/// so a client racing another registrant is refused there, not here.
pub fn is_available(name: &AppName, state: &GovernanceState) -> bool {
    state.resolve_app_name(name).is_none()
}

/// Verifies that a network is configured to host apps at all.
///
/// Two independent things must hold, and neither implies the other: the
/// content-type allowlist must include `app-bundle`, and this spec's
/// capabilities must be registered so their tiers resolve.
pub fn supports_app_hosting(state: &GovernanceState) -> Result<(), AppError> {
    if !state.allows_content_type(&intranet_governance::ContentType::new("app-bundle")) {
        return Err(AppError::AppHostingNotEnabled {
            reason: "app-bundle is not on this network's content-type allowlist".into(),
        });
    }
    for capability in [REGISTER_APP_NAME, RECLAIM_APP_NAME] {
        if state.policy.extension_tier(capability).is_none() {
            return Err(AppError::AppHostingNotEnabled {
                reason: format!("capability '{capability}' is not registered in policy"),
            });
        }
    }
    Ok(())
}
