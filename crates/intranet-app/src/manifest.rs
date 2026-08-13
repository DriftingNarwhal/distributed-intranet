//! App manifests and publishing policy — App Hosting Spec §2, §3.5.

use crate::AppError;
use intranet_crypto::{Enc, Signature};
use intranet_governance::{
    APPROVE_APP_PUBLISH, Capability, ContentType, GovernanceState, PointerId,
};
use intranet_identity::{PerNetworkIdentity, PerNetworkIdentityId};

/// Domain tag for app manifest signatures.
const MANIFEST_DOMAIN: &str = "intranet.app-manifest.v1";

/// What an app asks permission to do — §2.2.
///
/// A permission-request system, declared now and enforced incrementally.
/// Anything not explicitly granted is denied, so adding a capability here does
/// not silently widen what existing apps can do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RequestedCapability {
    /// Read this app's per-user persistent storage. Supported.
    NetworkStorageRead,
    /// Write this app's per-user persistent storage. Supported.
    ///
    /// Scoped and isolated per `(app_id, visiting user)`, backed by the storage
    /// layer's primitives rather than raw browser storage.
    NetworkStorageWrite,
    /// Reach other apps or services in the same network. Declared, not enforced.
    NetworkCall,
    /// Use the real-time media transport. Declared, not enforced.
    RealtimeMedia,
}

impl RequestedCapability {
    /// Whether this build actually enforces a grant of this capability.
    ///
    /// Declared-but-unenforced capabilities are visible in a manifest so the
    /// format does not change when they become real, but a visitor must not be
    /// told an app has been granted something the platform cannot yet contain.
    pub fn is_enforced(self) -> bool {
        matches!(self, Self::NetworkStorageRead | Self::NetworkStorageWrite)
    }

    fn discriminant(self) -> u8 {
        match self {
            Self::NetworkStorageRead => 0,
            Self::NetworkStorageWrite => 1,
            Self::NetworkCall => 2,
            Self::RealtimeMedia => 3,
        }
    }
}

/// An application's manifest — §2.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppManifest {
    /// Stable identifier — this *is* the app's mutable pointer id.
    pub app_id: PointerId,
    /// Human-readable name.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Matches the underlying mutable pointer's version counter.
    pub version: u64,
    /// Path to the root HTML file within the bundle.
    pub entry_point: String,
    /// What the app is asking permission to do.
    pub requested_capabilities: Vec<RequestedCapability>,
    /// The publishing identity.
    pub publisher_identity: PerNetworkIdentityId,
    /// The publisher's signature.
    pub signature: Signature,
}

impl AppManifest {
    /// Creates and signs a manifest.
    pub fn create(
        publisher: &PerNetworkIdentity,
        app_id: PointerId,
        name: impl Into<String>,
        description: impl Into<String>,
        version: u64,
        entry_point: impl Into<String>,
        requested_capabilities: Vec<RequestedCapability>,
    ) -> Self {
        let name = name.into();
        let description = description.into();
        let entry_point = entry_point.into();
        let publisher_id = publisher.id();
        let payload = Self::payload(
            &app_id,
            &name,
            &description,
            version,
            &entry_point,
            &requested_capabilities,
            &publisher_id,
        );
        Self {
            app_id,
            name,
            description,
            version,
            entry_point,
            requested_capabilities,
            publisher_identity: publisher_id,
            signature: publisher.sign(&payload),
        }
    }

    /// Verifies the publisher's signature.
    pub fn verify(&self) -> Result<(), AppError> {
        let payload = Self::payload(
            &self.app_id,
            &self.name,
            &self.description,
            self.version,
            &self.entry_point,
            &self.requested_capabilities,
            &self.publisher_identity,
        );
        self.publisher_identity
            .verifying_key()
            .verify(&payload, &self.signature)
            .map_err(|_| AppError::BadSignature)
    }

    /// Capabilities this app requests that the platform can actually enforce.
    pub fn enforceable_capabilities(&self) -> Vec<RequestedCapability> {
        self.requested_capabilities
            .iter()
            .copied()
            .filter(|capability| capability.is_enforced())
            .collect()
    }

    #[allow(clippy::too_many_arguments)]
    fn payload(
        app_id: &PointerId,
        name: &str,
        description: &str,
        version: u64,
        entry_point: &str,
        requested: &[RequestedCapability],
        publisher: &PerNetworkIdentityId,
    ) -> Enc {
        let mut e = Enc::domain(MANIFEST_DOMAIN);
        e.fixed(app_id.as_bytes())
            .str(name)
            .str(description)
            .u64(version)
            .str(entry_point);
        e.seq(requested.iter(), |e, capability| {
            e.u8(capability.discriminant());
        });
        publisher.encode(&mut e);
        e
    }
}

/// Whether app publishes go live immediately or need review — §3.5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PublishingPolicy {
    /// Immediately live and discoverable once stored.
    ///
    /// Safety rests entirely on the reactive mechanisms: sandbox containment
    /// limits what any single run of malicious code can do, and moderation can
    /// delist it afterwards.
    #[default]
    Open,
    /// Pending until a holder of `approve-app-publish` admits it.
    ///
    /// Stored exactly as normal — nothing about chunking, replication, or the
    /// underlying storage changes — but not resolvable through the registry and
    /// not fetchable by an ordinary visitor until approved.
    Reviewed,
}

/// A published version awaiting review.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingPublish {
    /// The app.
    pub app_id: PointerId,
    /// The version awaiting approval.
    pub version: u64,
    /// Who published it.
    pub publisher: PerNetworkIdentityId,
}

/// Tracks which app versions have been approved under reviewed publishing.
///
/// # Review applies per version, not per app
///
/// Gating only an app's first publish leaves an obvious bypass: get an innocuous
/// version approved, then push a malicious update that skips review entirely.
/// Approval is therefore recorded against `(app_id, version)`, so a new version
/// is unapproved by construction rather than inheriting its predecessor's
/// standing. That adds real friction for publishers shipping frequent
/// legitimate updates, and is the right trade given a fail-closed bias.
#[derive(Debug, Clone, Default)]
pub struct ReviewQueue {
    approved: std::collections::BTreeSet<(PointerId, u64)>,
    pending: std::collections::BTreeMap<(PointerId, u64), PendingPublish>,
}

impl ReviewQueue {
    /// Creates an empty queue.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a newly published version as awaiting review.
    pub fn submit(&mut self, publish: PendingPublish) {
        self.pending
            .insert((publish.app_id, publish.version), publish);
    }

    /// Approves a pending version.
    ///
    /// Requires `approve-app-publish`, which is deliberately distinct from
    /// `moderate-content`: admitting new content and taking down live content
    /// are separate, independently grantable powers.
    pub fn approve(
        &mut self,
        app_id: PointerId,
        version: u64,
        approver: &PerNetworkIdentityId,
        state: &GovernanceState,
    ) -> Result<(), AppError> {
        if !state.identity_holds(approver, &Capability::extension(APPROVE_APP_PUBLISH)) {
            return Err(AppError::NotAuthorizedToApprove {
                identity: approver.short(),
            });
        }
        self.pending.remove(&(app_id, version));
        self.approved.insert((app_id, version));
        Ok(())
    }

    /// Versions still awaiting review, for a reviewer's queue.
    pub fn pending(&self) -> impl Iterator<Item = &PendingPublish> {
        self.pending.values()
    }

    /// Whether a version may be served to an ordinary visitor.
    ///
    /// Under `Open` everything is servable. Under `Reviewed` only explicitly
    /// approved versions are — including for an app whose previous version was
    /// approved, which is what closes the update bypass.
    pub fn is_servable(&self, app_id: PointerId, version: u64, policy: PublishingPolicy) -> bool {
        match policy {
            PublishingPolicy::Open => true,
            PublishingPolicy::Reviewed => self.approved.contains(&(app_id, version)),
        }
    }
}

/// The content type every app bundle is published under.
pub fn app_bundle_content_type() -> ContentType {
    ContentType::new("app-bundle")
}
