//! In-network application hosting — App Hosting Spec.
//!
//! # This layer is optional, and that is not a footnote
//!
//! Most applications built on this platform are expected to be conventionally
//! distributed native clients that use the core protocol and storage directly
//! as a networking and data backend, never touching anything here. A friend
//! group's chat client is installed once and updated like any other software;
//! its updates have nothing to do with what is published inside the networks it
//! connects to, the same way a browser's own updates are unrelated to the sites
//! it renders.
//!
//! What this document covers is the other pattern: a generic, protocol-aware
//! client rendering applications published *inside* a network, sandboxed. A
//! network opts into that by putting `app-bundle` on its content-type
//! allowlist. A network that does not cannot host apps under any capability
//! configuration — that is the mechanism for scoping a network away from app
//! hosting entirely.
//!
//! # What is implemented here
//!
//! - [`registry`] — governance-anchored name ownership, and the best-effort
//!   discovery index layered on top of it.
//! - [`manifest`] — app manifests, requested capabilities, and the
//!   open-versus-reviewed publishing policy.
//!
//! # What is not
//!
//! The **execution sandbox**. Apps run on the visitor's own machine in a
//! webview with browser-tab isolation, platform-enforced CSP, and no ambient
//! host access — that is an embedding job against a real browser engine rather
//! than protocol logic, and none of it is stubbed here. Nothing in this crate
//! will tell a caller an app is safe to run; it only settles which bytes are
//! the app and whether it is servable at all.

pub mod manifest;
pub mod registry;

pub use manifest::{
    AppManifest, PendingPublish, PublishingPolicy, RequestedCapability, ReviewQueue,
    app_bundle_content_type,
};
pub use registry::{
    DirectoryListing, ResolvedName, browse, directory_collection, is_available,
    name_registration_entry, register_capabilities, resolve, supports_app_hosting,
};

/// Errors produced by the app-hosting layer.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AppError {
    /// A signature failed to verify.
    #[error("signature verification failed")]
    BadSignature,

    /// This network is not configured to host apps.
    #[error("app hosting is not enabled on this network: {reason}")]
    AppHostingNotEnabled {
        /// Why not.
        reason: String,
    },

    /// An identity without `approve-app-publish` tried to approve a version.
    #[error("identity {identity} may not approve app publishes")]
    NotAuthorizedToApprove {
        /// The identity that tried.
        identity: String,
    },
}
