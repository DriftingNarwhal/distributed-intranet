//! Membership and governance — Core Protocol Spec §2.
//!
//! This crate is the network's policy engine: the thing that answers "is this
//! action currently authorized". Every other layer calls into it rather than
//! reimplementing authorization — storage's two-gate publish check, app
//! hosting's publish review, search's posting validation, and swarm serving's
//! `read-content` gate are all queries against the state this crate computes.
//!
//! # The one idea everything here follows from
//!
//! Authorization is a **computation over a replayed log**, never a query to a
//! trusted party. Any node can independently recompute a network's entire
//! current governance state — who is in which group, what each group may do,
//! what the policy is, which pointers are delisted — by replaying the log from
//! genesis and checking each entry against the rules that were in effect at that
//! point in the chain. No node ever has to trust another node's claim about the
//! current state.
//!
//! # Layout
//!
//! - [`capability`] — what may be granted, and the governance-tier tag that the
//!   `everyone` ceiling keys off as a *class* rather than a name list.
//! - [`group`] — flat groups; capabilities are held by groups, never identities.
//! - [`policy`] — per-network configuration, including the bounded-finality
//!   thresholds and the content-type allowlist.
//! - [`entry`] — the signed, hash-chained entry types, including the
//!   `ModerationEntry` that gives "delisted" a concrete record.
//! - [`state`] — the replay engine and every authorization check.
//! - [`log`] — the entry store, fork choice, bounded finality, and the mandatory
//!   voided-actions report.
//! - [`vote`] — quorum certificates, whose *existence* is the outcome of a vote.
//!
//! # Not yet implemented here
//!
//! The explicit-intake waiting room (§2.4) is deliberately absent. A waiting-room
//! record carries which invite was used and who issued it, and invites are
//! specified in §5.6 as part of discovery and transport — so the record type
//! lands with that layer rather than being invented ahead of it. The
//! [`AdmissionMode`] policy flag it keys off is implemented here.

mod capability;
mod entry;
mod error;
mod group;
mod log;
mod policy;
mod state;
mod vote;

pub mod wire;

pub use capability::{
    APPROVE_APP_PUBLISH, Capability, CapabilitySet, RECLAIM_APP_NAME, REGISTER_APP_NAME, Tier,
};
pub use entry::{
    AppName, Cascade, EntryBody, InviteProvenance, LogEntry, MembershipAction, ModerationAction,
    ModerationEntry, PointerId, RotationReason,
};
pub use error::GovernanceError;
pub use group::{EVERYONE, FOUNDERS, Group, GroupId, MembershipRecord};
pub use log::{GovernanceLog, Reconciliation, VoidedEntry};
pub use policy::{
    AdmissionMode, ContentType, FinalityParams, GovernanceModel, HistoryAccess, NetworkPolicy,
    starter_content_types,
};
pub use state::{AppNameRecord, GovernanceState};
pub use wire::{
    MAX_ENTRIES_PER_RESPONSE, SyncRequest, SyncResponse, WireError, decode_entry, encode_entry,
};
pub use vote::{Ballot, QuorumCertificate, VoteOutcome, VoteProposal};
pub use wire::{
    BallotRefusal, BallotRequest, BallotResponse, MAX_BALLOTS, MAX_BALLOTS_PER_RESPONSE,
    MAX_ELECTORATE,
};
