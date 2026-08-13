//! The governance log, fork choice, and bounded finality — Core Protocol Spec §2.7.1.
//!
//! # Why a rule is needed at all
//!
//! "Whichever entry attaches first is canonical" is not a well-defined rule in a
//! distributed system: with two concurrent entries referencing the same parent,
//! gossiped into different parts of the network, each side honestly observes its
//! own as having attached first. There is no global "first". This module
//! implements the explicit, deterministic rule that replaces it.

use crate::{EntryBody, GovernanceError, GovernanceState, LogEntry, MembershipAction};
use intranet_crypto::{Hash, Timestamp};
use intranet_identity::PerNetworkIdentityId;
use std::collections::{BTreeMap, BTreeSet};

/// An entry that exists only on a branch reconciliation discarded.
///
/// Reconciliation must produce an explicit, computable list of everything it
/// voided (§2.7.1, point 5). Without one, resubmission depends on a party
/// happening to notice — which matters most in exactly the case where noticing
/// is least likely and the consequence is worst: a **voided revocation**, where
/// someone legitimately removed on the losing branch silently becomes a full
/// member again on the winning one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoidedEntry {
    /// The voided entry's hash.
    pub hash: Hash,
    /// Who submitted it.
    pub author: PerNetworkIdentityId,
    /// When it was submitted.
    pub timestamp: Timestamp,
    /// Short label for the action that was voided.
    pub kind: &'static str,
    /// Whether losing this action re-opens a security-relevant gap.
    ///
    /// True for revocations, moderation, and rotations: each *removed* an
    /// access or a piece of content, so voiding it silently restores what was
    /// taken away. Client software is expected to watch this flag and prompt for
    /// (or automatically perform) resubmission.
    pub security_relevant: bool,
}

/// The outcome of reconciling the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reconciliation {
    /// The canonical chain, from genesis to tip.
    pub canonical: Vec<Hash>,
    /// Everything voided, in insertion-independent order.
    pub voided: Vec<VoidedEntry>,
    /// The deepest entry that has reached bounded finality, if any.
    pub finalized: Option<Hash>,
}

/// A hash-chained store of governance entries, which may contain forks.
#[derive(Debug, Clone, Default)]
pub struct GovernanceLog {
    entries: BTreeMap<Hash, LogEntry>,
    children: BTreeMap<Hash, BTreeSet<Hash>>,
    root: Option<Hash>,
    finalized: Option<Hash>,
}

impl GovernanceLog {
    /// Creates an empty log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an entry, returning its hash.
    ///
    /// Structural validation only: signature, genesis placement, and parent
    /// presence. Whether the entry was *authorized* is decided by replay
    /// ([`GovernanceState`]), because authorization depends on which branch the
    /// entry ends up on — an entry can be validly authorized on one branch and
    /// unauthorized on another, so it cannot be settled at insertion time.
    pub fn insert(&mut self, entry: LogEntry) -> Result<Hash, GovernanceError> {
        entry.verify_signature()?;
        let hash = entry.hash();

        match entry.parent {
            None => {
                if !matches!(entry.body, EntryBody::Genesis { .. }) {
                    return Err(GovernanceError::MissingParent);
                }
                if self.root.is_some_and(|root| root != hash) {
                    return Err(GovernanceError::UnexpectedGenesis);
                }
                self.root = Some(hash);
            }
            Some(parent) => {
                if !self.entries.contains_key(&parent) {
                    return Err(GovernanceError::UnknownParent {
                        parent: parent.to_string(),
                    });
                }
                self.children.entry(parent).or_default().insert(hash);
            }
        }

        self.entries.insert(hash, entry);
        Ok(hash)
    }

    /// Looks up an entry.
    pub fn get(&self, hash: &Hash) -> Option<&LogEntry> {
        self.entries.get(hash)
    }

    /// The number of entries held, across all branches.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether `hash` has reached bounded finality.
    ///
    /// True for the finalized entry itself and every ancestor of it.
    pub fn is_final(&self, hash: &Hash) -> bool {
        let Some(finalized) = self.finalized else {
            return false;
        };
        let mut cursor = Some(finalized);
        while let Some(current) = cursor {
            if current == *hash {
                return true;
            }
            cursor = self.entries.get(&current).and_then(|entry| entry.parent);
        }
        false
    }

    /// Reconciles the log, advancing finality, and reports what was voided.
    ///
    /// Takes `&mut self` because finality is a *commitment*, not a recomputation:
    /// once an entry is final it can never be displaced, so the finalized point
    /// is remembered and only ever moves forward. Recomputing it from scratch
    /// each call would let a sufficiently long branch presented later displace
    /// something already treated as settled — exactly what bounded finality
    /// exists to prevent.
    pub fn reconcile(&mut self, now: Timestamp) -> Reconciliation {
        let Some(root) = self.root else {
            return Reconciliation {
                canonical: Vec::new(),
                voided: Vec::new(),
                finalized: None,
            };
        };

        // Fork choice is constrained to branches containing the finalized entry,
        // which is what makes finality binding rather than advisory.
        let start = self.finalized.unwrap_or(root);
        let mut canonical = self.ancestry(start);
        canonical.extend(self.best_branch_below(start));

        self.advance_finality(&canonical, now);

        let on_canonical: BTreeSet<Hash> = canonical.iter().copied().collect();
        let voided = self
            .entries
            .iter()
            .filter(|(hash, _)| !on_canonical.contains(hash))
            .map(|(hash, entry)| VoidedEntry {
                hash: *hash,
                author: entry.author,
                timestamp: entry.timestamp,
                kind: entry.body.kind(),
                security_relevant: matches!(
                    entry.body,
                    EntryBody::MembershipChange {
                        action: MembershipAction::Remove { .. },
                        ..
                    } | EntryBody::Moderation(_)
                        | EntryBody::EpochRotation { .. }
                ),
            })
            .collect();

        Reconciliation {
            canonical,
            voided,
            finalized: self.finalized,
        }
    }

    /// The canonical chain without advancing finality.
    pub fn canonical_chain(&self) -> Vec<Hash> {
        let Some(root) = self.root else {
            return Vec::new();
        };
        let start = self.finalized.unwrap_or(root);
        let mut chain = self.ancestry(start);
        chain.extend(self.best_branch_below(start));
        chain
    }

    /// Replays the canonical chain into authorization state.
    pub fn replay_canonical(&self) -> Result<GovernanceState, GovernanceError> {
        let chain = self.canonical_chain();
        let entries: Vec<&LogEntry> = chain
            .iter()
            .filter_map(|hash| self.entries.get(hash))
            .collect();
        GovernanceState::replay(entries)
    }

    /// The path from the root down to `hash`, inclusive.
    fn ancestry(&self, hash: Hash) -> Vec<Hash> {
        let mut path = Vec::new();
        let mut cursor = Some(hash);
        while let Some(current) = cursor {
            path.push(current);
            cursor = self.entries.get(&current).and_then(|entry| entry.parent);
        }
        path.reverse();
        path
    }

    /// Chooses the winning branch below `node`, excluding `node` itself.
    ///
    /// Two rules, applied together (§2.7.1, points 1–2):
    ///
    /// - **More capability-gated actions wins.** Counting *only* capability-gated
    ///   actions is what closes the grinding attack: capability-free entries can
    ///   be minted freely by any member, so counting raw entries would let an
    ///   attacker pad a branch during a partition and void an unfavourable
    ///   revocation regardless of what governance actions the branch contained.
    /// - **On an equal count, the lower tip hash wins.** For a single-entry fork
    ///   the tip *is* the sibling, so this collapses to point 1's rule with no
    ///   special case needed.
    fn best_branch_below(&self, node: Hash) -> Vec<Hash> {
        let Some(children) = self.children.get(&node) else {
            return Vec::new();
        };

        let mut best: Option<(u32, Hash, Vec<Hash>)> = None;

        for &child in children {
            let sub_path = self.best_branch_below(child);
            let gated = u32::from(
                self.entries
                    .get(&child)
                    .is_some_and(LogEntry::is_capability_gated),
            );
            let count = gated
                + sub_path
                    .iter()
                    .filter(|hash| {
                        self.entries
                            .get(hash)
                            .is_some_and(LogEntry::is_capability_gated)
                    })
                    .count() as u32;

            let tip = sub_path.last().copied().unwrap_or(child);

            let mut path = vec![child];
            path.extend(sub_path);

            // Higher capability-gated count wins; ties break on the lower tip
            // hash, which every node computes identically.
            let better = match &best {
                None => true,
                Some((best_count, best_tip, _)) => {
                    (count, std::cmp::Reverse(tip)) > (*best_count, std::cmp::Reverse(*best_tip))
                }
            };
            if better {
                best = Some((count, tip, path));
            }
        }

        best.map(|(_, _, path)| path).unwrap_or_default()
    }

    /// Moves the finalized point forward along the canonical chain.
    ///
    /// An entry is final once it is buried under `k` capability-gated actions
    /// **and** is at least `T` old. Both are required, and each covers a gap the
    /// other leaves: depth alone lets a rapid burst of capability-gated actions
    /// buy finality before a competing branch could realistically surface, and
    /// age alone lets a quiet branch finalize with no meaningful confirmation.
    fn advance_finality(&mut self, canonical: &[Hash], now: Timestamp) {
        let Ok(state) = self.replay_canonical() else {
            // A chain that does not replay cleanly cannot be used to advance a
            // commitment as consequential as finality.
            return;
        };
        let params = state.policy.finality;

        let already = self
            .finalized
            .and_then(|hash| canonical.iter().position(|entry| *entry == hash));

        let mut newly_final: Option<usize> = None;

        for (index, hash) in canonical.iter().enumerate() {
            let Some(entry) = self.entries.get(hash) else {
                continue;
            };

            let depth = canonical[index + 1..]
                .iter()
                .filter(|later| {
                    self.entries
                        .get(later)
                        .is_some_and(LogEntry::is_capability_gated)
                })
                .count() as u32;

            let age = now.millis_since(entry.timestamp);

            if params.is_final(depth, age) {
                newly_final = Some(index);
            }
        }

        // Finality only ever moves forward.
        let target = match (already, newly_final) {
            (Some(current), Some(candidate)) if candidate <= current => return,
            (_, Some(candidate)) => candidate,
            (_, None) => return,
        };

        self.finalized = canonical.get(target).copied();
    }
}
