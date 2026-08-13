//! Epoch key retention and finality — Core Protocol Spec §3.3, §3.4.
//!
//! # The problem this solves
//!
//! Treating rotations as governance log entries fixes *ordering* without a
//! central Delivery Service, but creates a new difficulty. A member who has
//! processed a commit has, per MLS's own forward-secrecy contract, discarded the
//! prior epoch's secrets. If that commit later turns out to sit on a branch
//! reconciliation voids, the member has no way back to a state that can process
//! whatever commit actually turns out to be canonical.
//!
//! This was verified against the real library rather than assumed: once a commit
//! is merged, the superseded epoch key is no longer exportable from the live
//! group. Retention therefore cannot be delegated to MLS — it has to happen
//! here, by caching each epoch key as it is produced.
//!
//! # The rule
//!
//! A rotation is **tentative** until its governance log entry reaches finality
//! (buried under k = 10 capability-gated actions *and* at least T = 30 minutes
//! old — both required). During that window:
//!
//! - The member may use the new epoch key immediately, so ordinary operation is
//!   never blocked waiting for finality.
//! - The member **must retain** the superseded epoch key, rather than letting
//!   forward secrecy discard it.
//!
//! Once the rotation is final, no future reconciliation can void it, so the
//! superseded key is dropped and ordinary MLS forward-secrecy behaviour resumes.
//! This is a bounded departure from "delete immediately", scoped precisely to
//! the window bounded finality defines — not a general weakening.

use crate::EpochError;
use intranet_crypto::Hash;
use intranet_governance::{EntryBody, GovernanceLog, HistoryAccess};
use intranet_storage::EpochKey;
use std::collections::{BTreeMap, BTreeSet};

/// Whether a rotation can still be displaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationStatus {
    /// Not yet final: reconciliation could still void this rotation.
    Tentative,
    /// Final: no competing branch can displace it, so superseded keys may go.
    Final,
}

/// One epoch's key, and how it stands.
#[derive(Clone)]
pub struct EpochRecord {
    /// The governance log entry that produced this epoch.
    ///
    /// An entry hash rather than a bare counter, because two competing branches
    /// can each legitimately produce "the next epoch" with the same ordinal.
    pub rotation_ref: Hash,
    /// The MLS epoch ordinal, for diagnostics only.
    pub epoch: u64,
    /// The key itself.
    pub key: EpochKey,
    /// Whether this rotation is settled.
    pub status: RotationStatus,
}

impl std::fmt::Debug for EpochRecord {
    /// Deliberately omits the key: an epoch key is the network's content
    /// confidentiality, and should not appear in a log line by accident.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EpochRecord")
            .field("rotation_ref", &self.rotation_ref.short())
            .field("epoch", &self.epoch)
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

/// What a reconciliation pass changed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyringReconciliation {
    /// Rotations that became final.
    pub finalized: Vec<Hash>,
    /// Rotations voided because they are no longer on the canonical chain.
    pub voided: Vec<Hash>,
    /// Superseded keys dropped because their successor is now final.
    pub pruned: Vec<Hash>,
    /// Whether the canonical rotation changed, requiring a re-welcome.
    ///
    /// When true, this member applied a rotation that turned out to be on a
    /// losing branch. Its retained keys still cover everything wrapped under
    /// the epochs it held, but its MLS group now sits on a dead branch and must
    /// be brought back via a Welcome from a member on the canonical one.
    pub needs_rewelcome: bool,
}

/// A member's held epoch keys.
///
/// Deliberately implements neither `Debug` beyond the redacted record form nor
/// any serialization: these keys are the network's content confidentiality.
#[derive(Clone, Default)]
pub struct EpochKeyring {
    records: BTreeMap<Hash, EpochRecord>,
    /// Rotation order as this member applied it, oldest first.
    order: Vec<Hash>,
    canonical: Option<Hash>,
}

impl EpochKeyring {
    /// Creates an empty keyring.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a rotation this member has applied, making it canonical.
    ///
    /// Recorded as tentative: it becomes final only when its governance log
    /// entry does. The previously canonical key is **retained**, not dropped —
    /// that retention is the whole point, and dropping it here would make a
    /// later void unrecoverable.
    pub fn record(&mut self, rotation_ref: Hash, epoch: u64, key: EpochKey) {
        self.records.insert(
            rotation_ref,
            EpochRecord {
                rotation_ref,
                epoch,
                key,
                status: RotationStatus::Tentative,
            },
        );
        if !self.order.contains(&rotation_ref) {
            self.order.push(rotation_ref);
        }
        self.canonical = Some(rotation_ref);
    }

    /// The current canonical epoch key, if any.
    pub fn current(&self) -> Option<(&Hash, &EpochKey)> {
        let canonical = self.canonical.as_ref()?;
        self.records
            .get(canonical)
            .map(|record| (&record.rotation_ref, &record.key))
    }

    /// The key for a specific rotation, if still held.
    ///
    /// This is what makes an old `DekWrapping` still openable during the
    /// tentative window, and what lets a member re-wrap a stale wrapping onto
    /// the canonical rotation after a void.
    pub fn key_for(&self, rotation_ref: &Hash) -> Option<&EpochKey> {
        self.records.get(rotation_ref).map(|record| &record.key)
    }

    /// Whether a rotation is held at all.
    pub fn holds(&self, rotation_ref: &Hash) -> bool {
        self.records.contains_key(rotation_ref)
    }

    /// A rotation's current status.
    pub fn status(&self, rotation_ref: &Hash) -> Option<RotationStatus> {
        self.records.get(rotation_ref).map(|record| record.status)
    }

    /// How many keys are currently retained.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether nothing is held.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Every held rotation, oldest first.
    pub fn records(&self) -> impl Iterator<Item = &EpochRecord> {
        self.order.iter().filter_map(|hash| self.records.get(hash))
    }

    /// Reconciles held keys against the governance log.
    ///
    /// Three things happen, in an order that matters:
    ///
    /// 1. Rotations no longer on the canonical chain are **voided** and their
    ///    keys dropped — those epochs never happened, so nothing will ever be
    ///    legitimately wrapped under them again.
    /// 2. Rotations whose entries have reached finality are marked **final**.
    /// 3. Superseded keys are **pruned**, but only once the rotation that
    ///    superseded them is final. Pruning earlier would discard exactly the
    ///    material a void needs.
    pub fn reconcile(&mut self, log: &GovernanceLog) -> KeyringReconciliation {
        let mut outcome = KeyringReconciliation::default();

        // Rotation entries on the canonical chain, oldest first.
        let canonical_rotations: Vec<Hash> = log
            .canonical_chain()
            .into_iter()
            .filter(|hash| {
                log.get(hash)
                    .is_some_and(|entry| matches!(entry.body, EntryBody::EpochRotation { .. }))
            })
            .collect();
        let canonical_set: BTreeSet<Hash> = canonical_rotations.iter().copied().collect();

        // 1. Void anything the canonical chain does not contain.
        let doomed: Vec<Hash> = self
            .records
            .keys()
            .filter(|hash| !canonical_set.contains(hash))
            .copied()
            .collect();
        for hash in doomed {
            self.records.remove(&hash);
            self.order.retain(|held| *held != hash);
            outcome.voided.push(hash);
            if self.canonical == Some(hash) {
                self.canonical = None;
                outcome.needs_rewelcome = true;
            }
        }

        // 2. Mark finality.
        for record in self.records.values_mut() {
            if record.status == RotationStatus::Tentative && log.is_final(&record.rotation_ref) {
                record.status = RotationStatus::Final;
                outcome.finalized.push(record.rotation_ref);
            }
        }

        // If this member's canonical rotation was voided, adopt the newest
        // canonical rotation it still holds, so it can keep operating on
        // whatever it legitimately has while a re-welcome is arranged.
        if self.canonical.is_none() {
            self.canonical = canonical_rotations
                .iter()
                .rev()
                .find(|hash| self.records.contains_key(hash))
                .copied();
        }

        // 3. Prune superseded keys, newest-first scan so "superseded by a final
        //    rotation" is evaluated against the canonical ordering.
        let held_order: Vec<Hash> = canonical_rotations
            .iter()
            .filter(|hash| self.records.contains_key(hash))
            .copied()
            .collect();

        for window in held_order.windows(2) {
            let (older, newer) = (window[0], window[1]);
            let successor_final = self
                .records
                .get(&newer)
                .is_some_and(|record| record.status == RotationStatus::Final);
            if successor_final && self.records.remove(&older).is_some() {
                self.order.retain(|held| *held != older);
                outcome.pruned.push(older);
            }
        }

        outcome
    }

    /// The keys a joining member should receive — §3.4.
    ///
    /// This is about *new members*, and is the only genuinely configurable
    /// choice left in this area. Revocation's guarantee is unconditional and not
    /// a per-network toggle; §3.4 was renamed precisely to stop conflating the
    /// two.
    pub fn keys_for_new_member(&self, policy: HistoryAccess) -> Vec<(Hash, EpochKey)> {
        match policy {
            // The conservative default: membership means "was present for
            // this", so a joiner reads from the current epoch forward.
            HistoryAccess::CurrentEpochForward => self
                .current()
                .map(|(hash, key)| vec![(*hash, key.clone())])
                .unwrap_or_default(),
            // An archive-style community instead grants full context.
            HistoryAccess::FullHistory => self
                .records()
                .map(|record| (record.rotation_ref, record.key.clone()))
                .collect(),
        }
    }

    /// Accepts historical keys delivered at join time.
    pub fn accept_delivered(&mut self, keys: Vec<(Hash, EpochKey)>) -> Result<(), EpochError> {
        if keys.is_empty() {
            return Err(EpochError::NoKeysDelivered);
        }
        for (index, (rotation_ref, key)) in keys.into_iter().enumerate() {
            self.records.insert(
                rotation_ref,
                EpochRecord {
                    rotation_ref,
                    epoch: index as u64,
                    key,
                    status: RotationStatus::Tentative,
                },
            );
            if !self.order.contains(&rotation_ref) {
                self.order.push(rotation_ref);
            }
            self.canonical = Some(rotation_ref);
        }
        Ok(())
    }
}
