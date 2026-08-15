//! Mutable pointers and DEK wrappings — Storage Spec §2.
//!
//! # The split that makes re-wrapping possible
//!
//! An earlier design put the wrapped DEK inside the owner-signed pointer record
//! *and* said any current member could re-wrap. Those contradict: a non-owner
//! cannot produce a valid signature over a field attributed to the owner, so
//! honest nodes would have had to reject every non-owner re-wrap — silently
//! reintroducing exactly the owner-offline blackout the design exists to avoid.
//!
//! The fix is not to weaken who may re-wrap, but to move the wrapping out of the
//! signed record:
//!
//! - The owner signs a **commitment** to the DEK once, at creation, and never
//!   signs anything DEK-related again.
//! - A [`DekWrapping`] lives outside that record and is valid whenever unwrapping
//!   it produces a value matching the commitment — a check anyone can perform,
//!   regardless of who published the wrapping.
//!
//! A re-wrapper never asserts the owner's authority over the pointer. It only
//! demonstrates it correctly wrapped the DEK the owner already committed to.

use crate::{Cid, Dek, EpochKey, StorageError};
use intranet_crypto::{Enc, Hash, Signature, hash_bytes, random_bytes};
use intranet_governance::{Capability, ContentType, GovernanceState, PointerId};
use intranet_identity::{PerNetworkIdentity, PerNetworkIdentityId};

/// Domain tag for mutable pointer signatures.
const POINTER_DOMAIN: &str = "intranet.mutable-pointer.v1";

/// Domain tag for DEK wrapping signatures.
const WRAPPING_DOMAIN: &str = "intranet.dek-wrapping.v1";

/// Generates a fresh pointer identifier.
pub fn new_pointer_id() -> Result<PointerId, StorageError> {
    let mut bytes = [0u8; 32];
    random_bytes(&mut bytes).map_err(|_| StorageError::Entropy)?;
    Ok(PointerId::from_bytes(bytes))
}

/// A stable, updatable address for content that changes over time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutablePointer {
    /// Stable identifier, chosen at creation, never changes.
    pub pointer_id: PointerId,
    /// The identity authorized to update this pointer.
    pub owner_identity: PerNetworkIdentityId,
    /// Declared content type, checked against the network's allowlist.
    pub content_type: ContentType,
    /// What this pointer currently resolves to — an object's manifest.
    pub current_cid: Cid,
    /// Commitment to this object's DEK, carried forward unchanged forever.
    pub dek_commitment: Hash,
    /// Monotonically increasing version.
    pub version: u64,
    /// The owner's signature over everything above.
    pub signature: Signature,
}

impl MutablePointer {
    /// Creates the first version of a pointer, enforcing both publish gates.
    ///
    /// The two gates answer different questions and both must pass (§2.2, Core
    /// Protocol Spec §2.8): the allowlist governs whether this type may exist on
    /// this network at all, and `publish:<content_type>` governs whether *this*
    /// identity is one of those permitted to create it. A type being allowed
    /// grants nobody permission to publish it.
    pub fn publish(
        owner: &PerNetworkIdentity,
        pointer_id: PointerId,
        content_type: ContentType,
        current_cid: Cid,
        dek_commitment: Hash,
        state: &GovernanceState,
    ) -> Result<Self, StorageError> {
        Self::check_publish_gates(&owner.id(), &content_type, state)?;
        Ok(Self::sign(
            owner,
            pointer_id,
            content_type,
            current_cid,
            dek_commitment,
            0,
        ))
    }

    /// Publishes a new version of an existing pointer.
    ///
    /// `dek_commitment` is carried forward unchanged: the DEK never changes
    /// across an object's life, only its wrapping does, and that lives outside
    /// this record entirely.
    ///
    /// Only `owner_identity` may do this, and **both publish gates are
    /// re-checked** — §2.3, corrected.
    ///
    /// An earlier reading had `publish:<content_type>` as a creation-time gate
    /// only, on the grounds that ownership governs updates. §2.2 says otherwise
    /// ("every publish, including updates"), and §2.2 is the version that can
    /// actually be enforced: a receiving node cannot tell a creation from an
    /// update for a pointer it has never seen, so a creation-time-only rule is
    /// bypassed by publishing a first record at a version above zero, and the
    /// repair — check when no prior record is held — makes two honest nodes
    /// disagree about the same record depending on what each had seen.
    ///
    /// Checking here as well as at the receiver is what keeps the two sides
    /// agreeing. Without it an owner could build an update locally that every
    /// peer refuses, and the failure would surface as unexplained
    /// non-propagation rather than as a refusal at the point of the action.
    ///
    /// The consequence is worth knowing: losing `publish:<content_type>` freezes
    /// the pointers you own of that type. They stay published, readable and
    /// servable — only further versions are refused.
    pub fn update(
        &self,
        owner: &PerNetworkIdentity,
        current_cid: Cid,
        state: &GovernanceState,
    ) -> Result<Self, StorageError> {
        if owner.id() != self.owner_identity {
            return Err(StorageError::NotPointerOwner {
                owner: self.owner_identity.short(),
                attempted_by: owner.id().short(),
            });
        }
        // Both gates, against *current* state: a network may have narrowed its
        // allowlist or the owner's grant since this pointer was created, and an
        // existing pointer must not be a way to keep publishing past either.
        Self::check_publish_gates(&owner.id(), &self.content_type, state)?;

        Ok(Self::sign(
            owner,
            self.pointer_id,
            self.content_type.clone(),
            current_cid,
            self.dek_commitment,
            self.version + 1,
        ))
    }

    /// Verifies the owner's signature.
    pub fn verify(&self) -> Result<(), StorageError> {
        let payload = Self::payload(
            &self.pointer_id,
            &self.owner_identity,
            &self.content_type,
            &self.current_cid,
            &self.dek_commitment,
            self.version,
        );
        self.owner_identity
            .verifying_key()
            .verify(&payload, &self.signature)
            .map_err(|_| StorageError::BadSignature)
    }

    /// This record's hash — its identity, and the collision tie-break key.
    pub fn record_hash(&self) -> Hash {
        let mut e = Self::payload(
            &self.pointer_id,
            &self.owner_identity,
            &self.content_type,
            &self.current_cid,
            &self.dek_commitment,
            self.version,
        );
        e.fixed(self.signature.as_bytes());
        hash_bytes(&e.finish())
    }

    /// Decides which of two competing records for one pointer is canonical.
    ///
    /// Higher version wins outright — that is the ordinary case, and rejecting a
    /// lower version is what stops a stale record being replayed to roll content
    /// back.
    ///
    /// When two valid records claim the **same** version — two publishers each
    /// building on the same prior version concurrently, neither having seen the
    /// other — the **lower record hash wins**, exactly as for sibling governance
    /// log entries. No timestamps to backdate, no negotiation, and any node
    /// holding both computes the same answer.
    ///
    /// This settles *which record is canonical* only. It supplies no
    /// content-merge semantics: what two concurrent edits mean together is
    /// deliberately left to the application layer.
    pub fn resolve<'a>(a: &'a Self, b: &'a Self) -> &'a Self {
        match a.version.cmp(&b.version) {
            std::cmp::Ordering::Greater => a,
            std::cmp::Ordering::Less => b,
            std::cmp::Ordering::Equal => {
                if a.record_hash() <= b.record_hash() {
                    a
                } else {
                    b
                }
            }
        }
    }

    /// Whether this record supersedes `current`.
    pub fn supersedes(&self, current: &Self) -> bool {
        std::ptr::eq(Self::resolve(self, current), self) && self != current
    }

    fn check_publish_gates(
        publisher: &PerNetworkIdentityId,
        content_type: &ContentType,
        state: &GovernanceState,
    ) -> Result<(), StorageError> {
        if !state.allows_content_type(content_type) {
            return Err(StorageError::ContentTypeNotAllowed {
                content_type: content_type.to_string(),
            });
        }
        if !state.identity_holds(publisher, &Capability::Publish(content_type.clone())) {
            return Err(StorageError::PublishNotPermitted {
                identity: publisher.short(),
                content_type: content_type.to_string(),
            });
        }
        Ok(())
    }

    fn sign(
        owner: &PerNetworkIdentity,
        pointer_id: PointerId,
        content_type: ContentType,
        current_cid: Cid,
        dek_commitment: Hash,
        version: u64,
    ) -> Self {
        let owner_id = owner.id();
        let payload = Self::payload(
            &pointer_id,
            &owner_id,
            &content_type,
            &current_cid,
            &dek_commitment,
            version,
        );
        Self {
            pointer_id,
            owner_identity: owner_id,
            content_type,
            current_cid,
            dek_commitment,
            version,
            signature: owner.sign(&payload),
        }
    }

    fn payload(
        pointer_id: &PointerId,
        owner: &PerNetworkIdentityId,
        content_type: &ContentType,
        current_cid: &Cid,
        dek_commitment: &Hash,
        version: u64,
    ) -> Enc {
        let mut e = Enc::domain(POINTER_DOMAIN);
        e.fixed(pointer_id.as_bytes());
        owner.encode(&mut e);
        e.str(content_type.as_str())
            .fixed(current_cid.hash().as_bytes())
            .fixed(dek_commitment.as_bytes())
            .u64(version);
        e
    }
}

/// A freely-republishable wrapping of an object's DEK.
///
/// Deliberately **not** part of the owner-signed pointer record. Publishing one
/// never increments the pointer's version, because there is nothing for
/// concurrent re-wraps to collide on — which is exactly the point of the split.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DekWrapping {
    /// Which object this wrapping is for.
    pub pointer_id: PointerId,
    /// The DEK, wrapped under a specific rotation's epoch key.
    pub wrapped_dek: Vec<u8>,
    /// The governance log entry hash that produced the epoch this is wrapped under.
    ///
    /// An entry hash, not a bare epoch counter. Two competing branches can each
    /// legitimately produce "the next epoch" with the same ordinal, and a
    /// counter cannot say which rotation a wrapping belongs to. Referencing the
    /// entry directly also makes post-reconciliation cleanup well-defined: a
    /// node can tell whether a wrapping's rotation is still canonical.
    pub rotation_ref: Hash,
    /// Who produced this wrapping.
    ///
    /// Recorded for accountability and anti-spam only. It is emphatically **not**
    /// what makes a wrapping valid — see [`unwrap`](Self::unwrap).
    pub wrapper_identity: PerNetworkIdentityId,
    /// The wrapper's signature.
    pub signature: Signature,
}

impl DekWrapping {
    /// Produces a wrapping of `dek` under the current epoch.
    ///
    /// Any current member may call this for any object it is tracking. The
    /// caller need not be the owner, and multiple members doing this
    /// concurrently for the same object under the same rotation produce
    /// byte-identical records.
    pub fn create(
        wrapper: &PerNetworkIdentity,
        pointer_id: PointerId,
        dek: &Dek,
        epoch_key: &EpochKey,
        rotation_ref: Hash,
    ) -> Self {
        let wrapped_dek = epoch_key.wrap(&pointer_id, dek);
        let wrapper_id = wrapper.id();
        let payload = Self::payload(&pointer_id, &wrapped_dek, &rotation_ref, &wrapper_id);
        Self {
            pointer_id,
            wrapped_dek,
            rotation_ref,
            wrapper_identity: wrapper_id,
            signature: wrapper.sign(&payload),
        }
    }

    /// Recovers the DEK, validating against the owner's commitment.
    ///
    /// **Validity comes from matching the commitment, not from who signed.** A
    /// wrapping produced by any current member is as valid as one produced by
    /// the owner, provided it unwraps to the committed DEK. This is what makes
    /// "any current member can re-wrap" true rather than contradictory.
    ///
    /// The wrapper's signature is verified too, but only for accountability: an
    /// unsigned or forged wrapping is refused so that spam has an attributable
    /// author, not because signing is what confers validity.
    pub fn unwrap(
        &self,
        epoch_key: &EpochKey,
        dek_commitment: &Hash,
    ) -> Result<Dek, StorageError> {
        self.verify_signature()?;

        let dek = epoch_key.unwrap_dek(&self.pointer_id, &self.wrapped_dek)?;
        if dek.commitment() != *dek_commitment {
            return Err(StorageError::CommitmentMismatch);
        }
        Ok(dek)
    }

    /// Verifies the wrapper's signature.
    pub fn verify_signature(&self) -> Result<(), StorageError> {
        let payload = Self::payload(
            &self.pointer_id,
            &self.wrapped_dek,
            &self.rotation_ref,
            &self.wrapper_identity,
        );
        self.wrapper_identity
            .verifying_key()
            .verify(&payload, &self.signature)
            .map_err(|_| StorageError::BadSignature)
    }

    /// Whether this wrapping references a rotation that is no longer canonical.
    ///
    /// Cleanup after a voided branch is a natural extension of ordinary
    /// re-wrapping rather than a new mechanism: a node seeing a stale
    /// `rotation_ref` simply produces a fresh wrapping against whatever rotation
    /// actually is canonical. Members who held the voided rotation's key retain
    /// what they need to do so, since reconciliation voids log entries, not key
    /// material already derived from them.
    pub fn is_stale(&self, canonical_rotation: &Hash) -> bool {
        self.rotation_ref != *canonical_rotation
    }

    fn payload(
        pointer_id: &PointerId,
        wrapped_dek: &[u8],
        rotation_ref: &Hash,
        wrapper: &PerNetworkIdentityId,
    ) -> Enc {
        let mut e = Enc::domain(WRAPPING_DOMAIN);
        e.fixed(pointer_id.as_bytes())
            .bytes(wrapped_dek)
            .fixed(rotation_ref.as_bytes());
        wrapper.encode(&mut e);
        e
    }
}
