//! MLS group keying — Core Protocol Spec §3.3.
//!
//! # Why MLS and not pairwise rekeying
//!
//! Pairwise rekeying costs O(n) per membership change. At this project's stated
//! target of hundreds of thousands of members, a single revocation would mean
//! individually re-keying every remaining member, which is not viable.
//! MLS/TreeKEM organises members into a tree so a rekey touches only the path
//! from the changed member to the root — around 20 nodes for a few hundred
//! thousand members rather than 200,000 operations.
//!
//! Because the epoch key only ever wraps small per-object key records, this
//! O(log n) rekey is the *entire* cost of a rotation. Content never moves.
//!
//! # Commit ordering without a Delivery Service
//!
//! Standard MLS deployments rely on a Delivery Service to impose a strict order
//! on commits — a centralized component, in tension with this project's
//! no-required-central-authority principle. Here, each rotation is simply
//! another governance log entry, so the log's existing ordering and fork-choice
//! rules do that job. This module therefore produces and consumes commits but
//! deliberately does **not** decide their order; that belongs to the log.

use crate::EpochError;
use intranet_storage::EpochKey;
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;

/// The ciphersuite this protocol uses.
///
/// X25519 and Ed25519 throughout, matching the curve the identity layer already
/// uses for per-network identities and libp2p PeerIds — one curve family across
/// the whole system rather than three.
const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// Exporter label for deriving the network epoch key from MLS group state.
///
/// Using the RFC 9420 exporter rather than reaching into MLS internals means the
/// epoch key is a proper derived secret, and changes with every commit by
/// construction.
const EXPORTER_LABEL: &str = "intranet.epoch-key.v1";

/// A member's view of the network's MLS group.
pub struct GroupSession {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
    group: MlsGroup,
}

/// The result of an operation that advances the epoch.
pub struct Rotation {
    /// The commit to append to the governance log and gossip.
    pub commit: Vec<u8>,
    /// A Welcome for any newly added member.
    pub welcome: Option<Vec<u8>>,
    /// The epoch key this rotation produced.
    pub key: EpochKey,
    /// The MLS epoch ordinal, for diagnostics.
    pub epoch: u64,
}

impl GroupSession {
    /// Creates a new network group with this member as its only occupant.
    pub fn create(identity_label: &[u8]) -> Result<Self, EpochError> {
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
            .map_err(|e| EpochError::Mls(format!("signature keypair: {e:?}")))?;
        let credential = CredentialWithKey {
            credential: BasicCredential::new(identity_label.to_vec()).into(),
            signature_key: signer.public().into(),
        };

        let group = MlsGroup::new(&provider, &signer, &Self::config(), credential.clone())
            .map_err(|e| EpochError::Mls(format!("group create: {e:?}")))?;

        Ok(Self {
            provider,
            signer,
            credential,
            group,
        })
    }

    /// Prepares a member who is not yet in any group, ready to be added.
    pub fn prepare_join(identity_label: &[u8]) -> Result<PendingMember, EpochError> {
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
            .map_err(|e| EpochError::Mls(format!("signature keypair: {e:?}")))?;
        let credential = CredentialWithKey {
            credential: BasicCredential::new(identity_label.to_vec()).into(),
            signature_key: signer.public().into(),
        };
        let bundle = KeyPackage::builder()
            .build(CIPHERSUITE, &provider, &signer, credential.clone())
            .map_err(|e| EpochError::Mls(format!("key package: {e:?}")))?;

        Ok(PendingMember {
            provider,
            signer,
            credential,
            bundle,
        })
    }

    /// The current epoch key.
    pub fn epoch_key(&self) -> Result<EpochKey, EpochError> {
        let bytes: Vec<u8> = self
            .group
            .export_secret(self.provider.crypto(), EXPORTER_LABEL, b"", 32)
            .map_err(|e| EpochError::Mls(format!("export: {e:?}")))?;
        let bytes: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| EpochError::Mls("exporter returned wrong length".into()))?;
        Ok(EpochKey::from_bytes(bytes))
    }

    /// The current MLS epoch ordinal.
    pub fn epoch(&self) -> u64 {
        self.group.epoch().as_u64()
    }

    /// How many members the group holds.
    pub fn member_count(&self) -> usize {
        self.group.members().count()
    }

    /// Adds a member, producing a commit and a Welcome.
    pub fn add_member(&mut self, key_package: &[u8]) -> Result<Rotation, EpochError> {
        let incoming = MlsMessageIn::tls_deserialize(&mut &key_package[..])
            .map_err(|e| EpochError::Mls(format!("key package decode: {e:?}")))?;
        let MlsMessageBodyIn::KeyPackage(key_package) = incoming.extract() else {
            return Err(EpochError::Mls("expected a key package".into()));
        };

        // A key package arrives from an untrusted peer, so it is validated
        // before use rather than trusted as decoded.
        let key_package = key_package
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|e| EpochError::Mls(format!("key package validation: {e:?}")))?;

        let (commit, welcome, _) = self
            .group
            .add_members(&self.provider, &self.signer, &[key_package])
            .map_err(|e| EpochError::Mls(format!("add member: {e:?}")))?;
        self.group
            .merge_pending_commit(&self.provider)
            .map_err(|e| EpochError::Mls(format!("merge: {e:?}")))?;

        Ok(Rotation {
            commit: Self::encode(&commit)?,
            welcome: Some(Self::encode(&welcome)?),
            key: self.epoch_key()?,
            epoch: self.epoch(),
        })
    }

    /// Removes a member, advancing the epoch.
    ///
    /// The removed member holds only superseded keys and cannot derive the new
    /// one, which is the cryptographic half of the revocation guarantee. The
    /// other half — that they also cannot obtain new *ciphertext* — is the
    /// `read-content` serving gate, and neither half is sufficient alone.
    pub fn remove_member(&mut self, index: u32) -> Result<Rotation, EpochError> {
        let (commit, welcome, _) = self
            .group
            .remove_members(&self.provider, &self.signer, &[LeafNodeIndex::new(index)])
            .map_err(|e| EpochError::Mls(format!("remove member: {e:?}")))?;
        self.group
            .merge_pending_commit(&self.provider)
            .map_err(|e| EpochError::Mls(format!("merge: {e:?}")))?;

        Ok(Rotation {
            commit: Self::encode(&commit)?,
            welcome: welcome.map(|w| Self::encode(&w)).transpose()?,
            key: self.epoch_key()?,
            epoch: self.epoch(),
        })
    }

    /// Rotates the epoch without changing membership.
    ///
    /// Backs the self-initiated rekey request any member may make (§1.3, point
    /// 6) after a device compromise, without holding any capability.
    pub fn rotate(&mut self) -> Result<Rotation, EpochError> {
        let bundle = self
            .group
            .self_update(&self.provider, &self.signer, LeafNodeParameters::default())
            .map_err(|e| EpochError::Mls(format!("self update: {e:?}")))?;
        let (commit, _, _) = bundle.into_contents();
        self.group
            .merge_pending_commit(&self.provider)
            .map_err(|e| EpochError::Mls(format!("merge: {e:?}")))?;

        Ok(Rotation {
            commit: Self::encode(&commit)?,
            // A self-update adds nobody, so there is never a Welcome to send.
            welcome: None,
            key: self.epoch_key()?,
            epoch: self.epoch(),
        })
    }

    /// Applies a commit produced by another member.
    pub fn apply_commit(&mut self, commit: &[u8]) -> Result<EpochKey, EpochError> {
        let incoming = MlsMessageIn::tls_deserialize(&mut &commit[..])
            .map_err(|e| EpochError::Mls(format!("commit decode: {e:?}")))?;
        let protocol = incoming
            .try_into_protocol_message()
            .map_err(|e| EpochError::Mls(format!("not a protocol message: {e:?}")))?;

        let processed = self
            .group
            .process_message(&self.provider, protocol)
            .map_err(|e| EpochError::Mls(format!("process: {e:?}")))?;

        match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                self.group
                    .merge_staged_commit(&self.provider, *staged)
                    .map_err(|e| EpochError::Mls(format!("merge staged: {e:?}")))?;
                self.epoch_key()
            }
            _ => Err(EpochError::Mls("expected a commit".into())),
        }
    }

    /// The signature label this session presents in its credential.
    pub fn identity_label(&self) -> Vec<u8> {
        self.credential.credential.serialized_content().to_vec()
    }

    fn config() -> MlsGroupCreateConfig {
        MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            // Carrying the ratchet tree in the group info means a joiner needs
            // nothing but the Welcome — no separate tree distribution channel,
            // which would be another thing to centralize.
            .use_ratchet_tree_extension(true)
            .build()
    }

    fn encode(message: &MlsMessageOut) -> Result<Vec<u8>, EpochError> {
        message
            .tls_serialize_detached()
            .map_err(|e| EpochError::Mls(format!("encode: {e:?}")))
    }
}

/// A member that has generated a key package but not yet joined a group.
pub struct PendingMember {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
    bundle: KeyPackageBundle,
}

impl PendingMember {
    /// The key package to hand to whoever will add this member.
    pub fn key_package(&self) -> Result<Vec<u8>, EpochError> {
        MlsMessageOut::from(self.bundle.key_package().clone())
            .tls_serialize_detached()
            .map_err(|e| EpochError::Mls(format!("key package encode: {e:?}")))
    }

    /// Joins the group from a Welcome.
    ///
    /// Also the **re-welcome** path: a member whose tentatively-applied rotation
    /// was voided sits on a dead branch, and is brought back onto the canonical
    /// one by being welcomed again. Its retained epoch keys cover everything it
    /// legitimately held in the meantime.
    pub fn join(self, welcome: &[u8]) -> Result<GroupSession, EpochError> {
        let incoming = MlsMessageIn::tls_deserialize(&mut &welcome[..])
            .map_err(|e| EpochError::Mls(format!("welcome decode: {e:?}")))?;
        let MlsMessageBodyIn::Welcome(welcome) = incoming.extract() else {
            return Err(EpochError::Mls("expected a welcome".into()));
        };

        let config = GroupSession::config();
        let staged = StagedWelcome::new_from_welcome(
            &self.provider,
            config.join_config(),
            welcome,
            None,
        )
        .map_err(|e| EpochError::Mls(format!("stage welcome: {e:?}")))?;

        let group = staged
            .into_group(&self.provider)
            .map_err(|e| EpochError::Mls(format!("join: {e:?}")))?;

        Ok(GroupSession {
            provider: self.provider,
            signer: self.signer,
            credential: self.credential,
            group,
        })
    }
}
