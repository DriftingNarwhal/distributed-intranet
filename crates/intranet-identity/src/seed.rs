//! Seeds and deterministic per-network key derivation — Core Protocol Spec §1.1–1.3.

use crate::{IdentityError, NetworkId};
use intranet_crypto::{CryptoError, Enc, SecretKey, Signature, VerifyingKey, hash_bytes, to_hex};

/// Domain-separation tag for derivation-path computation.
const DERIVE_DOMAIN: &str = "intranet.derive.v1";

/// Purpose label for a master identity's per-network key.
const PURPOSE_IDENTITY: &str = "identity";

/// Purpose label for a device's per-network key.
const PURPOSE_DEVICE: &str = "device";

/// Computes a SLIP-0010 derivation path from a network ID and a purpose label.
///
/// SLIP-0010 over Ed25519 takes a path of `u32` indices, but the protocol's
/// derivation input is `(seed, network_id, purpose)` where `network_id` is 32
/// bytes — far wider than one index. The 32-byte input is therefore hashed and
/// folded into four indices, which preserves the two properties §1.2 actually
/// requires: determinism (same inputs always yield the same path) and
/// unlinkability (two network IDs produce unrelated paths, so the resulting keys
/// reveal nothing about sharing a master seed).
///
/// Indices are masked to 31 bits because Ed25519 SLIP-0010 supports only
/// hardened derivation; the high bit is the hardening flag and is applied by the
/// derivation library, so leaving it set here would overflow into a different
/// index than intended.
fn derivation_path(network: &NetworkId, purpose: &str) -> [u32; 4] {
    let mut e = Enc::domain(DERIVE_DOMAIN);
    network.encode(&mut e);
    e.str(purpose);
    let digest = hash_bytes(&e.finish());
    let bytes = digest.as_bytes();

    let mut path = [0u32; 4];
    for (i, slot) in path.iter_mut().enumerate() {
        let chunk: [u8; 4] = bytes[i * 4..i * 4 + 4].try_into().expect("4-byte chunk");
        *slot = u32::from_be_bytes(chunk) & 0x7fff_ffff;
    }
    path
}

/// Derives 32 bytes of Ed25519 key material from a seed, network, and purpose.
fn derive_key_bytes(expanded_seed: &[u8; 64], network: &NetworkId, purpose: &str) -> [u8; 32] {
    let path = derivation_path(network, purpose);
    slip10_ed25519::derive_ed25519_private_key(expanded_seed, &path)
}

/// Expands 32 bytes of entropy into a 64-byte seed via its BIP-39 mnemonic.
///
/// Routing expansion through the mnemonic (rather than using the entropy
/// directly) is what makes §1.1's recoverability guarantee real: the backup
/// phrase alone is sufficient to regenerate every key, with no additional
/// secret needed alongside it.
fn expand(entropy: &[u8; 32]) -> Result<[u8; 64], IdentityError> {
    let mnemonic = bip39::Mnemonic::from_entropy(entropy)
        .map_err(|e| IdentityError::InvalidBackupPhrase(e.to_string()))?;
    Ok(mnemonic.to_seed(""))
}

/// A person's master identity seed — Core Protocol Spec §1.1.
///
/// This value is never transmitted over the network under any circumstance. It
/// is the single source of truth from which every per-network identity key is
/// derived, and it is recoverable by the user from a backup phrase independently
/// of any device.
///
/// Deliberately implements neither `Debug`, `Display`, `Clone`, nor any
/// serialization: the type system should make it awkward to accidentally log,
/// duplicate, or persist the one secret whose disclosure compromises every
/// network the person belongs to.
pub struct MasterSeed {
    entropy: [u8; 32],
}

impl MasterSeed {
    /// Generates a new master seed from operating-system entropy.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut entropy = [0u8; 32];
        intranet_crypto::random_bytes(&mut entropy)?;
        Ok(Self { entropy })
    }

    /// Reconstructs a master seed from raw entropy.
    pub const fn from_entropy(entropy: [u8; 32]) -> Self {
        Self { entropy }
    }

    /// Renders the 24-word BIP-39 backup phrase for this seed.
    ///
    /// This phrase is the user's entire identity across every network they
    /// belong to. Recovering it onto any device immediately restores the ability
    /// to act as, and to mint device certificates for, that identity everywhere
    /// (§1.3, point 8).
    pub fn to_backup_phrase(&self) -> Result<String, IdentityError> {
        bip39::Mnemonic::from_entropy(&self.entropy)
            .map(|m| m.to_string())
            .map_err(|e| IdentityError::InvalidBackupPhrase(e.to_string()))
    }

    /// Recovers a master seed from its BIP-39 backup phrase.
    pub fn from_backup_phrase(phrase: &str) -> Result<Self, IdentityError> {
        let mnemonic = bip39::Mnemonic::parse(phrase)
            .map_err(|e| IdentityError::InvalidBackupPhrase(e.to_string()))?;
        let entropy = mnemonic.to_entropy();
        let entropy: [u8; 32] = entropy
            .as_slice()
            .try_into()
            .map_err(|_| IdentityError::WrongEntropyLength { got: entropy.len() })?;
        Ok(Self { entropy })
    }

    /// Derives this person's identity for a specific network — §1.2.
    ///
    /// The same master seed and network ID always regenerate the same keypair,
    /// so identity survives total device loss as long as the seed is recovered.
    /// Two identities derived for two different networks are unlinkable: nothing
    /// about one reveals that the other shares a master seed.
    pub fn identity_for(&self, network: &NetworkId) -> Result<PerNetworkIdentity, IdentityError> {
        let expanded = expand(&self.entropy)?;
        Ok(PerNetworkIdentity {
            network: *network,
            secret_bytes: derive_key_bytes(&expanded, network, PURPOSE_IDENTITY),
        })
    }
}

/// A single device's own seed — Core Protocol Spec §1.3, point 1.
///
/// Generated independently on each device at setup, never shared with the master
/// identity or any other device, and **never derived from the master seed**. A
/// device is not a derivative of the master identity; it starts as its own thing
/// and is subsequently *authorized* to act on that identity's behalf via a
/// [`DeviceCertificate`](crate::DeviceCertificate).
///
/// This is what bounds the blast radius of a lost device: revoking its
/// certificate cuts off its future signing authority without rotating the master
/// identity in any network.
pub struct DeviceSeed {
    entropy: [u8; 32],
}

impl DeviceSeed {
    /// Generates a new device seed from operating-system entropy.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut entropy = [0u8; 32];
        intranet_crypto::random_bytes(&mut entropy)?;
        Ok(Self { entropy })
    }

    /// Reconstructs a device seed from raw entropy.
    pub const fn from_entropy(entropy: [u8; 32]) -> Self {
        Self { entropy }
    }

    /// Derives this device's keypair for a specific network — §1.3, point 2.
    ///
    /// Uses the same per-network derivation pattern as master identities, for
    /// the same unlinkability reason: a device's participation in one network
    /// should not be correlatable, by key material alone, to its participation
    /// in another.
    pub fn key_for(&self, network: &NetworkId) -> Result<PerNetworkIdentity, IdentityError> {
        let expanded = expand(&self.entropy)?;
        Ok(PerNetworkIdentity {
            network: *network,
            secret_bytes: derive_key_bytes(&expanded, network, PURPOSE_DEVICE),
        })
    }
}

/// A keypair scoped to exactly one network.
///
/// Produced either by [`MasterSeed::identity_for`] (the person's identity in that
/// network) or by [`DeviceSeed::key_for`] (a device's key in that network). The
/// two are structurally identical — what distinguishes them is whether a
/// [`DeviceCertificate`](crate::DeviceCertificate) binds one to the other.
pub struct PerNetworkIdentity {
    network: NetworkId,
    secret_bytes: [u8; 32],
}

impl PerNetworkIdentity {
    /// The network this keypair is scoped to.
    pub const fn network(&self) -> &NetworkId {
        &self.network
    }

    /// The public identifier for this keypair.
    pub fn id(&self) -> PerNetworkIdentityId {
        PerNetworkIdentityId(self.secret().verifying_key())
    }

    /// The libp2p PeerId for this keypair — Core Protocol Spec §1.2.
    ///
    /// Deriving the transport identity from the *per-network* key is a hard
    /// requirement, not a convenience. Key-level unlinkability is void in
    /// practice if a node reuses one PeerId across networks, because that single
    /// correlating fingerprint makes its memberships trivially linkable to any
    /// observer regardless of how carefully the identity keys were derived.
    ///
    /// Note the honest limit the spec states alongside this: IP-level and
    /// timing correlation remain out of scope, so this closes the key/transport
    /// correlation channel, not every correlation channel.
    pub fn peer_id(&self) -> crate::PeerId {
        self.transport_keypair().public().to_peer_id()
    }

    /// The libp2p keypair this identity presents on the wire.
    ///
    /// Exposed so the transport layer never has to reach for raw secret bytes
    /// to build a swarm: the per-network identity keypair *is* the transport
    /// keypair, so this is the single place that correspondence is established,
    /// and [`peer_id`](Self::peer_id) is derived from it rather than computed
    /// separately — the two cannot drift apart.
    pub fn transport_keypair(&self) -> libp2p_identity::Keypair {
        let mut bytes = self.secret_bytes;
        let secret = libp2p_identity::ed25519::SecretKey::try_from_bytes(&mut bytes)
            .expect("32 bytes is always a valid ed25519 secret key");
        libp2p_identity::Keypair::from(libp2p_identity::ed25519::Keypair::from(secret))
    }

    /// Signs a canonical encoding with this keypair.
    pub fn sign(&self, message: &Enc) -> Signature {
        self.secret().sign(message)
    }

    /// Reconstructs the signing key transiently, in memory, for one operation.
    ///
    /// Matches §1.3's framing that a per-network private key is derived "in
    /// memory, as it already does for any per-network operation" rather than
    /// held live for the process lifetime.
    fn secret(&self) -> SecretKey {
        SecretKey::from_bytes(self.secret_bytes)
    }
}

/// The public identifier of a per-network identity.
///
/// This is what group membership, capability grants, and every signature in the
/// governance log are keyed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PerNetworkIdentityId(VerifyingKey);

impl PerNetworkIdentityId {
    /// Wraps a verifying key as an identity ID.
    pub const fn from_verifying_key(key: VerifyingKey) -> Self {
        Self(key)
    }

    /// Borrows the underlying verifying key.
    pub const fn verifying_key(&self) -> &VerifyingKey {
        &self.0
    }

    /// Appends this identifier to a canonical encoding.
    pub fn encode(&self, enc: &mut Enc) {
        enc.fixed(self.0.as_bytes());
    }

    /// Renders the first 8 hex characters, for human-facing output.
    pub fn short(&self) -> String {
        to_hex(&self.0.as_bytes()[..4])
    }
}

impl std::fmt::Display for PerNetworkIdentityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(seed: u8) -> NetworkId {
        NetworkId::from_bytes([seed; 32])
    }

    #[test]
    fn derivation_is_deterministic() {
        // §1.2: the same master seed + network_id always regenerates the same
        // keypair, which is what makes identity survive device loss.
        let seed = MasterSeed::from_entropy([1u8; 32]);
        let a = seed.identity_for(&net(9)).unwrap();
        let b = seed.identity_for(&net(9)).unwrap();
        assert_eq!(a.id(), b.id());
        assert_eq!(a.peer_id(), b.peer_id());
    }

    #[test]
    fn identity_survives_recovery_from_backup_phrase() {
        // §1.1: recoverable by the user, independent of any device.
        let original = MasterSeed::generate().unwrap();
        let phrase = original.to_backup_phrase().unwrap();
        assert_eq!(phrase.split_whitespace().count(), 24);

        let recovered = MasterSeed::from_backup_phrase(&phrase).unwrap();
        let network = net(4);
        assert_eq!(
            original.identity_for(&network).unwrap().id(),
            recovered.identity_for(&network).unwrap().id()
        );
    }

    #[test]
    fn keys_are_unlinkable_across_networks() {
        // §1.2: two per-network public keys must not reveal common ownership.
        let seed = MasterSeed::from_entropy([2u8; 32]);
        let a = seed.identity_for(&net(1)).unwrap();
        let b = seed.identity_for(&net(2)).unwrap();
        assert_ne!(a.id(), b.id());
    }

    #[test]
    fn peer_id_differs_per_network() {
        // §1.2: transport-layer unlinkability. A shared PeerId would void
        // key-level unlinkability entirely, so this is a hard requirement.
        let seed = MasterSeed::from_entropy([2u8; 32]);
        assert_ne!(
            seed.identity_for(&net(1)).unwrap().peer_id(),
            seed.identity_for(&net(2)).unwrap().peer_id()
        );
    }

    #[test]
    fn different_master_seeds_yield_different_identities() {
        let network = net(7);
        assert_ne!(
            MasterSeed::from_entropy([1u8; 32])
                .identity_for(&network)
                .unwrap()
                .id(),
            MasterSeed::from_entropy([2u8; 32])
                .identity_for(&network)
                .unwrap()
                .id()
        );
    }

    #[test]
    fn device_keys_are_not_derived_from_the_master_seed() {
        // §1.3, point 1: a device is independently seeded, never a derivative of
        // the master seed. Identical entropy in both roles must still produce
        // different keys, or the purpose separation is not actually doing its job.
        let network = net(5);
        let identity = MasterSeed::from_entropy([8u8; 32])
            .identity_for(&network)
            .unwrap();
        let device = DeviceSeed::from_entropy([8u8; 32]).key_for(&network).unwrap();
        assert_ne!(identity.id(), device.id());
    }

    #[test]
    fn device_keys_are_unlinkable_across_networks() {
        // §1.3, point 2: same unlinkability reasoning as identities.
        let device = DeviceSeed::from_entropy([6u8; 32]);
        assert_ne!(
            device.key_for(&net(1)).unwrap().id(),
            device.key_for(&net(2)).unwrap().id()
        );
    }

    #[test]
    fn derivation_paths_are_hardened_and_distinct() {
        let a = derivation_path(&net(1), PURPOSE_IDENTITY);
        let b = derivation_path(&net(1), PURPOSE_DEVICE);
        let c = derivation_path(&net(2), PURPOSE_IDENTITY);
        assert_ne!(a, b, "purpose must separate paths");
        assert_ne!(a, c, "network must separate paths");
        for index in a {
            assert_eq!(index & 0x8000_0000, 0, "high bit must be free for hardening");
        }
    }

    #[test]
    fn signatures_verify_against_the_derived_public_key() {
        let identity = MasterSeed::from_entropy([1u8; 32])
            .identity_for(&net(3))
            .unwrap();
        let mut message = Enc::domain("test");
        message.str("payload");
        let signature = identity.sign(&message);
        assert!(
            identity
                .id()
                .verifying_key()
                .verify(&message, &signature)
                .is_ok()
        );
    }

    #[test]
    fn malformed_backup_phrases_are_rejected() {
        assert!(matches!(
            MasterSeed::from_backup_phrase("not actually a mnemonic"),
            Err(IdentityError::InvalidBackupPhrase(_))
        ));
    }

    #[test]
    fn short_backup_phrases_are_rejected_not_silently_padded() {
        // A 12-word phrase carries 16 bytes of entropy, not 32. Accepting it
        // would silently halve the master seed's entropy.
        let twelve = bip39::Mnemonic::from_entropy(&[7u8; 16]).unwrap().to_string();
        assert!(matches!(
            MasterSeed::from_backup_phrase(&twelve),
            Err(IdentityError::WrongEntropyLength { got: 16 })
        ));
    }
}
