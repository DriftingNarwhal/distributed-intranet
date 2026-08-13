//! Network identifiers.

use intranet_crypto::{CryptoError, Enc, random_bytes, to_hex};

/// The unique identifier of a network.
///
/// Every per-network derivation in this protocol is keyed on this value, so it
/// is the input that makes one person's identity in network A cryptographically
/// unrelated to their identity in network B (Core Protocol Spec §1.2).
///
/// # Why this is random rather than derived from genesis
///
/// The Core Protocol Spec requires a network to have a unique identifier but does
/// not specify how it is produced. Deriving it from the genesis entry would be
/// circular: the genesis entry is signed by the founder's *per-network* identity,
/// which cannot be derived until the network ID already exists. A random 32-byte
/// value at creation avoids that ordering problem, and collision risk is
/// negligible. **Flagged as an implementation choice not covered by the specs.**
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NetworkId([u8; 32]);

impl NetworkId {
    /// Generates a new random network identifier, for network genesis.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut bytes = [0u8; 32];
        random_bytes(&mut bytes)?;
        Ok(Self(bytes))
    }

    /// Wraps raw identifier bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrows the raw identifier bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Appends this identifier to a canonical encoding.
    pub fn encode(&self, enc: &mut Enc) {
        enc.fixed(&self.0);
    }

    /// Renders the first 8 hex characters, for human-facing output.
    pub fn short(&self) -> String {
        to_hex(&self.0[..4])
    }
}

impl std::fmt::Display for NetworkId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", to_hex(&self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_ids_are_distinct() {
        assert_ne!(NetworkId::generate().unwrap(), NetworkId::generate().unwrap());
    }

    #[test]
    fn encoding_is_stable() {
        let id = NetworkId::from_bytes([3u8; 32]);
        let enc = |n: &NetworkId| {
            let mut e = Enc::new();
            n.encode(&mut e);
            e.finish()
        };
        assert_eq!(enc(&id), enc(&id));
        assert_ne!(enc(&id), enc(&NetworkId::from_bytes([4u8; 32])));
    }
}
