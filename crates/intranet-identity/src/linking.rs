//! Voluntary proof of common ownership — Core Protocol Spec §1.2.
//!
//! Unlinkability is the default and is unconditional: nobody can determine that
//! two per-network identities belong to the same person. This module provides
//! the single, deliberate escape hatch — the person choosing to *prove* common
//! ownership, to their own alt accounts or to a trusted party.
//!
//! The property that matters is asymmetry: the proof is only ever produced by
//! someone holding **both** private keys, and its absence reveals nothing. There
//! is no way to derive, guess, or compel this relationship from public data.

use crate::{IdentityError, NetworkId, PerNetworkIdentity, PerNetworkIdentityId};
use intranet_crypto::{Enc, Signature};

/// Domain tag for common-ownership proof signatures.
const LINK_DOMAIN: &str = "intranet.common-ownership.v1";

/// One side of a common-ownership claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Side {
    network: NetworkId,
    identity: PerNetworkIdentityId,
}

impl Side {
    fn encode(&self, enc: &mut Enc) {
        self.network.encode(enc);
        self.identity.encode(enc);
    }
}

/// A signed statement that two per-network identities are the same person.
///
/// Both identities sign the same canonical statement, so neither party can be
/// unilaterally linked to the other by a third party holding only one key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommonOwnershipProof {
    /// Lower-ordered side of the claim.
    first: Side,
    /// Higher-ordered side of the claim.
    second: Side,
    /// Signature by `first`'s identity.
    first_signature: Signature,
    /// Signature by `second`'s identity.
    second_signature: Signature,
}

impl CommonOwnershipProof {
    /// Creates a proof linking two per-network identities held by one person.
    ///
    /// The two sides are stored in a canonical order so that the same pair
    /// always produces the same signed statement regardless of argument order —
    /// otherwise two structurally different proofs would exist for one fact, and
    /// verifiers would have to try both orderings.
    pub fn create(a: &PerNetworkIdentity, b: &PerNetworkIdentity) -> Self {
        let side_a = Side {
            network: *a.network(),
            identity: a.id(),
        };
        let side_b = Side {
            network: *b.network(),
            identity: b.id(),
        };

        let (first, second, first_key, second_key) = if side_a <= side_b {
            (side_a, side_b, a, b)
        } else {
            (side_b, side_a, b, a)
        };

        let payload = Self::payload(&first, &second);
        Self {
            first,
            second,
            first_signature: first_key.sign(&payload),
            second_signature: second_key.sign(&payload),
        }
    }

    /// Verifies that both named identities signed this statement.
    ///
    /// Requires *both* signatures. A proof carrying only one is not a weaker
    /// proof, it is not a proof at all: a single signature would let anyone
    /// holding one key assert an association with an identity that never agreed
    /// to it, which would turn a consent mechanism into a doxxing primitive.
    pub fn verify(&self) -> Result<(), IdentityError> {
        let payload = Self::payload(&self.first, &self.second);
        self.first
            .identity
            .verifying_key()
            .verify(&payload, &self.first_signature)
            .map_err(|_| IdentityError::BadSignature {
                what: "common ownership proof (first side)",
            })?;
        self.second
            .identity
            .verifying_key()
            .verify(&payload, &self.second_signature)
            .map_err(|_| IdentityError::BadSignature {
                what: "common ownership proof (second side)",
            })
    }

    /// Returns the two `(network, identity)` pairs this proof links.
    pub fn linked(
        &self,
    ) -> (
        (NetworkId, PerNetworkIdentityId),
        (NetworkId, PerNetworkIdentityId),
    ) {
        (
            (self.first.network, self.first.identity),
            (self.second.network, self.second.identity),
        )
    }

    fn payload(first: &Side, second: &Side) -> Enc {
        let mut e = Enc::domain(LINK_DOMAIN);
        first.encode(&mut e);
        second.encode(&mut e);
        e
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MasterSeed;

    fn net(seed: u8) -> NetworkId {
        NetworkId::from_bytes([seed; 32])
    }

    #[test]
    fn proof_verifies_and_is_order_independent() {
        let seed = MasterSeed::from_entropy([1u8; 32]);
        let a = seed.identity_for(&net(1)).unwrap();
        let b = seed.identity_for(&net(2)).unwrap();

        let forward = CommonOwnershipProof::create(&a, &b);
        let reverse = CommonOwnershipProof::create(&b, &a);

        assert!(forward.verify().is_ok());
        assert!(reverse.verify().is_ok());
        assert_eq!(
            forward.linked(),
            reverse.linked(),
            "argument order must not change the fact being asserted"
        );
    }

    #[test]
    fn proof_works_across_unrelated_master_seeds() {
        // The mechanism proves "these two keys agree they are the same person",
        // which is exactly what a person with two separate master seeds needs to
        // link their own alt accounts.
        let a = MasterSeed::from_entropy([1u8; 32])
            .identity_for(&net(1))
            .unwrap();
        let b = MasterSeed::from_entropy([2u8; 32])
            .identity_for(&net(2))
            .unwrap();
        assert!(CommonOwnershipProof::create(&a, &b).verify().is_ok());
    }

    #[test]
    fn a_third_party_cannot_forge_a_link() {
        // Holding one key must not be enough to assert an association with an
        // identity that never consented to it.
        let seed = MasterSeed::from_entropy([1u8; 32]);
        let a = seed.identity_for(&net(1)).unwrap();
        let b = seed.identity_for(&net(2)).unwrap();
        let victim = MasterSeed::from_entropy([9u8; 32])
            .identity_for(&net(3))
            .unwrap();

        let mut forged = CommonOwnershipProof::create(&a, &b);
        // Substitute the victim into whichever side is not the attacker's own.
        if forged.first.identity == a.id() {
            forged.second = Side {
                network: net(3),
                identity: victim.id(),
            };
        } else {
            forged.first = Side {
                network: net(3),
                identity: victim.id(),
            };
        }

        assert!(
            matches!(forged.verify(), Err(IdentityError::BadSignature { .. })),
            "substituting a non-consenting identity must fail verification"
        );
    }

    #[test]
    fn proof_does_not_verify_for_a_different_pair() {
        let seed = MasterSeed::from_entropy([1u8; 32]);
        let a = seed.identity_for(&net(1)).unwrap();
        let b = seed.identity_for(&net(2)).unwrap();
        let c = seed.identity_for(&net(3)).unwrap();

        let ab = CommonOwnershipProof::create(&a, &b);
        let ac = CommonOwnershipProof::create(&a, &c);
        assert_ne!(ab.linked(), ac.linked());

        // Signatures are bound to the specific pair, so swapping payloads fails.
        let mut mixed = ab.clone();
        mixed.first_signature = ac.first_signature;
        assert!(mixed.verify().is_err());
    }
}
