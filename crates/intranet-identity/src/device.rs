//! Device certificates — Core Protocol Spec §1.3.
//!
//! A device is authorized, never derived. These records are what carry that
//! authorization, and revoking one cuts off a device's future signing authority
//! without rotating the master identity in any network.
//!
//! Both record types are designed to be carried as governance log entries
//! (§1.3, point 3) so that device linking reuses the same tamper-evident,
//! independently-replayable structure as every other network fact — even though
//! linking is not itself a group or capability action.

use crate::{IdentityError, NetworkId, PerNetworkIdentity, PerNetworkIdentityId};
use intranet_crypto::{Enc, Signature, Timestamp, VerifyingKey, to_hex};

/// Domain tag for device certificate signatures.
const CERT_DOMAIN: &str = "intranet.device-certificate.v1";

/// Domain tag for device certificate revocation signatures.
const REVOCATION_DOMAIN: &str = "intranet.device-revocation.v1";

/// The public key of a device, scoped to one network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DevicePublicKey(VerifyingKey);

impl DevicePublicKey {
    /// Wraps a verifying key as a device public key.
    pub const fn from_verifying_key(key: VerifyingKey) -> Self {
        Self(key)
    }

    /// Borrows the underlying verifying key.
    pub const fn verifying_key(&self) -> &VerifyingKey {
        &self.0
    }

    /// Appends this key to a canonical encoding.
    pub fn encode(&self, enc: &mut Enc) {
        enc.fixed(self.0.as_bytes());
    }

    /// Renders the first 8 hex characters, for human-facing output.
    pub fn short(&self) -> String {
        to_hex(&self.0.as_bytes()[..4])
    }
}

impl std::fmt::Display for DevicePublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A certificate binding a device key to an identity, for one network.
///
/// Minted by whichever device currently holds the master seed, which derives the
/// network's identity private key transiently in memory to sign (§1.3, point 3).
/// There is no protocol-level "primary device" role: any master-seed-holding
/// device can mint or revoke certificates for any network the identity belongs
/// to (§1.3, point 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCertificate {
    /// Network this certificate is valid in — enrollment is per-network.
    pub network: NetworkId,
    /// The identity the device is authorized to act on behalf of.
    pub identity: PerNetworkIdentityId,
    /// The device key being authorized, for this network.
    pub device: DevicePublicKey,
    /// Human-readable label, for the user's own device management.
    pub label: String,
    /// When the certificate was issued.
    pub issued_at: Timestamp,
    /// Signature by `identity` over the fields above.
    pub signature: Signature,
}

impl DeviceCertificate {
    /// Issues a certificate authorizing `device` to act for `identity`.
    ///
    /// `identity` must be the per-network identity derived from the master seed
    /// — this is the one operation in §1.3 that genuinely requires the master
    /// seed, once, per network.
    pub fn issue(
        identity: &PerNetworkIdentity,
        device: DevicePublicKey,
        label: impl Into<String>,
        issued_at: Timestamp,
    ) -> Self {
        let label = label.into();
        let identity_id = identity.id();
        let payload = Self::payload(
            identity.network(),
            &identity_id,
            &device,
            &label,
            issued_at,
        );
        Self {
            network: *identity.network(),
            identity: identity_id,
            device,
            label,
            issued_at,
            signature: identity.sign(&payload),
        }
    }

    /// Verifies the certificate's signature against the identity it names.
    pub fn verify(&self) -> Result<(), IdentityError> {
        let payload = Self::payload(
            &self.network,
            &self.identity,
            &self.device,
            &self.label,
            self.issued_at,
        );
        self.identity
            .verifying_key()
            .verify(&payload, &self.signature)
            .map_err(|_| IdentityError::BadSignature {
                what: "device certificate",
            })
    }

    /// Verifies the certificate and confirms it was issued for `network`.
    ///
    /// Enrollment is per-network (§1.3, point 7): authorizing a device for one
    /// network does not authorize it for another. Callers evaluating a
    /// certificate in a network context must use this rather than [`verify`],
    /// or a certificate minted for a low-trust network would be accepted as
    /// authorization in a high-trust one.
    ///
    /// [`verify`]: Self::verify
    pub fn verify_for_network(&self, network: &NetworkId) -> Result<(), IdentityError> {
        if self.network != *network {
            return Err(IdentityError::NetworkMismatch {
                certificate_network: self.network.short(),
                expected_network: network.short(),
            });
        }
        self.verify()
    }

    fn payload(
        network: &NetworkId,
        identity: &PerNetworkIdentityId,
        device: &DevicePublicKey,
        label: &str,
        issued_at: Timestamp,
    ) -> Enc {
        let mut e = Enc::domain(CERT_DOMAIN);
        network.encode(&mut e);
        identity.encode(&mut e);
        device.encode(&mut e);
        e.str(label).i64(issued_at.as_millis());
        e
    }
}

/// A revocation cutting off a device's future signing authority — §1.3, point 6.
///
/// This is one of two separable actions a lost or stolen device calls for. It
/// addresses future signing authority only. It does **not** address the separate
/// risk that the device already cached the network's current epoch key and can
/// still decrypt previously-accessible content — that requires a voluntary
/// epoch rekey request, which any identity may make without holding any
/// capability, precisely so that reporting a compromise is never discouraged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCertificateRevocation {
    /// Network the revocation applies to.
    pub network: NetworkId,
    /// The identity revoking one of its devices.
    pub identity: PerNetworkIdentityId,
    /// The device key losing its authority.
    pub device: DevicePublicKey,
    /// When the revocation was issued.
    pub revoked_at: Timestamp,
    /// Signature by `identity` over the fields above.
    pub signature: Signature,
}

impl DeviceCertificateRevocation {
    /// Issues a revocation for `device`.
    pub fn issue(
        identity: &PerNetworkIdentity,
        device: DevicePublicKey,
        revoked_at: Timestamp,
    ) -> Self {
        let identity_id = identity.id();
        let payload = Self::payload(identity.network(), &identity_id, &device, revoked_at);
        Self {
            network: *identity.network(),
            identity: identity_id,
            device,
            revoked_at,
            signature: identity.sign(&payload),
        }
    }

    /// Verifies the revocation's signature against the identity it names.
    pub fn verify(&self) -> Result<(), IdentityError> {
        let payload = Self::payload(&self.network, &self.identity, &self.device, self.revoked_at);
        self.identity
            .verifying_key()
            .verify(&payload, &self.signature)
            .map_err(|_| IdentityError::BadSignature {
                what: "device certificate revocation",
            })
    }

    fn payload(
        network: &NetworkId,
        identity: &PerNetworkIdentityId,
        device: &DevicePublicKey,
        revoked_at: Timestamp,
    ) -> Enc {
        let mut e = Enc::domain(REVOCATION_DOMAIN);
        network.encode(&mut e);
        identity.encode(&mut e);
        device.encode(&mut e);
        e.i64(revoked_at.as_millis());
        e
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DeviceSeed, MasterSeed};

    fn net(seed: u8) -> NetworkId {
        NetworkId::from_bytes([seed; 32])
    }

    fn at(millis: i64) -> Timestamp {
        Timestamp::from_millis(millis)
    }

    #[test]
    fn issued_certificate_verifies() {
        let network = net(1);
        let identity = MasterSeed::from_entropy([1u8; 32])
            .identity_for(&network)
            .unwrap();
        let device_key = DeviceSeed::from_entropy([2u8; 32]).key_for(&network).unwrap();
        let device = DevicePublicKey::from_verifying_key(*device_key.id().verifying_key());

        let cert = DeviceCertificate::issue(&identity, device, "laptop", at(1_000));
        assert!(cert.verify().is_ok());
        assert!(cert.verify_for_network(&network).is_ok());
        assert_eq!(cert.label, "laptop");
    }

    #[test]
    fn tampered_certificate_fields_fail_verification() {
        let network = net(1);
        let identity = MasterSeed::from_entropy([1u8; 32])
            .identity_for(&network)
            .unwrap();
        let device_key = DeviceSeed::from_entropy([2u8; 32]).key_for(&network).unwrap();
        let device = DevicePublicKey::from_verifying_key(*device_key.id().verifying_key());

        let mut cert = DeviceCertificate::issue(&identity, device, "laptop", at(1_000));
        cert.label = "phone".into();
        assert!(matches!(cert.verify(), Err(IdentityError::BadSignature { .. })));
    }

    #[test]
    fn certificate_swapped_to_another_device_fails_verification() {
        // The whole point of the certificate is binding one specific device key
        // to the identity; substituting a different device must not verify.
        let network = net(1);
        let identity = MasterSeed::from_entropy([1u8; 32])
            .identity_for(&network)
            .unwrap();
        let honest = DeviceSeed::from_entropy([2u8; 32]).key_for(&network).unwrap();
        let attacker = DeviceSeed::from_entropy([3u8; 32]).key_for(&network).unwrap();

        let mut cert = DeviceCertificate::issue(
            &identity,
            DevicePublicKey::from_verifying_key(*honest.id().verifying_key()),
            "laptop",
            at(1_000),
        );
        cert.device = DevicePublicKey::from_verifying_key(*attacker.id().verifying_key());
        assert!(matches!(cert.verify(), Err(IdentityError::BadSignature { .. })));
    }

    #[test]
    fn certificate_from_one_network_is_refused_in_another() {
        // §1.3, point 7: enrollment is per-network. A certificate minted in a
        // low-trust network must confer nothing in a high-trust one.
        let seed = MasterSeed::from_entropy([1u8; 32]);
        let low_trust = net(1);
        let high_trust = net(2);

        let identity = seed.identity_for(&low_trust).unwrap();
        let device_key = DeviceSeed::from_entropy([2u8; 32])
            .key_for(&low_trust)
            .unwrap();
        let cert = DeviceCertificate::issue(
            &identity,
            DevicePublicKey::from_verifying_key(*device_key.id().verifying_key()),
            "laptop",
            at(1_000),
        );

        assert!(cert.verify().is_ok(), "signature itself is valid");
        assert!(
            matches!(
                cert.verify_for_network(&high_trust),
                Err(IdentityError::NetworkMismatch { .. })
            ),
            "but it must not be accepted as authorization in another network"
        );
    }

    #[test]
    fn revocation_verifies_and_is_bound_to_one_device() {
        let network = net(1);
        let identity = MasterSeed::from_entropy([1u8; 32])
            .identity_for(&network)
            .unwrap();
        let device_key = DeviceSeed::from_entropy([2u8; 32]).key_for(&network).unwrap();
        let device = DevicePublicKey::from_verifying_key(*device_key.id().verifying_key());

        let revocation = DeviceCertificateRevocation::issue(&identity, device, at(5_000));
        assert!(revocation.verify().is_ok());

        let other = DeviceSeed::from_entropy([9u8; 32]).key_for(&network).unwrap();
        let mut forged = revocation.clone();
        forged.device = DevicePublicKey::from_verifying_key(*other.id().verifying_key());
        assert!(matches!(
            forged.verify(),
            Err(IdentityError::BadSignature { .. })
        ));
    }

    #[test]
    fn a_device_cannot_mint_its_own_certificate() {
        // Only master-seed possession authorizes certificate issuance. A device
        // holding only its own key cannot self-authorize, which is the property
        // that keeps a compromised device from re-enrolling itself after
        // revocation.
        let network = net(1);
        let identity = MasterSeed::from_entropy([1u8; 32])
            .identity_for(&network)
            .unwrap();
        let device_key = DeviceSeed::from_entropy([2u8; 32]).key_for(&network).unwrap();
        let device = DevicePublicKey::from_verifying_key(*device_key.id().verifying_key());

        // The device signs a certificate naming the real identity as issuer.
        let mut forged = DeviceCertificate::issue(&device_key, device, "self", at(1_000));
        forged.identity = identity.id();

        assert!(
            matches!(forged.verify(), Err(IdentityError::BadSignature { .. })),
            "a certificate signed by the device but attributed to the identity must not verify"
        );
    }
}
