//! Invites and the explicit-intake waiting room — Core Protocol Spec §5.6–5.7, §2.4.
//!
//! # An invite's job ends at the first connection
//!
//! This is the design principle §5.7 states explicitly, and it is why this crate
//! is so small. An invite carries only what is strictly required to make the
//! network's first authenticated connection and verify that connection is
//! legitimate: bootstrap addresses, network ID, issuer, and a signature.
//!
//! Everything else a new node needs — the rest of the peer set, the governance
//! log, the capability ledger, the epoch key, and the network's default app if
//! it has one — is obtained *after* that connection exists, using ordinary
//! steady-state protocol operations. None of it is special-cased to the join
//! moment, and none of it belongs in the invite payload.
//!
//! There is deliberately no field here for a network key. The prior prototype's
//! invite carried a single shared static network key; that scheme is rejected
//! (§3.2), and an invite now triggers the epoch-key delivery handshake instead.
//!
//! # What using an invite grants
//!
//! Nothing, by itself. The consequence of a successful join is governed entirely
//! by the network's admission-mode policy, not by the invite:
//!
//! - **Auto-admit**: the join immediately places the identity in `everyone` and
//!   triggers epoch key delivery.
//! - **Explicit intake**: the join establishes connectivity and a per-network
//!   identity *only*. The node enters the groupless [`WaitingRoom`], holding no
//!   capabilities and — critically — **no epoch key**, since holding the epoch
//!   key is equivalent to being able to decrypt network content regardless of
//!   group membership.

mod waiting_room;
pub mod wire;

pub use waiting_room::{WaitingRoom, WaitingRoomEntry};
pub use wire::{
    decode_invite, encode_invite,
    JoinRefusal, JoinRequest, JoinResponse, MAX_ADDRESS_BYTES, MAX_BOOTSTRAP_ADDRESSES,
};

use intranet_crypto::{Enc, Hash, Signature, Timestamp, hash_bytes};
use intranet_governance::{Capability, GovernanceState, InviteProvenance};
use intranet_identity::{NetworkId, PerNetworkIdentity, PerNetworkIdentityId};

/// Domain tag for invite signatures.
const INVITE_DOMAIN: &str = "intranet.invite.v1";

/// Who may redeem an invite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteSubject {
    /// Anyone holding the invite may redeem it.
    ///
    /// Bearer invites are what make pre-admission identities cheap to mint,
    /// which is exactly why relay rate limiting must be scoped per-invite rather
    /// than solely per-identity for not-yet-admitted nodes (§5.3).
    Bearer,
    /// Only this specific identity may redeem it.
    Identity(PerNetworkIdentityId),
}

/// Why an invite was refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum InviteError {
    /// The invite's signature did not verify against its issuer.
    #[error("invite signature verification failed")]
    BadSignature,

    /// The invite is for a different network.
    #[error("invite is for network {invite_network}, not {expected_network}")]
    NetworkMismatch {
        /// Network named by the invite.
        invite_network: String,
        /// Network it was presented to.
        expected_network: String,
    },

    /// The invite has expired.
    #[error("invite expired at {expires_at}, now {now}")]
    Expired {
        /// When the invite expired.
        expires_at: Timestamp,
        /// The evaluating node's current time.
        now: Timestamp,
    },

    /// The invite is not yet valid.
    #[error("invite is not valid until {issued_at}, now {now}")]
    NotYetValid {
        /// When the invite becomes valid.
        issued_at: Timestamp,
        /// The evaluating node's current time.
        now: Timestamp,
    },

    /// The issuer does not (or no longer does) hold `approve-node`.
    #[error("invite issuer {issuer} does not hold approve-node")]
    IssuerNotAuthorized {
        /// The issuing identity.
        issuer: String,
    },

    /// A specific-identity invite was presented by someone else.
    #[error("invite was issued to {expected}, presented by {presenter}")]
    WrongSubject {
        /// Who the invite names.
        expected: String,
        /// Who presented it.
        presenter: String,
    },

    /// The invite has already been redeemed its maximum number of times.
    #[error("invite has been used {used} times, limit is {max_uses}")]
    Exhausted {
        /// How many times it has been used.
        used: usize,
        /// The configured limit.
        max_uses: u32,
    },

    /// The invite carries no bootstrap addresses, so it cannot establish a
    /// connection — the one job it exists to do.
    #[error("invite carries no bootstrap addresses")]
    NoBootstrapAddresses,
}

/// A signed, time-bounded, use-count-limited credential to join a network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    /// The network being joined.
    pub network: NetworkId,
    /// Bootstrap peer addresses to dial, as multiaddr strings.
    ///
    /// Held as strings rather than parsed multiaddrs so that this crate stays
    /// free of a libp2p dependency: an invite is a signed credential, and its
    /// validation has nothing to do with transport. The transport layer parses
    /// these when it dials.
    pub bootstrap_addresses: Vec<String>,
    /// The identity that issued this invite.
    pub issuer: PerNetworkIdentityId,
    /// Who may redeem it.
    pub subject: InviteSubject,
    /// When it was issued.
    pub issued_at: Timestamp,
    /// When it expires.
    pub expires_at: Timestamp,
    /// How many identities may be admitted using it.
    pub max_uses: u32,
    /// The issuer's signature over everything above.
    pub signature: Signature,
}

impl Invite {
    /// Issues and signs an invite.
    ///
    /// Does not itself check that `issuer` holds `approve-node` — that is a
    /// governance question answered at redemption time against the redeeming
    /// node's own replayed state, because the issuer's authority may have been
    /// revoked between issuance and use, and it is the state at *use* that must
    /// govern.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        issuer: &PerNetworkIdentity,
        bootstrap_addresses: Vec<String>,
        subject: InviteSubject,
        issued_at: Timestamp,
        expires_at: Timestamp,
        max_uses: u32,
    ) -> Self {
        let issuer_id = issuer.id();
        let payload = Self::payload(
            issuer.network(),
            &bootstrap_addresses,
            &issuer_id,
            &subject,
            issued_at,
            expires_at,
            max_uses,
        );
        Self {
            network: *issuer.network(),
            bootstrap_addresses,
            issuer: issuer_id,
            subject,
            issued_at,
            expires_at,
            max_uses,
            signature: issuer.sign(&payload),
        }
    }

    /// This invite's identifier, derived from its contents.
    pub fn invite_id(&self) -> Hash {
        let mut e = self.signing_payload();
        e.fixed(self.signature.as_bytes());
        hash_bytes(&e.finish())
    }

    /// The provenance record to attach to a membership granted via this invite.
    pub fn provenance(&self) -> InviteProvenance {
        InviteProvenance {
            invite_id: self.invite_id(),
            issuer: self.issuer,
        }
    }

    /// Verifies the invite's signature only.
    pub fn verify_signature(&self) -> Result<(), InviteError> {
        self.issuer
            .verifying_key()
            .verify(&self.signing_payload(), &self.signature)
            .map_err(|_| InviteError::BadSignature)
    }

    /// Fully validates this invite for redemption by `presenter`.
    ///
    /// Every check is performed against the redeeming node's own replayed
    /// governance state and its own clock — no central check, consistent with
    /// §5.6's requirement that any receiving node can independently verify an
    /// invite is legitimate.
    ///
    /// Ordering is deliberate: cheap structural checks run before the
    /// governance-state query, so a malformed or expired invite is rejected
    /// without doing replay work on an attacker's behalf.
    pub fn validate(
        &self,
        presenter: &PerNetworkIdentityId,
        state: &GovernanceState,
        now: Timestamp,
    ) -> Result<InviteProvenance, InviteError> {
        self.verify_signature()?;

        if self.network != state.network {
            return Err(InviteError::NetworkMismatch {
                invite_network: self.network.short(),
                expected_network: state.network.short(),
            });
        }

        if self.bootstrap_addresses.is_empty() {
            return Err(InviteError::NoBootstrapAddresses);
        }

        if now < self.issued_at {
            return Err(InviteError::NotYetValid {
                issued_at: self.issued_at,
                now,
            });
        }

        if now > self.expires_at {
            return Err(InviteError::Expired {
                expires_at: self.expires_at,
                now,
            });
        }

        if let InviteSubject::Identity(named) = self.subject
            && named != *presenter
        {
            return Err(InviteError::WrongSubject {
                expected: named.short(),
                presenter: presenter.short(),
            });
        }

        // Authority is evaluated as of *now*, not as of issuance: an invite
        // signed by someone since stripped of `approve-node` must stop working,
        // or revoking an admin would leave their outstanding invites live.
        if !state.identity_holds(&self.issuer, &Capability::ApproveNode) {
            return Err(InviteError::IssuerNotAuthorized {
                issuer: self.issuer.short(),
            });
        }

        // Use count is derived from membership provenance in replayed state, so
        // every node reaches the same answer (see `GovernanceState::invite_use_count`).
        let used = state.invite_use_count(&self.invite_id());
        if used >= self.max_uses as usize {
            return Err(InviteError::Exhausted {
                used,
                max_uses: self.max_uses,
            });
        }

        Ok(self.provenance())
    }

    fn signing_payload(&self) -> Enc {
        Self::payload(
            &self.network,
            &self.bootstrap_addresses,
            &self.issuer,
            &self.subject,
            self.issued_at,
            self.expires_at,
            self.max_uses,
        )
    }

    fn payload(
        network: &NetworkId,
        bootstrap_addresses: &[String],
        issuer: &PerNetworkIdentityId,
        subject: &InviteSubject,
        issued_at: Timestamp,
        expires_at: Timestamp,
        max_uses: u32,
    ) -> Enc {
        let mut e = Enc::domain(INVITE_DOMAIN);
        network.encode(&mut e);
        e.seq(bootstrap_addresses.iter(), |e, address| {
            e.str(address);
        });
        issuer.encode(&mut e);
        match subject {
            InviteSubject::Bearer => {
                e.variant(0);
            }
            InviteSubject::Identity(identity) => {
                e.variant(1);
                identity.encode(&mut e);
            }
        }
        e.i64(issued_at.as_millis())
            .i64(expires_at.as_millis())
            .u32(max_uses);
        e
    }
}
