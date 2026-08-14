//! Relay resource limits and identity-keyed rate limiting — Core Protocol Spec §5.3.
//!
//! # Two specific bugs this module exists to make impossible
//!
//! Both were found in real prior relay code and are named explicitly in the
//! Reference Test Harness Spec (§2.5) as requiring their own test:
//!
//! 1. **A limiter that computed a decision but never enforced it.** Guarded
//!    against structurally rather than by discipline: a caller cannot open a
//!    circuit without presenting a [`ReservationId`] that this module issued,
//!    and [`RelayGuard::record_bytes`] / [`RelayGuard::expire`] return the
//!    circuits they closed rather than merely reporting that a threshold was
//!    passed. There is no code path that yields a "denied" verdict the caller
//!    can quietly ignore and proceed anyway.
//!
//! 2. **Rate limiting keyed by libp2p peer ID.** A peer ID is free to
//!    regenerate — nothing stops a client generating a fresh keypair per
//!    connection attempt — so a peer-ID-keyed limit is not protection, only the
//!    appearance of it. Limits here key on the authenticated per-network
//!    identity. The transport's own handle is accepted for bookkeeping and is
//!    deliberately *never* part of any limit key; see [`TransportHandle`].
//!
//! # The pre-admission gap
//!
//! Keying on per-network identity is only meaningfully costly for an
//! *already-admitted* member, because admission is what costs something. A
//! waiting-room identity exists before admission and, under a multi-use or
//! bearer invite, can be minted freely — so per-identity limits alone provide no
//! protection there. Pre-admission activity is therefore additionally metered
//! per-invite, since the invite is the actual scarce resource in that window.
//!
//! # Where this metering can actually be enforced — §5.3.1
//!
//! Both keys assume somebody verified the thing being metered is real: that the
//! identity was admitted, or that the invite's issuer holds `approve-node`. Both
//! are governance-state questions, and **a stateless bootstrap relay holds no
//! governance state by deliberate design (§5.4)**, so it can answer neither. It
//! can check an invite's signature, which is self-contained, but not the
//! authority behind it — an attacker self-signs an invite naming a keypair it
//! just generated and gets a structurally perfect credential and a fresh bucket.
//!
//! So this type is enforceable in full only at a **member** node offering
//! `relay_bootstrap_willing`, which replays the log anyway. A bootstrap relay
//! uses the global ceilings — [`RelayLimits::max_reservations`],
//! [`RelayLimits::max_circuits`], and the duration and byte ceilings — which need
//! no state and bound what an attacker can consume without allocating it fairly.
//!
//! That is a decided limit rather than a gap awaiting work (§5.3.1). The failure
//! mode is denial of cold start, not compromise: a forged invite is refused by
//! the receiving member at redemption, and a relay never inspects a join. Giving
//! relays governance state to close it would trade away the disposability that
//! makes a relay replaceable, against an attack whose remedy is replacing it.

use intranet_crypto::{Hash, Timestamp};
use intranet_identity::PerNetworkIdentityId;
use std::collections::BTreeMap;

/// An opaque handle for the transport-level connection a request arrived on.
///
/// Exists purely so a relay can correlate its own bookkeeping with a live
/// connection. It is **never** used as a rate-limit key, and must not become
/// one: it corresponds to a libp2p peer ID, which is free to regenerate, so
/// keying limits on it would be exactly the bug §5.3 forbids.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, std::hash::Hash)]
pub struct TransportHandle(pub u64);

/// Who is asking for relay resources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Requester {
    /// An identity that has completed admission into a group.
    ///
    /// Ordinary per-identity limits apply: regenerating this identity requires
    /// clearing the network's admission process again, a real cost an attacker
    /// cannot route around by generating new key material.
    Admitted(PerNetworkIdentityId),

    /// A waiting-room identity that has not yet been admitted.
    ///
    /// Metered per-invite as well as per-identity, because the identity itself
    /// is cheap to mint in this window and provides no scarcity to meter against.
    PreAdmission {
        /// The not-yet-admitted identity.
        identity: PerNetworkIdentityId,
        /// The invite it connected under.
        invite: Hash,
    },
}

impl Requester {
    /// The per-network identity making the request.
    pub fn identity(&self) -> &PerNetworkIdentityId {
        match self {
            Self::Admitted(identity) => identity,
            Self::PreAdmission { identity, .. } => identity,
        }
    }

    /// The invite being metered against, for pre-admission requesters.
    pub fn invite(&self) -> Option<&Hash> {
        match self {
            Self::Admitted(_) => None,
            Self::PreAdmission { invite, .. } => Some(invite),
        }
    }
}

/// Configured relay resource ceilings.
///
/// Defaults are the baseline values §5.3 gives as validated in a working prior
/// implementation, except where noted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayLimits {
    /// Total concurrent reservations across all requesters.
    pub max_reservations: u32,
    /// Concurrent reservations per authenticated identity.
    pub max_reservations_per_identity: u32,
    /// Concurrent reservations per invite, for pre-admission requesters.
    ///
    /// **Flagged: the specs require per-invite scoping but give no number.**
    /// Set to twice the per-identity cap, so a bearer invite admits a little
    /// burst of genuine joiners without becoming a free amplification channel.
    pub max_reservations_per_invite: u32,
    /// Total concurrent relayed circuits.
    pub max_circuits: u32,
    /// Maximum lifetime of a single circuit.
    ///
    /// Forces periodic renegotiation rather than indefinitely-held circuits.
    pub max_circuit_duration_millis: i64,
    /// Maximum bytes carried by a single circuit.
    ///
    /// Consistent with a relay's job being connection-establishment assistance,
    /// not sustained data transport — that is the separate media-relay role
    /// (§4.4), which this ceiling deliberately makes unattractive to abuse.
    pub max_circuit_bytes: u64,
}

impl Default for RelayLimits {
    fn default() -> Self {
        Self {
            max_reservations: 128,
            max_reservations_per_identity: 4,
            max_reservations_per_invite: 8,
            max_circuits: 32,
            max_circuit_duration_millis: 120_000,
            max_circuit_bytes: 8 * 1024 * 1024,
        }
    }
}

/// Why a relay request was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RelayDenied {
    /// The relay is at its global reservation ceiling.
    #[error("relay is at its reservation ceiling of {limit}")]
    ReservationCeiling {
        /// The configured ceiling.
        limit: u32,
    },

    /// This identity already holds its maximum reservations.
    #[error("identity {identity} already holds {limit} reservations")]
    IdentityCeiling {
        /// The identity.
        identity: String,
        /// The configured per-identity ceiling.
        limit: u32,
    },

    /// This invite has produced its maximum pre-admission reservations.
    #[error("invite {invite} already holds {limit} pre-admission reservations")]
    InviteCeiling {
        /// The invite, abbreviated.
        invite: String,
        /// The configured per-invite ceiling.
        limit: u32,
    },

    /// The relay is at its global circuit ceiling.
    #[error("relay is at its circuit ceiling of {limit}")]
    CircuitCeiling {
        /// The configured ceiling.
        limit: u32,
    },

    /// A circuit was requested without a live reservation.
    #[error("no live reservation for this request")]
    NoReservation,

    /// The referenced circuit is not open.
    #[error("no such open circuit")]
    NoCircuit,
}

/// Identifier for a granted reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, std::hash::Hash)]
pub struct ReservationId(u64);

/// Identifier for an open circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, std::hash::Hash)]
pub struct CircuitId(u64);

/// Why a circuit was closed by the relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitClosure {
    /// The circuit exceeded its maximum lifetime.
    DurationExceeded,
    /// The circuit exceeded its byte ceiling.
    ByteCeilingExceeded,
}

#[derive(Debug, Clone)]
struct Reservation {
    requester: Requester,
    #[allow(dead_code)]
    handle: TransportHandle,
    #[allow(dead_code)]
    granted_at: Timestamp,
}

#[derive(Debug, Clone)]
struct Circuit {
    reservation: ReservationId,
    opened_at: Timestamp,
    bytes: u64,
}

/// Enforces a relay's resource ceilings.
///
/// State is entirely in memory and disposable between restarts, which is a
/// deliberate design goal rather than an omission (§5.4): a relay that persists
/// nothing is cheap, interchangeable with any other relay a network designates,
/// and therefore reinforces takedown resistance.
#[derive(Debug, Clone)]
pub struct RelayGuard {
    limits: RelayLimits,
    reservations: BTreeMap<ReservationId, Reservation>,
    circuits: BTreeMap<CircuitId, Circuit>,
    next_id: u64,
}

impl RelayGuard {
    /// Creates a guard with the given limits.
    pub fn new(limits: RelayLimits) -> Self {
        Self {
            limits,
            reservations: BTreeMap::new(),
            circuits: BTreeMap::new(),
            next_id: 0,
        }
    }

    /// The configured limits.
    pub fn limits(&self) -> &RelayLimits {
        &self.limits
    }

    /// Requests a reservation, enforcing every applicable ceiling.
    pub fn try_reserve(
        &mut self,
        requester: Requester,
        handle: TransportHandle,
        now: Timestamp,
    ) -> Result<ReservationId, RelayDenied> {
        if self.reservations.len() as u32 >= self.limits.max_reservations {
            return Err(RelayDenied::ReservationCeiling {
                limit: self.limits.max_reservations,
            });
        }

        // Keyed on identity, never on `handle` — regenerating a transport
        // identity must not reset this count.
        let identity = requester.identity();
        let held = self
            .reservations
            .values()
            .filter(|reservation| reservation.requester.identity() == identity)
            .count() as u32;
        if held >= self.limits.max_reservations_per_identity {
            return Err(RelayDenied::IdentityCeiling {
                identity: identity.short(),
                limit: self.limits.max_reservations_per_identity,
            });
        }

        // Pre-admission identities are free to mint, so the invite is what
        // actually gets metered in that window.
        if let Some(invite) = requester.invite() {
            let per_invite = self
                .reservations
                .values()
                .filter(|reservation| reservation.requester.invite() == Some(invite))
                .count() as u32;
            if per_invite >= self.limits.max_reservations_per_invite {
                return Err(RelayDenied::InviteCeiling {
                    invite: invite.short(),
                    limit: self.limits.max_reservations_per_invite,
                });
            }
        }

        let id = ReservationId(self.take_id());
        self.reservations.insert(
            id,
            Reservation {
                requester,
                handle,
                granted_at: now,
            },
        );
        Ok(id)
    }

    /// Releases a reservation and closes any circuits opened under it.
    pub fn release(&mut self, reservation: ReservationId) {
        self.reservations.remove(&reservation);
        self.circuits
            .retain(|_, circuit| circuit.reservation != reservation);
    }

    /// Opens a circuit against a live reservation.
    ///
    /// Requiring a [`ReservationId`] is what makes the reservation check
    /// unskippable: there is no way to obtain a circuit without having passed
    /// the reservation ceilings first.
    pub fn open_circuit(
        &mut self,
        reservation: ReservationId,
        now: Timestamp,
    ) -> Result<CircuitId, RelayDenied> {
        if !self.reservations.contains_key(&reservation) {
            return Err(RelayDenied::NoReservation);
        }
        if self.circuits.len() as u32 >= self.limits.max_circuits {
            return Err(RelayDenied::CircuitCeiling {
                limit: self.limits.max_circuits,
            });
        }

        let id = CircuitId(self.take_id());
        self.circuits.insert(
            id,
            Circuit {
                reservation,
                opened_at: now,
                bytes: 0,
            },
        );
        Ok(id)
    }

    /// Records bytes carried by a circuit, closing it if it exceeds its ceiling.
    ///
    /// Returns `Ok(Some(_))` when the circuit was closed as a result — the
    /// closure has *already happened* by the time this returns, so a caller that
    /// ignores the return value still cannot keep using the circuit.
    pub fn record_bytes(
        &mut self,
        circuit: CircuitId,
        bytes: u64,
    ) -> Result<Option<CircuitClosure>, RelayDenied> {
        let entry = self.circuits.get_mut(&circuit).ok_or(RelayDenied::NoCircuit)?;
        entry.bytes = entry.bytes.saturating_add(bytes);

        if entry.bytes > self.limits.max_circuit_bytes {
            self.circuits.remove(&circuit);
            return Ok(Some(CircuitClosure::ByteCeilingExceeded));
        }
        Ok(None)
    }

    /// Closes every circuit that has outlived its maximum duration.
    ///
    /// Returns what it closed. Callers drive this from their event loop; the
    /// closure is applied here regardless of what the caller does with the list.
    pub fn expire(&mut self, now: Timestamp) -> Vec<(CircuitId, CircuitClosure)> {
        let expired: Vec<CircuitId> = self
            .circuits
            .iter()
            .filter(|(_, circuit)| {
                now.millis_since(circuit.opened_at) > self.limits.max_circuit_duration_millis
            })
            .map(|(id, _)| *id)
            .collect();

        for id in &expired {
            self.circuits.remove(id);
        }
        expired
            .into_iter()
            .map(|id| (id, CircuitClosure::DurationExceeded))
            .collect()
    }

    /// Closes a circuit that ended normally.
    pub fn close_circuit(&mut self, circuit: CircuitId) {
        self.circuits.remove(&circuit);
    }

    /// Current number of live reservations.
    pub fn reservation_count(&self) -> usize {
        self.reservations.len()
    }

    /// Current number of open circuits.
    pub fn circuit_count(&self) -> usize {
        self.circuits.len()
    }

    /// Live reservations held by one identity.
    pub fn reservations_for(&self, identity: &PerNetworkIdentityId) -> usize {
        self.reservations
            .values()
            .filter(|reservation| reservation.requester.identity() == identity)
            .count()
    }

    /// Live pre-admission reservations metered against one invite.
    pub fn reservations_for_invite(&self, invite: &Hash) -> usize {
        self.reservations
            .values()
            .filter(|reservation| reservation.requester.invite() == Some(invite))
            .count()
    }

    fn take_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }
}
