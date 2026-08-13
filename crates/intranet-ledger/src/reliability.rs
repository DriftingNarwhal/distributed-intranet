//! Locally observed reliability and its audit path — Core Protocol Spec §4.6.
//!
//! # Passive, opportunistic, essentially free
//!
//! Every node already verifies signatures and content hashes as a mandatory
//! correctness step on everything it receives. This widens that into a
//! lightweight reputation signal at no meaningful extra cost: when verification
//! of something from a peer fails, the node increments a local counter instead
//! of just discarding the bad data. No probing, no health-checking, no new
//! network traffic.
//!
//! # Local, never gossiped — and that is load-bearing
//!
//! A shared, network-wide reputation score would be vulnerable to coordinated
//! slander: a group of colluding nodes could tank a target's score. A private,
//! per-observer signal is not. This is why [`ReliabilityObservations`] has no
//! serialization or advertisement path, and why [`crate::placement`] cannot
//! accept it as an input.
//!
//! # A soft signal for selection only
//!
//! It biases *local* candidate choices — which source to fetch a chunk from,
//! which relay to route a call through. It never gates group membership or
//! capabilities, and never triggers automated revocation. Revocation remains a
//! deliberate action by a capability holder, never something the protocol does
//! on its own based on a score.

use crate::LedgerError;
use intranet_crypto::{Enc, Signature, Timestamp};
use intranet_governance::{Capability, GovernanceState};
use intranet_identity::{PerNetworkIdentity, PerNetworkIdentityId};
use std::collections::BTreeMap;

/// Domain tag for audit request signatures.
const AUDIT_REQUEST_DOMAIN: &str = "intranet.reputation-audit-request.v1";

/// Domain tag for audit response signatures.
const AUDIT_RESPONSE_DOMAIN: &str = "intranet.reputation-audit-response.v1";

/// What one node has observed about one peer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PeerObservations {
    /// Items from this peer that verified correctly.
    pub verified: u64,
    /// Items from this peer that failed verification.
    pub failed: u64,
}

impl PeerObservations {
    /// Total items observed.
    pub fn total(&self) -> u64 {
        self.verified.saturating_add(self.failed)
    }

    /// Failure rate in `[0.0, 1.0]`, or `None` when nothing has been observed.
    ///
    /// Returns `None` rather than 0.0 for an unobserved peer, because "no
    /// evidence" and "evidence of reliability" are different things and
    /// collapsing them would let an unknown peer look as good as a proven one.
    pub fn failure_rate(&self) -> Option<f64> {
        let total = self.total();
        (total > 0).then(|| self.failed as f64 / total as f64)
    }
}

/// One node's private observations about its peers.
///
/// Deliberately has no serialization: this state is never gossiped, and the
/// only way it leaves the node is through an authorized [`AuditRequest`].
#[derive(Debug, Clone, Default)]
pub struct ReliabilityObservations {
    counters: BTreeMap<PerNetworkIdentityId, PeerObservations>,
    audit_log: BTreeMap<PerNetworkIdentityId, Vec<Timestamp>>,
}

impl ReliabilityObservations {
    /// Creates an empty observation store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a successful verification of something received from `peer`.
    pub fn record_verified(&mut self, peer: PerNetworkIdentityId) {
        let entry = self.counters.entry(peer).or_default();
        entry.verified = entry.verified.saturating_add(1);
    }

    /// Records a failed verification of something received from `peer`.
    ///
    /// Called from the paths that already had to verify for correctness anyway:
    /// swarm chunk hashes, gossiped ballots, governance log entries, relay
    /// traffic. There is no separate probing path that calls this.
    pub fn record_failed(&mut self, peer: PerNetworkIdentityId) {
        let entry = self.counters.entry(peer).or_default();
        entry.failed = entry.failed.saturating_add(1);
    }

    /// What this node has observed about `peer`.
    pub fn for_peer(&self, peer: &PerNetworkIdentityId) -> PeerObservations {
        self.counters.get(peer).copied().unwrap_or_default()
    }

    /// Peers this node has observed at all.
    pub fn observed_peers(&self) -> impl Iterator<Item = &PerNetworkIdentityId> {
        self.counters.keys()
    }

    /// Orders `candidates` worst-observed last, for local selection only.
    ///
    /// A stable partition rather than a score: peers with no observations sit
    /// between proven-good and proven-bad, so an unknown peer is neither
    /// promoted over a reliable one nor punished as though it had failed.
    pub fn deprioritize_unreliable(
        &self,
        candidates: &mut [PerNetworkIdentityId],
        failure_threshold: f64,
    ) {
        candidates.sort_by_key(|peer| {
            match self.for_peer(peer).failure_rate() {
                Some(rate) if rate >= failure_threshold => 2u8,
                None => 1,
                Some(_) => 0,
            }
        });
    }

    /// Answers an audit request — §4.6.
    ///
    /// Responding is **mandatory but rate-limited**. Mandatory because allowing
    /// refusal would let a compromised node simply decline audits of itself,
    /// creating an obvious blind spot. Rate-limited so the audit mechanism
    /// cannot itself be turned into a way to harass or overload a member.
    ///
    /// The response is this node's **raw local counters, signed** — no
    /// interpretation, no network-wide aggregation. The requester's value comes
    /// from cross-referencing many unrelated observers: a pattern of failures
    /// reported independently by many nodes is meaningfully stronger evidence
    /// than any single node's opinion, and is what an admin should have in hand
    /// before exercising `revoke-node`.
    pub fn respond_to_audit(
        &mut self,
        request: &AuditRequest,
        responder: &PerNetworkIdentity,
        state: &GovernanceState,
        now: Timestamp,
        policy: AuditRateLimit,
    ) -> Result<AuditResponse, LedgerError> {
        request.verify()?;

        if !state.identity_holds(&request.requester, &Capability::AuditReputation) {
            return Err(LedgerError::AuditNotAuthorized {
                requester: request.requester.short(),
            });
        }

        let history = self.audit_log.entry(request.requester).or_default();
        history.retain(|at| now.millis_since(*at) <= policy.window_millis);
        if history.len() as u32 >= policy.max_requests_per_window {
            return Err(LedgerError::AuditRateLimited {
                requester: request.requester.short(),
                max_requests: policy.max_requests_per_window,
            });
        }
        history.push(now);

        let observations = self.for_peer(&request.subject);
        Ok(AuditResponse::create(
            responder,
            request,
            observations,
            now,
        ))
    }
}

/// How often one requester may audit this node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditRateLimit {
    /// Requests permitted per window.
    pub max_requests_per_window: u32,
    /// Window length in milliseconds.
    pub window_millis: i64,
}

impl Default for AuditRateLimit {
    fn default() -> Self {
        // **Flagged: the specs require rate limiting but give no numbers.**
        // Oversight is an occasional investigative act, not a polling loop, so
        // a handful per hour is generous for the legitimate use and useless as
        // a harassment channel.
        Self {
            max_requests_per_window: 6,
            window_millis: 60 * 60_000,
        }
    }
}

/// A signed request for a node's raw observations about a third party.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRequest {
    /// Who is asking. Must hold `audit-reputation`.
    pub requester: PerNetworkIdentityId,
    /// The peer whose reputation is being investigated.
    pub subject: PerNetworkIdentityId,
    /// When the request was made.
    pub issued_at: Timestamp,
    /// The requester's signature.
    pub signature: Signature,
}

impl AuditRequest {
    /// Builds and signs an audit request.
    pub fn create(
        requester: &PerNetworkIdentity,
        subject: PerNetworkIdentityId,
        issued_at: Timestamp,
    ) -> Self {
        let requester_id = requester.id();
        let payload = Self::payload(&requester_id, &subject, issued_at);
        Self {
            requester: requester_id,
            subject,
            issued_at,
            signature: requester.sign(&payload),
        }
    }

    /// Verifies the request's signature.
    pub fn verify(&self) -> Result<(), LedgerError> {
        let payload = Self::payload(&self.requester, &self.subject, self.issued_at);
        self.requester
            .verifying_key()
            .verify(&payload, &self.signature)
            .map_err(|_| LedgerError::BadSignature)
    }

    fn payload(
        requester: &PerNetworkIdentityId,
        subject: &PerNetworkIdentityId,
        issued_at: Timestamp,
    ) -> Enc {
        let mut e = Enc::domain(AUDIT_REQUEST_DOMAIN);
        requester.encode(&mut e);
        subject.encode(&mut e);
        e.i64(issued_at.as_millis());
        e
    }
}

/// A signed disclosure of one node's raw counters about a subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditResponse {
    /// The node disclosing its observations.
    pub responder: PerNetworkIdentityId,
    /// Who asked.
    pub requester: PerNetworkIdentityId,
    /// Who the observations concern.
    pub subject: PerNetworkIdentityId,
    /// The raw counters, uninterpreted.
    pub observations: PeerObservations,
    /// When the response was produced.
    pub responded_at: Timestamp,
    /// The responder's signature.
    pub signature: Signature,
}

impl AuditResponse {
    fn create(
        responder: &PerNetworkIdentity,
        request: &AuditRequest,
        observations: PeerObservations,
        responded_at: Timestamp,
    ) -> Self {
        let responder_id = responder.id();
        let payload = Self::payload(
            &responder_id,
            &request.requester,
            &request.subject,
            observations,
            responded_at,
        );
        Self {
            responder: responder_id,
            requester: request.requester,
            subject: request.subject,
            observations,
            responded_at,
            signature: responder.sign(&payload),
        }
    }

    /// Verifies the response's signature.
    ///
    /// Signed so a requester cross-referencing many responses can prove each one
    /// came from the node it claims to — otherwise the corroboration the whole
    /// mechanism rests on could be manufactured by the requester itself.
    pub fn verify(&self) -> Result<(), LedgerError> {
        let payload = Self::payload(
            &self.responder,
            &self.requester,
            &self.subject,
            self.observations,
            self.responded_at,
        );
        self.responder
            .verifying_key()
            .verify(&payload, &self.signature)
            .map_err(|_| LedgerError::BadSignature)
    }

    fn payload(
        responder: &PerNetworkIdentityId,
        requester: &PerNetworkIdentityId,
        subject: &PerNetworkIdentityId,
        observations: PeerObservations,
        responded_at: Timestamp,
    ) -> Enc {
        let mut e = Enc::domain(AUDIT_RESPONSE_DOMAIN);
        responder.encode(&mut e);
        requester.encode(&mut e);
        subject.encode(&mut e);
        e.u64(observations.verified)
            .u64(observations.failed)
            .i64(responded_at.as_millis());
        e
    }
}
