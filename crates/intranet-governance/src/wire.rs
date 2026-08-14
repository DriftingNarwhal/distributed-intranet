//! Wire encoding for governance log entries and the sync protocol — §2.7, §5.1.
//!
//! # Why the log needs a codec at all
//!
//! Until now every governance value was built locally and only ever *encoded*,
//! for hashing and signing. Gossip is the first thing that has to go the other
//! way: an entry arrives from a peer as bytes, and something must turn it back
//! into a [`LogEntry`].
//!
//! # The property that makes a hand-written codec safe
//!
//! A second representation of a signed type is a genuine hazard. If the decoder
//! disagrees with the encoder anywhere — two fields transposed, a variant tag
//! read as its neighbour — the result is a structurally valid entry that is not
//! the entry the author signed. Entry hashes drive the fork-choice tie-break
//! (§2.7.1 point 1), so a node that decoded differently would compute different
//! hashes and stop converging, silently, which is precisely the failure this
//! project's hand-written canonical encoding exists to prevent.
//!
//! So nothing here trusts the decoder. [`decode_entry`] reconstructs the entry
//! and then re-verifies the author's signature over the *canonically re-encoded*
//! payload. Because that payload is produced by the same `encode` path used at
//! signing time, any disagreement between this module and the canonical encoding
//! changes the signed bytes and the signature fails. A codec bug is therefore a
//! rejected entry, not a divergent network.
//!
//! That check also does the security work: an entry cannot be forged or tampered
//! with in flight, since the signature is over the author's own key.
//!
//! # Sync protocol
//!
//! Deliberately pull-based, and deliberately not a new transport primitive —
//! §2.7 requires the log to need "no new storage or transport primitive beyond
//! what's already specified in §5.1", and §5.1 names no pubsub mechanism. This
//! is a request/response protocol over the libp2p streams already in use:
//!
//! ```text
//! A --> B   Heads                     "what are your branch tips?"
//! B --> A   Heads { heads }
//! A --> B   Fetch { wanted, have }    "send these, minus anything under `have`"
//! B --> A   Entries { entries }       ordered ancestors-first
//! ```
//!
//! Both sides run it independently on every connection, which is what makes
//! partition healing fall out for free: a heal is just a reconnect, and a
//! reconnect is a sync. There is no separate catch-up path that could rot.
//!
//! **Ordering is load-bearing.** [`GovernanceLog::insert`](crate::GovernanceLog::insert)
//! refuses an entry whose parent it has never seen, so entries must arrive
//! ancestors-first or they are dropped — and a dropped entry looks exactly like
//! one that was never sent. [`ancestors_first`] is the single place that
//! ordering is established.

use crate::{
    AdmissionMode, AppName, Capability, CapabilitySet, Cascade, ContentType, EntryBody,
    FinalityParams, GovernanceModel, GroupId, HistoryAccess, InviteProvenance, LogEntry,
    MembershipAction, ModerationAction, ModerationEntry, NetworkPolicy, PointerId, RotationReason,
    Tier,
};
use intranet_crypto::{Dec, DecodeError, Enc, Hash, Signature, Timestamp};
use intranet_identity::{
    DeviceCertificate, DeviceCertificateRevocation, DevicePublicKey, NetworkId,
    PerNetworkIdentityId,
};
use std::collections::{BTreeMap, BTreeSet};

/// Domain tag for an entry on the wire.
///
/// Distinct from the entry's *hash* domain on purpose: these bytes are a
/// transport framing, not the thing anyone signed, and tagging them separately
/// means a wire message can never be mistaken for a signable payload.
const ENTRY_WIRE_DOMAIN: &str = "intranet.wire.entry.v1";
/// Domain tag for a sync request.
const REQUEST_DOMAIN: &str = "intranet.wire.sync-request.v1";
/// Domain tag for a sync response.
const RESPONSE_DOMAIN: &str = "intranet.wire.sync-response.v1";

/// Why a message could not be turned into a value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    /// The bytes were malformed.
    #[error("malformed message: {0}")]
    Malformed(#[from] DecodeError),
    /// A public key on the wire was not a valid point.
    #[error("invalid public key in message")]
    InvalidKey,
    /// The entry decoded, but its signature did not verify.
    ///
    /// This is the check that makes a hand-written decoder safe (see the module
    /// docs). It fires both for a tampered entry and for a codec that disagrees
    /// with the canonical encoding, which is why the two are not distinguished:
    /// in both cases the bytes are not something an author signed.
    #[error("entry signature did not verify after decoding")]
    BadSignature,
}

// ---------------------------------------------------------------------------
// Entries
// ---------------------------------------------------------------------------

/// Encodes an entry for transmission.
pub fn encode_entry(entry: &LogEntry) -> Vec<u8> {
    let mut e = Enc::domain(ENTRY_WIRE_DOMAIN);
    put_entry(&mut e, entry);
    e.finish()
}

/// Decodes an entry and verifies its signature.
///
/// The verification is not optional and not the caller's job — see the module
/// docs. An entry that reaches a caller has been authenticated.
pub fn decode_entry(bytes: &[u8]) -> Result<LogEntry, WireError> {
    let mut d = Dec::domain(bytes, ENTRY_WIRE_DOMAIN)?;
    let entry = get_entry(&mut d)?;
    d.finish()?;
    entry.verify_signature().map_err(|_| WireError::BadSignature)?;
    Ok(entry)
}

fn put_entry(e: &mut Enc, entry: &LogEntry) {
    e.option(entry.parent.as_ref(), |e, hash| {
        e.fixed(hash.as_bytes());
    });
    e.i64(entry.timestamp.as_millis());
    entry.author.encode(e);
    put_body(e, &entry.body);
    e.fixed(entry.signature.as_bytes());
}

fn get_entry(d: &mut Dec<'_>) -> Result<LogEntry, WireError> {
    let parent = d
        .option::<_, WireError>(|d| Ok(d.fixed::<32>()?))?
        .map(Hash::from_bytes);
    let timestamp = Timestamp::from_millis(d.i64()?);
    let author = get_identity(d)?;
    let body = get_body(d)?;
    let signature = Signature::from_bytes(d.fixed::<64>()?);
    Ok(LogEntry {
        parent,
        timestamp,
        author,
        body,
        signature,
    })
}

// ---------------------------------------------------------------------------
// Entry bodies
//
// Variant tags mirror `EntryBody::encode` exactly, including the fact that
// `AppNameRegistration` is 9 and `Moderation` is 8 despite their declaration
// order. Reordering them here to look tidier would change what a tag means and
// break every signature.
// ---------------------------------------------------------------------------

fn put_body(e: &mut Enc, body: &EntryBody) {
    match body {
        EntryBody::Genesis {
            network,
            policy,
            everyone_capabilities,
        } => {
            e.variant(0);
            network.encode(e);
            put_policy(e, policy);
            e.seq(everyone_capabilities.iter(), |e, c| c.encode(e));
        }
        EntryBody::DefineGroup {
            group,
            capabilities,
        } => {
            e.variant(1).str(group.as_str());
            capabilities.encode(e);
        }
        EntryBody::MembershipChange {
            group,
            identity,
            action,
        } => {
            e.variant(2).str(group.as_str());
            identity.encode(e);
            match action {
                MembershipAction::Add { via_invite } => {
                    e.variant(0);
                    e.option(via_invite.as_ref(), |e, p| p.encode(e));
                }
                MembershipAction::Remove { cascade } => {
                    e.variant(1);
                    e.option(cascade.as_ref(), |e, c| {
                        e.option(c.window_millis.as_ref(), |e, w| {
                            e.i64(*w);
                        });
                    });
                }
            }
        }
        EntryBody::PolicyChange { policy } => {
            e.variant(3);
            put_policy(e, policy);
        }
        EntryBody::ContentTypePolicy { allowlist } => {
            e.variant(4);
            e.seq(allowlist.iter(), |e, t| {
                e.str(t.as_str());
            });
        }
        EntryBody::EpochRotation { reason } => {
            e.variant(5).u8(match reason {
                RotationReason::MembershipChange => 0,
                RotationReason::SelfInitiated => 1,
            });
        }
        EntryBody::DeviceEnrollment(cert) => {
            e.variant(6);
            cert.network.encode(e);
            cert.identity.encode(e);
            cert.device.encode(e);
            e.str(&cert.label)
                .i64(cert.issued_at.as_millis())
                .fixed(cert.signature.as_bytes());
        }
        EntryBody::DeviceRevocation(revocation) => {
            e.variant(7);
            revocation.network.encode(e);
            revocation.identity.encode(e);
            revocation.device.encode(e);
            e.i64(revocation.revoked_at.as_millis())
                .fixed(revocation.signature.as_bytes());
        }
        EntryBody::Moderation(moderation) => {
            e.variant(8)
                .u8(match moderation.action {
                    ModerationAction::Delist => 0,
                    ModerationAction::Relist => 1,
                })
                .fixed(moderation.target_pointer_id.as_bytes());
        }
        EntryBody::AppNameRegistration { name, app_id } => {
            e.variant(9).str(name.as_str()).fixed(app_id.as_bytes());
        }
    }
}

fn get_body(d: &mut Dec<'_>) -> Result<EntryBody, WireError> {
    Ok(match d.variant()? {
        0 => EntryBody::Genesis {
            network: NetworkId::from_bytes(d.fixed::<32>()?),
            policy: get_policy(d)?,
            everyone_capabilities: d.seq::<_, WireError>(get_capability)?.into_iter().collect(),
        },
        1 => EntryBody::DefineGroup {
            group: GroupId::new(d.str()?),
            capabilities: get_capability_set(d)?,
        },
        2 => {
            let group = GroupId::new(d.str()?);
            let identity = get_identity(d)?;
            let action = match d.variant()? {
                0 => MembershipAction::Add {
                    via_invite: d.option::<_, WireError>(get_invite_provenance)?,
                },
                1 => MembershipAction::Remove {
                    cascade: d.option::<_, WireError>(|d| {
                        Ok(Cascade {
                            window_millis: d.option::<_, WireError>(|d| Ok(d.i64()?))?,
                        })
                    })?,
                },
                other => return Err(unknown("MembershipAction", other)),
            };
            EntryBody::MembershipChange {
                group,
                identity,
                action,
            }
        }
        3 => EntryBody::PolicyChange {
            policy: get_policy(d)?,
        },
        4 => EntryBody::ContentTypePolicy {
            allowlist: d
                .seq::<_, WireError>(|d| Ok(ContentType::new(d.str()?)))?
                .into_iter()
                .collect(),
        },
        5 => EntryBody::EpochRotation {
            reason: match d.u8()? {
                0 => RotationReason::MembershipChange,
                1 => RotationReason::SelfInitiated,
                other => return Err(unknown("RotationReason", other)),
            },
        },
        6 => EntryBody::DeviceEnrollment(DeviceCertificate {
            network: NetworkId::from_bytes(d.fixed::<32>()?),
            identity: get_identity(d)?,
            device: get_device_key(d)?,
            label: d.str()?.to_owned(),
            issued_at: Timestamp::from_millis(d.i64()?),
            signature: Signature::from_bytes(d.fixed::<64>()?),
        }),
        7 => EntryBody::DeviceRevocation(DeviceCertificateRevocation {
            network: NetworkId::from_bytes(d.fixed::<32>()?),
            identity: get_identity(d)?,
            device: get_device_key(d)?,
            revoked_at: Timestamp::from_millis(d.i64()?),
            signature: Signature::from_bytes(d.fixed::<64>()?),
        }),
        8 => EntryBody::Moderation(ModerationEntry {
            action: match d.u8()? {
                0 => ModerationAction::Delist,
                1 => ModerationAction::Relist,
                other => return Err(unknown("ModerationAction", other)),
            },
            target_pointer_id: PointerId::from_bytes(d.fixed::<32>()?),
        }),
        9 => EntryBody::AppNameRegistration {
            name: AppName::new(d.str()?),
            app_id: PointerId::from_bytes(d.fixed::<32>()?),
        },
        other => return Err(unknown("EntryBody", other)),
    })
}

// ---------------------------------------------------------------------------
// Policy and capabilities
// ---------------------------------------------------------------------------

fn put_policy(e: &mut Enc, policy: &NetworkPolicy) {
    policy.encode(e);
}

fn get_policy(d: &mut Dec<'_>) -> Result<NetworkPolicy, WireError> {
    let admission_mode = match d.variant()? {
        0 => AdmissionMode::AutoAdmit,
        1 => AdmissionMode::ExplicitIntake,
        other => return Err(unknown("AdmissionMode", other)),
    };
    let governance_model = match d.variant()? {
        0 => GovernanceModel::CapabilityHolders,
        1 => GovernanceModel::MemberVote {
            electorate: GroupId::new(d.str()?),
            quorum: d.u32()?,
            window_millis: d.i64()?,
        },
        other => return Err(unknown("GovernanceModel", other)),
    };
    let history_access = match d.variant()? {
        0 => HistoryAccess::CurrentEpochForward,
        1 => HistoryAccess::FullHistory,
        other => return Err(unknown("HistoryAccess", other)),
    };
    let content_type_allowlist: BTreeSet<ContentType> = d
        .seq::<_, WireError>(|d| Ok(ContentType::new(d.str()?)))?
        .into_iter()
        .collect();
    let extension_capabilities: BTreeMap<String, Tier> = d
        .seq::<_, WireError>(|d| {
            let name = d.str()?.to_owned();
            let tier = match d.u8()? {
                0 => Tier::Ordinary,
                1 => Tier::Governance,
                other => return Err(unknown("Tier", other)),
            };
            Ok((name, tier))
        })?
        .into_iter()
        .collect();
    let finality = FinalityParams {
        k: d.u32()?,
        t_millis: d.i64()?,
    };
    // Encoded as a `u32` via `u32::from`, so a value that does not fit back into
    // a `u16` is a message this build cannot represent rather than something to
    // silently truncate.
    let replication_factor = u16::try_from(d.u32()?).map_err(|_| {
        WireError::Malformed(DecodeError::ImplausibleLength {
            claimed: u64::from(u32::MAX),
            remaining: 0,
        })
    })?;
    Ok(NetworkPolicy {
        admission_mode,
        governance_model,
        history_access,
        content_type_allowlist,
        extension_capabilities,
        finality,
        replication_factor,
        mesh_relay_threshold: d.u8()?,
        target_chunk_size: d.u32()?,
    })
}

fn get_capability(d: &mut Dec<'_>) -> Result<Capability, WireError> {
    Ok(match d.variant()? {
        0 => Capability::ApproveNode,
        1 => Capability::RevokeNode,
        2 => Capability::DefineGroup,
        3 => Capability::DefinePolicy,
        4 => Capability::DefineContentPolicy,
        5 => Capability::ModerateContent,
        6 => Capability::AuditReputation,
        7 => Capability::ReadContent,
        8 => Capability::ManageMembership(GroupId::new(d.str()?)),
        9 => Capability::Publish(ContentType::new(d.str()?)),
        10 => Capability::Extension(d.str()?.to_owned()),
        other => return Err(unknown("Capability", other)),
    })
}

fn get_capability_set(d: &mut Dec<'_>) -> Result<CapabilitySet, WireError> {
    Ok(match d.variant()? {
        0 => CapabilitySet::All,
        1 => CapabilitySet::Explicit(d.seq::<_, WireError>(get_capability)?.into_iter().collect()),
        other => return Err(unknown("CapabilitySet", other)),
    })
}

// ---------------------------------------------------------------------------
// Identity primitives
// ---------------------------------------------------------------------------

fn get_identity(d: &mut Dec<'_>) -> Result<PerNetworkIdentityId, WireError> {
    let key = intranet_crypto::VerifyingKey::from_bytes(d.fixed::<32>()?)
        .map_err(|_| WireError::InvalidKey)?;
    Ok(PerNetworkIdentityId::from_verifying_key(key))
}

fn get_device_key(d: &mut Dec<'_>) -> Result<DevicePublicKey, WireError> {
    let key = intranet_crypto::VerifyingKey::from_bytes(d.fixed::<32>()?)
        .map_err(|_| WireError::InvalidKey)?;
    Ok(DevicePublicKey::from_verifying_key(key))
}

fn get_invite_provenance(d: &mut Dec<'_>) -> Result<InviteProvenance, WireError> {
    Ok(InviteProvenance {
        invite_id: Hash::from_bytes(d.fixed::<32>()?),
        issuer: get_identity(d)?,
    })
}

fn unknown(type_name: &'static str, discriminant: u8) -> WireError {
    WireError::Malformed(DecodeError::UnknownVariant {
        type_name,
        discriminant,
    })
}

// ---------------------------------------------------------------------------
// Sync protocol
// ---------------------------------------------------------------------------

/// The most entries one response will carry.
///
/// **Flagged: the specs set no bound on a sync response.** A cap is needed
/// regardless, because a response is built from a peer's request and an
/// unbounded one is a memory amplification vector. 512 is chosen to be far above
/// any plausible partition's divergence while staying a bounded allocation; a
/// requester that needs more simply asks again, since the protocol is pull-based
/// and resuming is just another `Fetch`.
pub const MAX_ENTRIES_PER_RESPONSE: usize = 512;

/// A request in the pull-based sync protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncRequest {
    /// Ask for the peer's branch tips.
    Heads,
    /// Ask for specific entries and their ancestry.
    Fetch {
        /// Branch tips the requester wants.
        wanted: Vec<Hash>,
        /// Tips the requester already holds, so their ancestry can be skipped.
        ///
        /// Purely an optimization, and safe to ignore: a responder that sends
        /// more than needed is merely wasteful, since re-inserting an entry a
        /// node already has is idempotent. Without it, every heal would re-send
        /// the whole log.
        have: Vec<Hash>,
    },
}

/// A response in the pull-based sync protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncResponse {
    /// The responder's branch tips.
    Heads {
        /// Tips of every branch the responder holds.
        heads: Vec<Hash>,
    },
    /// Entries, ordered ancestors-first.
    Entries {
        /// The entries, in an order the receiver can insert directly.
        entries: Vec<LogEntry>,
        /// Whether the response was truncated at [`MAX_ENTRIES_PER_RESPONSE`].
        ///
        /// Reported rather than left implicit so a caller can tell "you now have
        /// everything" from "ask again" — a truncated sync that looked complete
        /// would leave the log permanently short of the peer's, with nothing
        /// indicating why.
        truncated: bool,
    },
}

impl SyncRequest {
    /// Encodes the request.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::domain(REQUEST_DOMAIN);
        match self {
            Self::Heads => {
                e.variant(0);
            }
            Self::Fetch { wanted, have } => {
                e.variant(1);
                e.seq(wanted.iter(), |e, h| {
                    e.fixed(h.as_bytes());
                });
                e.seq(have.iter(), |e, h| {
                    e.fixed(h.as_bytes());
                });
            }
        }
        e.finish()
    }

    /// Decodes a request.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut d = Dec::domain(bytes, REQUEST_DOMAIN)?;
        let request = match d.variant()? {
            0 => Self::Heads,
            1 => Self::Fetch {
                wanted: d.seq::<_, WireError>(|d| Ok(Hash::from_bytes(d.fixed::<32>()?)))?,
                have: d.seq::<_, WireError>(|d| Ok(Hash::from_bytes(d.fixed::<32>()?)))?,
            },
            other => return Err(unknown("SyncRequest", other)),
        };
        d.finish()?;
        Ok(request)
    }
}

impl SyncResponse {
    /// Encodes the response.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::domain(RESPONSE_DOMAIN);
        match self {
            Self::Heads { heads } => {
                e.variant(0);
                e.seq(heads.iter(), |e, h| {
                    e.fixed(h.as_bytes());
                });
            }
            Self::Entries { entries, truncated } => {
                e.variant(1);
                e.seq(entries.iter(), |e, entry| {
                    // Nested inside a length prefix so one malformed entry is a
                    // bounded parse failure rather than desynchronizing the rest
                    // of the response.
                    e.bytes(&encode_entry(entry));
                });
                e.bool(*truncated);
            }
        }
        e.finish()
    }

    /// Decodes a response, verifying every entry's signature.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut d = Dec::domain(bytes, RESPONSE_DOMAIN)?;
        let response = match d.variant()? {
            0 => Self::Heads {
                heads: d.seq::<_, WireError>(|d| Ok(Hash::from_bytes(d.fixed::<32>()?)))?,
            },
            1 => Self::Entries {
                entries: d
                    .seq::<_, WireError>(|d| Ok(d.bytes()?.to_vec()))?
                    .iter()
                    .map(|bytes| decode_entry(bytes))
                    .collect::<Result<Vec<_>, _>>()?,
                truncated: d.bool()?,
            },
            other => return Err(unknown("SyncResponse", other)),
        };
        d.finish()?;
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GovernanceLog, starter_content_types};
    use intranet_identity::{MasterSeed, PerNetworkIdentity};

    fn identity(n: u8) -> PerNetworkIdentity {
        MasterSeed::from_entropy([n; 32])
            .identity_for(&NetworkId::from_bytes([42u8; 32]))
            .unwrap()
    }

    fn genesis(author: &PerNetworkIdentity) -> LogEntry {
        LogEntry::create(
            author,
            None,
            Timestamp::from_millis(0),
            EntryBody::Genesis {
                network: NetworkId::from_bytes([42u8; 32]),
                policy: NetworkPolicy::conservative_default(),
                everyone_capabilities: [Capability::ReadContent].into_iter().collect(),
            },
        )
    }

    /// Every body variant, so no variant can be added without a round-trip test.
    fn every_body() -> Vec<EntryBody> {
        vec![
            EntryBody::Genesis {
                network: NetworkId::from_bytes([42u8; 32]),
                policy: NetworkPolicy {
                    governance_model: GovernanceModel::MemberVote {
                        electorate: GroupId::new("voters"),
                        quorum: 3,
                        window_millis: 9_000,
                    },
                    history_access: HistoryAccess::FullHistory,
                    admission_mode: AdmissionMode::ExplicitIntake,
                    content_type_allowlist: starter_content_types(),
                    extension_capabilities: [
                        ("ext.one".to_owned(), Tier::Ordinary),
                        ("ext.two".to_owned(), Tier::Governance),
                    ]
                    .into_iter()
                    .collect(),
                    ..NetworkPolicy::conservative_default()
                },
                everyone_capabilities: [Capability::ReadContent].into_iter().collect(),
            },
            EntryBody::DefineGroup {
                group: GroupId::new("admins"),
                capabilities: CapabilitySet::Explicit(
                    [
                        Capability::ApproveNode,
                        Capability::ManageMembership(GroupId::new("crew")),
                        Capability::Publish(ContentType::new("text/plain")),
                        Capability::Extension("ext.one".to_owned()),
                    ]
                    .into_iter()
                    .collect(),
                ),
            },
            EntryBody::DefineGroup {
                group: GroupId::new("founders"),
                capabilities: CapabilitySet::All,
            },
            EntryBody::MembershipChange {
                group: GroupId::new("crew"),
                identity: identity(2).id(),
                action: MembershipAction::Add {
                    via_invite: Some(InviteProvenance {
                        invite_id: Hash::from_bytes([3u8; 32]),
                        issuer: identity(1).id(),
                    }),
                },
            },
            EntryBody::MembershipChange {
                group: GroupId::new("crew"),
                identity: identity(2).id(),
                action: MembershipAction::Add { via_invite: None },
            },
            EntryBody::MembershipChange {
                group: GroupId::new("crew"),
                identity: identity(2).id(),
                action: MembershipAction::Remove {
                    cascade: Some(Cascade {
                        window_millis: Some(48 * 3_600_000),
                    }),
                },
            },
            EntryBody::MembershipChange {
                group: GroupId::new("crew"),
                identity: identity(2).id(),
                action: MembershipAction::Remove {
                    cascade: Some(Cascade {
                        window_millis: None,
                    }),
                },
            },
            EntryBody::MembershipChange {
                group: GroupId::new("crew"),
                identity: identity(2).id(),
                action: MembershipAction::Remove { cascade: None },
            },
            EntryBody::PolicyChange {
                policy: NetworkPolicy::conservative_default(),
            },
            EntryBody::ContentTypePolicy {
                allowlist: starter_content_types(),
            },
            EntryBody::EpochRotation {
                reason: RotationReason::MembershipChange,
            },
            EntryBody::EpochRotation {
                reason: RotationReason::SelfInitiated,
            },
            EntryBody::DeviceEnrollment(DeviceCertificate::issue(
                &identity(1),
                DevicePublicKey::from_verifying_key(*identity(5).id().verifying_key()),
                "laptop".to_owned(),
                Timestamp::from_millis(11),
            )),
            EntryBody::DeviceRevocation(DeviceCertificateRevocation::issue(
                &identity(1),
                DevicePublicKey::from_verifying_key(*identity(5).id().verifying_key()),
                Timestamp::from_millis(12),
            )),
            EntryBody::Moderation(ModerationEntry {
                action: ModerationAction::Delist,
                target_pointer_id: PointerId::from_bytes([7u8; 32]),
            }),
            EntryBody::Moderation(ModerationEntry {
                action: ModerationAction::Relist,
                target_pointer_id: PointerId::from_bytes([7u8; 32]),
            }),
            EntryBody::AppNameRegistration {
                name: AppName::new("wiki"),
                app_id: PointerId::from_bytes([8u8; 32]),
            },
        ]
    }

    #[test]
    fn every_entry_body_round_trips_with_an_identical_hash() {
        // The hash is what is asserted, not merely structural equality. Entry
        // hashes drive the fork-choice tie-break (§2.7.1), so a codec that
        // round-tripped a value into an equal-looking one with a different hash
        // would still break convergence.
        let author = identity(1);
        for body in every_body() {
            let entry = LogEntry::create(
                &author,
                Some(Hash::from_bytes([1u8; 32])),
                Timestamp::from_millis(5),
                body.clone(),
            );
            let decoded = decode_entry(&encode_entry(&entry))
                .unwrap_or_else(|e| panic!("{} should decode: {e}", body.kind()));

            assert_eq!(decoded, entry, "{} did not round-trip", body.kind());
            assert_eq!(
                decoded.hash(),
                entry.hash(),
                "{} round-tripped to a different hash",
                body.kind()
            );
        }
    }

    #[test]
    fn a_genesis_entry_round_trips_with_no_parent() {
        let entry = genesis(&identity(1));
        let decoded = decode_entry(&encode_entry(&entry)).unwrap();
        assert_eq!(decoded.parent, None);
        assert_eq!(decoded.hash(), entry.hash());
    }

    #[test]
    fn a_tampered_entry_is_rejected_rather_than_accepted_as_different() {
        // The property the whole module rests on. Flipping any signed byte must
        // fail verification, so an attacker cannot rewrite an entry in flight
        // and a codec bug cannot pass as a merely-different entry.
        let entry = LogEntry::create(
            &identity(1),
            Some(Hash::from_bytes([1u8; 32])),
            Timestamp::from_millis(5),
            EntryBody::MembershipChange {
                group: GroupId::new("admins"),
                identity: identity(2).id(),
                action: MembershipAction::Add { via_invite: None },
            },
        );
        let encoded = encode_entry(&entry);

        let mut tampered = 0;
        for index in 0..encoded.len() {
            let mut bytes = encoded.clone();
            bytes[index] ^= 0x01;
            if decode_entry(&bytes).is_err() {
                tampered += 1;
            }
        }
        assert_eq!(
            tampered,
            encoded.len(),
            "every single-bit change to a signed entry must be rejected"
        );
    }

    #[test]
    fn an_off_curve_author_key_is_refused() {
        // Reachable only from the wire: locally an identity is always derived
        // from a seed and is a valid point by construction.
        let entry = genesis(&identity(1));
        let encoded = encode_entry(&entry);
        let author_offset = encoded
            .windows(32)
            .position(|w| w == entry.author.verifying_key().as_bytes())
            .expect("the author key should appear in the encoding");

        // Deliberately not `[0xff; 32]`: Ed25519 accepts non-canonical
        // y-coordinates, so those bytes make a *valid* key whose signature then
        // fails — which would test the wrong rejection path. These bytes do not
        // decompress to a curve point at all. See `intranet-crypto`'s
        // `off_curve_public_key_is_rejected_at_construction`.
        let mut off_curve = [0u8; 32];
        off_curve[0] = 1;
        off_curve[31] = 3;

        let mut bytes = encoded.clone();
        bytes[author_offset..author_offset + 32].copy_from_slice(&off_curve);
        assert_eq!(decode_entry(&bytes).unwrap_err(), WireError::InvalidKey);
    }

    #[test]
    fn sync_requests_and_responses_round_trip() {
        let author = identity(1);
        let entry = genesis(&author);

        for request in [
            SyncRequest::Heads,
            SyncRequest::Fetch {
                wanted: vec![Hash::from_bytes([1u8; 32]), Hash::from_bytes([2u8; 32])],
                have: vec![],
            },
            SyncRequest::Fetch {
                wanted: vec![],
                have: vec![Hash::from_bytes([3u8; 32])],
            },
        ] {
            assert_eq!(SyncRequest::decode(&request.encode()).unwrap(), request);
        }

        for response in [
            SyncResponse::Heads {
                heads: vec![Hash::from_bytes([1u8; 32])],
            },
            SyncResponse::Heads { heads: vec![] },
            SyncResponse::Entries {
                entries: vec![entry.clone()],
                truncated: false,
            },
            SyncResponse::Entries {
                entries: vec![],
                truncated: true,
            },
        ] {
            assert_eq!(SyncResponse::decode(&response.encode()).unwrap(), response);
        }
    }

    #[test]
    fn a_response_carrying_a_forged_entry_is_refused_whole() {
        // Signature verification happens during response decoding, so a peer
        // cannot slip an unsigned entry in beside legitimate ones and have it
        // land in the log.
        let entry = genesis(&identity(1));
        let mut forged = entry.clone();
        forged.timestamp = Timestamp::from_millis(999);

        let response = SyncResponse::Entries {
            entries: vec![entry, forged],
            truncated: false,
        };
        assert_eq!(
            SyncResponse::decode(&response.encode()).unwrap_err(),
            WireError::BadSignature
        );
    }

    #[test]
    fn a_decoded_entry_inserts_into_a_log_under_its_original_hash() {
        // End to end: the hash a receiving node computes must be the hash the
        // sender's log knows the entry by, or the two logs are describing
        // different chains while appearing to agree.
        let author = identity(1);
        let entry = genesis(&author);

        let mut sender = GovernanceLog::new();
        let sent_hash = sender.insert(entry.clone()).unwrap();

        let mut receiver = GovernanceLog::new();
        let received_hash = receiver
            .insert(decode_entry(&encode_entry(&entry)).unwrap())
            .unwrap();

        assert_eq!(sent_hash, received_hash);
    }
}
