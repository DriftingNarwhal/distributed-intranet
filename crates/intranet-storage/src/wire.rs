//! Wire encoding for chunk transfer — Storage Spec §4.3–4.5, §5.4.
//!
//! # Why a request carries the requester's identity
//!
//! Serving is gated on `read-content` (§5.4), and a gate needs to know who is
//! asking. The libp2p PeerId is not enough on its own: it is derived from the
//! per-network identity key (Core Protocol Spec §1.2), but the serving node has
//! to map it back to a `PerNetworkIdentityId` to evaluate governance state, and
//! a request that simply asserted an identity would let any peer claim to be
//! anyone. So a request is **signed over the chunk being asked for**, and the
//! serving node verifies that signature before consulting the gate.
//!
//! Binding the signature to the CID rather than signing a bare identity is what
//! stops a captured request being replayed to fetch something else. It is not a
//! full freshness guarantee — the same request for the same chunk can be
//! replayed — but that costs nothing beyond bandwidth the responder is already
//! willing to spend, and adding a nonce round trip would double the latency of
//! every chunk fetch to prevent an attacker re-requesting data they already had.
//!
//! # Refusals are explicit
//!
//! A node that will not serve says so, rather than pretending not to hold the
//! chunk. §5.4's guarantee is convergence — a node still catching up on a
//! revocation will briefly still serve — and a requester that cannot tell
//! "refused" from "not held" would silently re-request from every other holder,
//! turning one refusal into a network-wide retry storm.

use crate::Cid;
use intranet_crypto::{Dec, DecodeError, Enc, Hash, Signature};
use intranet_governance::PointerId;
use intranet_identity::{PerNetworkIdentity, PerNetworkIdentityId};

/// Domain tag for a chunk request signature.
const REQUEST_SIGNATURE_DOMAIN: &str = "intranet.chunk-request.v1";
/// Domain tag for a chunk request on the wire.
const REQUEST_DOMAIN: &str = "intranet.wire.chunk-request.v1";
/// Domain tag for a chunk response on the wire.
const RESPONSE_DOMAIN: &str = "intranet.wire.chunk-response.v1";

/// The largest chunk this build will accept from a peer.
///
/// **Flagged: §1.3 makes chunk size a network policy value with a target, not a
/// hard ceiling.** A ceiling is needed here regardless, because the length is
/// chosen by the peer. 16 MiB is far above any plausible content-defined chunk
/// while bounding what one response can cost.
pub const MAX_CHUNK_BYTES: usize = 16 * 1024 * 1024;

/// Why a chunk message could not be turned into a value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    /// The bytes were malformed.
    #[error("malformed message: {0}")]
    Malformed(#[from] DecodeError),
    /// A public key on the wire was not a valid point.
    #[error("invalid public key in message")]
    InvalidKey,
    /// The request's signature did not verify.
    #[error("chunk request signature did not verify")]
    BadSignature,
    /// A chunk exceeded [`MAX_CHUNK_BYTES`].
    #[error("chunk of {size} bytes exceeds the {MAX_CHUNK_BYTES} byte ceiling")]
    ChunkTooLarge {
        /// The size claimed.
        size: usize,
    },
    /// A message carried more entries, or a longer field, than its ceiling.
    #[error("message carried {got}, over the {limit} ceiling")]
    TooManyEntries {
        /// What was presented.
        got: usize,
        /// The ceiling.
        limit: usize,
    },
}

fn unknown(type_name: &'static str, discriminant: u8) -> WireError {
    WireError::Malformed(DecodeError::UnknownVariant {
        type_name,
        discriminant,
    })
}

fn get_identity(d: &mut Dec<'_>) -> Result<PerNetworkIdentityId, WireError> {
    let key = intranet_crypto::VerifyingKey::from_bytes(d.fixed::<32>()?)
        .map_err(|_| WireError::InvalidKey)?;
    Ok(PerNetworkIdentityId::from_verifying_key(key))
}

/// A request for one chunk's bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkRequest {
    /// The chunk wanted.
    pub cid: Cid,
    /// Who is asking, for the `read-content` gate (§5.4).
    pub requester: PerNetworkIdentityId,
    /// The requester's signature over `(cid, requester)`.
    pub signature: Signature,
}

impl ChunkRequest {
    /// Builds and signs a request.
    pub fn create(requester: &PerNetworkIdentity, cid: Cid) -> Self {
        let requester_id = requester.id();
        Self {
            cid,
            requester: requester_id,
            signature: requester.sign(&Self::payload(&cid, &requester_id)),
        }
    }

    /// Verifies that the named requester really made this request.
    ///
    /// Called before the serving gate, not after: evaluating `read-content` for
    /// an identity that never asked would let any peer borrow a member's
    /// standing simply by naming them.
    pub fn verify(&self) -> Result<(), WireError> {
        self.requester
            .verifying_key()
            .verify(
                &Self::payload(&self.cid, &self.requester),
                &self.signature,
            )
            .map_err(|_| WireError::BadSignature)
    }

    fn payload(cid: &Cid, requester: &PerNetworkIdentityId) -> Enc {
        let mut e = Enc::domain(REQUEST_SIGNATURE_DOMAIN);
        e.fixed(cid.hash().as_bytes());
        requester.encode(&mut e);
        e
    }

    /// Encodes the request.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::domain(REQUEST_DOMAIN);
        e.fixed(self.cid.hash().as_bytes());
        self.requester.encode(&mut e);
        e.fixed(self.signature.as_bytes());
        e.finish()
    }

    /// Decodes a request and verifies its signature.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut d = Dec::domain(bytes, REQUEST_DOMAIN)?;
        let request = Self {
            cid: Cid::from_hash(intranet_crypto::Hash::from_bytes(d.fixed::<32>()?)),
            requester: get_identity(&mut d)?,
            signature: Signature::from_bytes(d.fixed::<64>()?),
        };
        d.finish()?;
        request.verify()?;
        Ok(request)
    }
}

/// Why a serving node would not hand over a chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkRefusal {
    /// The requester does not hold `read-content` (§5.4).
    NoReadContent,
    /// The responder could not evaluate the gate — no governance state yet.
    ///
    /// Distinct from a refusal on the merits, and deliberately so: this means
    /// "ask again once I have caught up", where [`Self::NoReadContent`] means
    /// "do not bother". Collapsing them would make a node that is merely behind
    /// look like one that has judged the requester ineligible.
    CannotEvaluate,
}

/// A response to a chunk request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkResponse {
    /// The chunk's bytes.
    Chunk {
        /// The bytes, to be verified against the requested CID on arrival.
        bytes: Vec<u8>,
    },
    /// The responder does not hold this chunk.
    ///
    /// Not an error: a node leaves a swarm simply by no longer caching the
    /// bytes (§4.2), so this is the ordinary answer to a stale provider record.
    NotHeld,
    /// The responder holds it but will not serve it.
    Refused {
        /// Why.
        reason: ChunkRefusal,
    },
}

impl ChunkResponse {
    /// Encodes the response.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::domain(RESPONSE_DOMAIN);
        match self {
            Self::Chunk { bytes } => {
                e.variant(0).bytes(bytes);
            }
            Self::NotHeld => {
                e.variant(1);
            }
            Self::Refused { reason } => {
                e.variant(2).u8(match reason {
                    ChunkRefusal::NoReadContent => 0,
                    ChunkRefusal::CannotEvaluate => 1,
                });
            }
        }
        e.finish()
    }

    /// Decodes a response.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut d = Dec::domain(bytes, RESPONSE_DOMAIN)?;
        let response = match d.variant()? {
            0 => {
                let payload = d.bytes()?;
                if payload.len() > MAX_CHUNK_BYTES {
                    return Err(WireError::ChunkTooLarge {
                        size: payload.len(),
                    });
                }
                Self::Chunk {
                    bytes: payload.to_vec(),
                }
            }
            1 => Self::NotHeld,
            2 => Self::Refused {
                reason: match d.u8()? {
                    0 => ChunkRefusal::NoReadContent,
                    1 => ChunkRefusal::CannotEvaluate,
                    other => return Err(unknown("ChunkRefusal", other)),
                },
            },
            other => return Err(unknown("ChunkResponse", other)),
        };
        d.finish()?;
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use intranet_identity::{MasterSeed, NetworkId};

    const NETWORK: NetworkId = NetworkId::from_bytes([42u8; 32]);

    fn identity(n: u8) -> PerNetworkIdentity {
        MasterSeed::from_entropy([n; 32]).identity_for(&NETWORK).unwrap()
    }

    #[test]
    fn a_request_round_trips_and_verifies() {
        let requester = identity(1);
        let request = ChunkRequest::create(&requester, Cid::of(b"chunk"));

        let decoded = ChunkRequest::decode(&request.encode()).unwrap();
        assert_eq!(decoded, request);
        assert_eq!(decoded.requester, requester.id());
    }

    #[test]
    fn a_request_cannot_be_made_in_someone_elses_name() {
        // Without this, the `read-content` gate is decorative: any peer could
        // name a member with the capability and be served on their standing.
        let mut forged = ChunkRequest::create(&identity(1), Cid::of(b"chunk"));
        forged.requester = identity(2).id();

        assert_eq!(forged.verify().unwrap_err(), WireError::BadSignature);
        assert_eq!(
            ChunkRequest::decode(&forged.encode()).unwrap_err(),
            WireError::BadSignature
        );
    }

    #[test]
    fn a_request_cannot_be_replayed_for_a_different_chunk() {
        // The signature binds the CID, so a captured request cannot be edited
        // into a request for something the requester never asked for.
        let mut tampered = ChunkRequest::create(&identity(1), Cid::of(b"public chunk"));
        tampered.cid = Cid::of(b"secret chunk");

        assert_eq!(tampered.verify().unwrap_err(), WireError::BadSignature);
    }

    #[test]
    fn every_single_bit_change_to_a_request_is_rejected() {
        let request = ChunkRequest::create(&identity(1), Cid::of(b"chunk"));
        let encoded = request.encode();

        let rejected = (0..encoded.len())
            .filter(|index| {
                let mut bytes = encoded.clone();
                bytes[*index] ^= 0x01;
                ChunkRequest::decode(&bytes).is_err()
            })
            .count();
        assert_eq!(rejected, encoded.len());
    }

    #[test]
    fn responses_round_trip() {
        for response in [
            ChunkResponse::Chunk {
                bytes: b"some content".to_vec(),
            },
            ChunkResponse::Chunk { bytes: Vec::new() },
            ChunkResponse::NotHeld,
            ChunkResponse::Refused {
                reason: ChunkRefusal::NoReadContent,
            },
            ChunkResponse::Refused {
                reason: ChunkRefusal::CannotEvaluate,
            },
        ] {
            assert_eq!(ChunkResponse::decode(&response.encode()).unwrap(), response);
        }
    }

    #[test]
    fn an_oversized_chunk_is_refused() {
        // The length is chosen by the peer, so it needs a ceiling. Refused at
        // decode rather than after allocation, so an absurd claim costs a parse
        // rather than the memory it asked for.
        let response = ChunkResponse::Chunk {
            bytes: vec![0u8; MAX_CHUNK_BYTES + 1],
        };
        assert!(matches!(
            ChunkResponse::decode(&response.encode()).unwrap_err(),
            WireError::ChunkTooLarge { .. }
        ));
    }
}

// ---------------------------------------------------------------------------
// Append-set collections — Storage Spec §2.5
// ---------------------------------------------------------------------------

/// Domain tag for a collection request on the wire.
const COLLECTION_REQUEST_DOMAIN: &str = "intranet.wire.collection-request.v1";
/// Domain tag for a collection response on the wire.
const COLLECTION_RESPONSE_DOMAIN: &str = "intranet.wire.collection-response.v1";

/// The most entries one collection response will carry.
///
/// **Flagged: §2.5 states enumeration is best-effort and gives no bound.** A cap
/// is needed regardless, and unusually here it is not only a memory concern:
/// §2.5 explicitly accepts that a popular collection may not be fully
/// enumerable in one pass, so truncation is a *specified* outcome rather than a
/// failure. 512 keeps a response bounded while being far above a typical term's
/// posting count.
pub const MAX_COLLECTION_ENTRIES: usize = 512;

/// A request to enumerate one append-set collection — §2.5.
///
/// Signed and gated like a chunk request. **Flagged: the specs do not say
/// whether enumeration requires `read-content`.** Requiring it is the
/// fail-closed reading and matches §5.4's reasoning about explicit intake: a
/// waiting-room node is supposed to receive essentially nothing, and a term
/// index is a map from words to the pointers that contain them — enough to learn
/// what a network is about without ever fetching a byte of content. Serving it
/// ungated would undercut the posture the content gate exists to create.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionRequest {
    /// The collection to enumerate.
    pub collection_id: Hash,
    /// Who is asking.
    pub requester: PerNetworkIdentityId,
    /// The requester's signature over `(collection_id, requester)`.
    pub signature: Signature,
}

impl CollectionRequest {
    /// Builds and signs a request.
    pub fn create(requester: &PerNetworkIdentity, collection_id: Hash) -> Self {
        let requester_id = requester.id();
        Self {
            collection_id,
            requester: requester_id,
            signature: requester.sign(&Self::payload(&collection_id, &requester_id)),
        }
    }

    /// Verifies that the named requester really made this request.
    pub fn verify(&self) -> Result<(), WireError> {
        self.requester
            .verifying_key()
            .verify(
                &Self::payload(&self.collection_id, &self.requester),
                &self.signature,
            )
            .map_err(|_| WireError::BadSignature)
    }

    fn payload(collection_id: &Hash, requester: &PerNetworkIdentityId) -> Enc {
        let mut e = Enc::domain("intranet.collection-request.v1");
        e.fixed(collection_id.as_bytes());
        requester.encode(&mut e);
        e
    }

    /// Encodes the request.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::domain(COLLECTION_REQUEST_DOMAIN);
        e.fixed(self.collection_id.as_bytes());
        self.requester.encode(&mut e);
        e.fixed(self.signature.as_bytes());
        e.finish()
    }

    /// Decodes a request and verifies its signature.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut d = Dec::domain(bytes, COLLECTION_REQUEST_DOMAIN)?;
        let request = Self {
            collection_id: intranet_crypto::Hash::from_bytes(d.fixed::<32>()?),
            requester: get_identity(&mut d)?,
            signature: Signature::from_bytes(d.fixed::<64>()?),
        };
        d.finish()?;
        request.verify()?;
        Ok(request)
    }
}

/// A response to a collection enumeration — §2.5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollectionResponse {
    /// The entries this node holds for the collection.
    ///
    /// Payloads are opaque here: the append-set is one primitive serving
    /// consumers whose entry shapes differ (search postings, the app name
    /// registry), so decoding belongs to whichever crate owns the shape rather
    /// than to the primitive carrying it.
    Entries {
        /// Encoded entries.
        payloads: Vec<Vec<u8>>,
        /// Whether more were held than one response could carry.
        ///
        /// §2.5 makes incompleteness a specified property of enumeration, not an
        /// error — but a consumer that needs an authoritative answer has to know
        /// it received a partial one, which is exactly the distinction that
        /// makes it safe for search and unsafe for name ownership.
        truncated: bool,
    },
    /// The requester may not enumerate this collection.
    Refused {
        /// Why.
        reason: ChunkRefusal,
    },
}

impl CollectionResponse {
    /// Encodes the response.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::domain(COLLECTION_RESPONSE_DOMAIN);
        match self {
            Self::Entries { payloads, truncated } => {
                e.variant(0);
                e.seq(payloads.iter(), |e, payload| {
                    e.bytes(payload);
                });
                e.bool(*truncated);
            }
            Self::Refused { reason } => {
                e.variant(1).u8(match reason {
                    ChunkRefusal::NoReadContent => 0,
                    ChunkRefusal::CannotEvaluate => 1,
                });
            }
        }
        e.finish()
    }

    /// Decodes a response.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut d = Dec::domain(bytes, COLLECTION_RESPONSE_DOMAIN)?;
        let response = match d.variant()? {
            0 => Self::Entries {
                payloads: d.seq::<_, WireError>(|d| Ok(d.bytes()?.to_vec()))?,
                truncated: d.bool()?,
            },
            1 => Self::Refused {
                reason: match d.u8()? {
                    0 => ChunkRefusal::NoReadContent,
                    1 => ChunkRefusal::CannotEvaluate,
                    other => return Err(unknown("ChunkRefusal", other)),
                },
            },
            other => return Err(unknown("CollectionResponse", other)),
        };
        d.finish()?;
        Ok(response)
    }
}

/// Domain tag for an append-set entry on the wire.
const ENTRY_WIRE_DOMAIN: &str = "intranet.wire.appendset-entry.v1";

/// The largest append-set entry payload this build will accept.
///
/// **Flagged: §2.5 sets no payload bound.** One is needed because the length is
/// publisher-chosen and a collection response carries many. 64 KiB is far above
/// a directory listing or a search posting while keeping one response bounded.
pub const MAX_ENTRY_PAYLOAD_BYTES: usize = 64 * 1024;

/// Encodes an append-set entry for announcement — §2.5.
pub fn encode_entry(entry: &crate::AppendSetEntry) -> Vec<u8> {
    let mut e = Enc::domain(ENTRY_WIRE_DOMAIN);
    e.fixed(entry.collection_id.as_bytes()).bytes(&entry.payload);
    e.option(entry.references.as_ref(), |e, pointer| {
        e.fixed(pointer.as_bytes());
    });
    entry.publisher_identity.encode(&mut e);
    e.fixed(entry.signature.as_bytes());
    e.finish()
}

/// Decodes an append-set entry and verifies its signature.
///
/// The signature is §2.5's first mandatory check. The other two — that the
/// publisher is a *current* member, and that any pointer it references is not
/// delisted — need replayed governance state and live in
/// [`AppendSetEntry::validate`](crate::AppendSetEntry::validate). A caller that
/// decodes without then validating has done one check of three, and §2.5 is
/// explicit that all three are required of any node relying on the data.
pub fn decode_entry(bytes: &[u8]) -> Result<crate::AppendSetEntry, WireError> {
    let mut d = Dec::domain(bytes, ENTRY_WIRE_DOMAIN)?;
    let collection_id = Hash::from_bytes(d.fixed::<32>()?);
    let payload = d.bytes()?;
    if payload.len() > MAX_ENTRY_PAYLOAD_BYTES {
        return Err(WireError::ChunkTooLarge {
            size: payload.len(),
        });
    }
    let references = d
        .option::<_, WireError>(|d| Ok(intranet_governance::PointerId::from_bytes(d.fixed::<32>()?)))?;
    let publisher_identity = get_identity(&mut d)?;
    let signature = Signature::from_bytes(d.fixed::<64>()?);
    d.finish()?;

    let entry = crate::AppendSetEntry {
        collection_id,
        payload: payload.to_vec(),
        references,
        publisher_identity,
        signature,
    };
    // Signature only — see the doc comment. `validate` is where the other two
    // checks live, and it needs state this layer does not have.
    entry
        .verify_signature()
        .map_err(|_| WireError::BadSignature)?;
    Ok(entry)
}

// ---------------------------------------------------------------------------
// Mutable pointers and DEK wrappings — Storage Spec §2.2, §5.3
//
// # Why pointers sync rather than broadcast
//
// §2.2 calls stale-pointer detection "a natural fit for the same gossip
// mechanism used for capability ledger propagation", and the ledger is pulled
// here rather than pushed for a reason that applies to pointers with equal
// force: a broadcast has no history. A pointer published while two halves of a
// network cannot see each other would simply never arrive, because the moment it
// was announced has passed. Pulling makes a heal a reconnect and a reconnect a
// sync, exactly as for the governance log.
//
// # Why the digest carries a record hash and not just a version
//
// Two publishers can each build on the same prior version, producing two valid
// records claiming the *identical* version (§2.2). A digest keyed on version
// alone reports those as agreeing, so neither side ever fetches the other's
// record and the divergence is permanent — the one failure mode a pointer sync
// exists to prevent. Carrying the record hash makes a same-version disagreement
// visible, at which point the existing lower-hash tie-break settles it.
// ---------------------------------------------------------------------------

/// Domain tag for the signature a requester makes over a pointer request.
const POINTER_REQUEST_SIGNATURE_DOMAIN: &str = "intranet.pointer-request.v1";
/// Domain tag for a pointer request on the wire.
const POINTER_REQUEST_DOMAIN: &str = "intranet.wire.pointer-request.v1";
/// Domain tag for a pointer response on the wire.
const POINTER_RESPONSE_DOMAIN: &str = "intranet.wire.pointer-response.v1";

/// The most pointers one response will carry.
///
/// **Flagged: §2.2 sets no bound.** One is needed because a node's pointer set
/// grows with everything the network has ever published. A requester that needs
/// more asks again, the same way a truncated governance sync is resumed.
pub const MAX_POINTERS_PER_RESPONSE: usize = 256;

/// The most DEK wrappings one pointer's record will carry.
///
/// **Flagged: §5.3 sets no bound.** At most one wrapping exists per rotation, by
/// determinism, so a legitimate record carries the current one plus any not yet
/// cleaned up after a voided branch (§5.3.1). 16 is far above that while stopping
/// a peer padding a record with wrappings for rotations nobody has.
pub const MAX_WRAPPINGS_PER_POINTER: usize = 16;

/// The largest wrapped DEK this build will accept.
///
/// **Flagged: the specs set no bound.** A wrapped 32-byte DEK is a nonce, the
/// ciphertext and a tag — well under 128 bytes. 1 KiB bounds a hostile record
/// without constraining any real one.
pub const MAX_WRAPPED_DEK_BYTES: usize = 1024;

/// One pointer's state, as a peer summarises it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PointerDigestEntry {
    /// Which pointer.
    pub pointer_id: PointerId,
    /// Its version, so a requester can skip anything it already has newer.
    pub version: u64,
    /// The record's hash, which is what makes a same-version fork visible.
    pub record_hash: Hash,
}

/// A pointer and the wrappings that open it.
///
/// Carried together because they are useless apart: a resolver needs the record
/// to know what to fetch and the wrapping to decrypt it, and fetching them over
/// two round trips would make the common case slower for no benefit. They remain
/// *separately valid* — a wrapping is checked against the owner's commitment,
/// never against whoever sent it (§5.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointerRecord {
    /// The signed pointer record.
    pub pointer: crate::MutablePointer,
    /// Wrappings this node holds for it, keyed by rotation in the sender's view.
    pub wrappings: Vec<crate::DekWrapping>,
}

/// A request for pointer state — §2.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PointerRequest {
    /// "What pointers do you hold, and at what version?"
    Digest {
        /// Who is asking, for the `read-content` gate (§5.4).
        requester: PerNetworkIdentityId,
        /// The requester's signature.
        signature: Signature,
    },
    /// "Send me these pointers and their wrappings."
    Fetch {
        /// Which pointers are wanted.
        wanted: Vec<PointerId>,
        /// Who is asking.
        requester: PerNetworkIdentityId,
        /// The requester's signature.
        signature: Signature,
    },
}

impl PointerRequest {
    /// Builds and signs a digest request.
    pub fn digest(requester: &PerNetworkIdentity) -> Self {
        let id = requester.id();
        Self::Digest {
            signature: requester.sign(&Self::payload(&id, &[])),
            requester: id,
        }
    }

    /// Builds and signs a fetch request.
    pub fn fetch(requester: &PerNetworkIdentity, wanted: Vec<PointerId>) -> Self {
        let id = requester.id();
        Self::Fetch {
            signature: requester.sign(&Self::payload(&id, &wanted)),
            requester: id,
            wanted,
        }
    }

    /// Who is asking.
    pub fn requester(&self) -> &PerNetworkIdentityId {
        match self {
            Self::Digest { requester, .. } | Self::Fetch { requester, .. } => requester,
        }
    }

    /// Verifies that the named requester really made this request.
    pub fn verify(&self) -> Result<(), WireError> {
        let (requester, wanted, signature) = match self {
            Self::Digest {
                requester,
                signature,
            } => (requester, [].as_slice(), signature),
            Self::Fetch {
                wanted,
                requester,
                signature,
            } => (requester, wanted.as_slice(), signature),
        };
        requester
            .verifying_key()
            .verify(&Self::payload(requester, wanted), signature)
            .map_err(|_| WireError::BadSignature)
    }

    fn payload(requester: &PerNetworkIdentityId, wanted: &[PointerId]) -> Enc {
        let mut e = Enc::domain(POINTER_REQUEST_SIGNATURE_DOMAIN);
        requester.encode(&mut e);
        // The wanted set is signed, so a request cannot be widened in flight to
        // pull pointers the requester never asked for under their standing.
        e.seq(wanted.iter(), |e, id| {
            e.fixed(id.as_bytes());
        });
        e
    }

    /// Encodes the request.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::domain(POINTER_REQUEST_DOMAIN);
        match self {
            Self::Digest {
                requester,
                signature,
            } => {
                e.variant(0);
                requester.encode(&mut e);
                e.fixed(signature.as_bytes());
            }
            Self::Fetch {
                wanted,
                requester,
                signature,
            } => {
                e.variant(1);
                e.seq(wanted.iter(), |e, id| {
                    e.fixed(id.as_bytes());
                });
                requester.encode(&mut e);
                e.fixed(signature.as_bytes());
            }
        }
        e.finish()
    }

    /// Decodes a request and verifies its signature.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut d = Dec::domain(bytes, POINTER_REQUEST_DOMAIN)?;
        let request = match d.variant()? {
            0 => Self::Digest {
                requester: get_identity(&mut d)?,
                signature: Signature::from_bytes(d.fixed::<64>()?),
            },
            1 => {
                let wanted = d.seq::<_, WireError>(|d| Ok(PointerId::from_bytes(d.fixed::<32>()?)))?;
                if wanted.len() > MAX_POINTERS_PER_RESPONSE {
                    return Err(WireError::TooManyEntries {
                        got: wanted.len(),
                        limit: MAX_POINTERS_PER_RESPONSE,
                    });
                }
                Self::Fetch {
                    wanted,
                    requester: get_identity(&mut d)?,
                    signature: Signature::from_bytes(d.fixed::<64>()?),
                }
            }
            other => return Err(unknown("PointerRequest", other)),
        };
        d.finish()?;
        request.verify()?;
        Ok(request)
    }
}

/// Why a node would not answer a pointer request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointerRefusal {
    /// The requester does not hold `read-content` (§5.4).
    ///
    /// Gating the *digest* matters as much as gating the records: a digest is a
    /// list of everything the network has published, which is the content graph
    /// itself. Serving it to a waiting-room identity would hand over the shape
    /// of a network's contents to somebody §2.4 promises essentially nothing.
    NoReadContent,
    /// The responder could not evaluate the gate — no governance state yet.
    CannotEvaluate,
}

/// A response to a pointer request — §2.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PointerResponse {
    /// What this node holds.
    Digest {
        /// One entry per pointer held.
        entries: Vec<PointerDigestEntry>,
        /// Whether the list was cut at [`MAX_POINTERS_PER_RESPONSE`].
        truncated: bool,
    },
    /// The requested records.
    Records {
        /// Pointers and their wrappings.
        records: Vec<PointerRecord>,
        /// Whether the list was cut at [`MAX_POINTERS_PER_RESPONSE`].
        truncated: bool,
    },
    /// The request was refused.
    Refused {
        /// Why.
        reason: PointerRefusal,
    },
}

impl PointerResponse {
    /// Encodes the response.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::domain(POINTER_RESPONSE_DOMAIN);
        match self {
            Self::Digest { entries, truncated } => {
                e.variant(0);
                e.seq(entries.iter(), |e, entry| {
                    e.fixed(entry.pointer_id.as_bytes())
                        .u64(entry.version)
                        .fixed(entry.record_hash.as_bytes());
                });
                e.bool(*truncated);
            }
            Self::Records { records, truncated } => {
                e.variant(1);
                e.seq(records.iter(), |e, record| {
                    put_pointer(e, &record.pointer);
                    e.seq(record.wrappings.iter(), |e, wrapping| {
                        put_wrapping(e, wrapping);
                    });
                });
                e.bool(*truncated);
            }
            Self::Refused { reason } => {
                e.variant(2).u8(match reason {
                    PointerRefusal::NoReadContent => 0,
                    PointerRefusal::CannotEvaluate => 1,
                });
            }
        }
        e.finish()
    }

    /// Decodes a response, verifying every signature it carries.
    ///
    /// Both the pointer's owner signature and each wrapping's wrapper signature
    /// are checked here, so nothing structurally unauthenticated reaches a
    /// caller. What is *not* checked here is authorization — the publish gates
    /// and the delisting state are governance questions, answered against
    /// replayed state by whoever consumes the record.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut d = Dec::domain(bytes, POINTER_RESPONSE_DOMAIN)?;
        let response = match d.variant()? {
            0 => {
                let entries = d.seq::<_, WireError>(|d| {
                    Ok(PointerDigestEntry {
                        pointer_id: PointerId::from_bytes(d.fixed::<32>()?),
                        version: d.u64()?,
                        record_hash: Hash::from_bytes(d.fixed::<32>()?),
                    })
                })?;
                if entries.len() > MAX_POINTERS_PER_RESPONSE {
                    return Err(WireError::TooManyEntries {
                        got: entries.len(),
                        limit: MAX_POINTERS_PER_RESPONSE,
                    });
                }
                Self::Digest {
                    entries,
                    truncated: d.bool()?,
                }
            }
            1 => {
                let records = d.seq::<_, WireError>(|d| {
                    let pointer = get_pointer(d)?;
                    let wrappings = d.seq::<_, WireError>(get_wrapping)?;
                    if wrappings.len() > MAX_WRAPPINGS_PER_POINTER {
                        return Err(WireError::TooManyEntries {
                            got: wrappings.len(),
                            limit: MAX_WRAPPINGS_PER_POINTER,
                        });
                    }
                    Ok(PointerRecord {
                        pointer,
                        wrappings,
                    })
                })?;
                if records.len() > MAX_POINTERS_PER_RESPONSE {
                    return Err(WireError::TooManyEntries {
                        got: records.len(),
                        limit: MAX_POINTERS_PER_RESPONSE,
                    });
                }
                Self::Records {
                    records,
                    truncated: d.bool()?,
                }
            }
            2 => Self::Refused {
                reason: match d.u8()? {
                    0 => PointerRefusal::NoReadContent,
                    1 => PointerRefusal::CannotEvaluate,
                    other => return Err(unknown("PointerRefusal", other)),
                },
            },
            other => return Err(unknown("PointerResponse", other)),
        };
        d.finish()?;
        Ok(response)
    }
}

fn put_pointer(e: &mut Enc, pointer: &crate::MutablePointer) {
    e.fixed(pointer.pointer_id.as_bytes());
    pointer.owner_identity.encode(e);
    e.str(pointer.content_type.as_str())
        .fixed(pointer.current_cid.hash().as_bytes())
        .fixed(pointer.dek_commitment.as_bytes())
        .u64(pointer.version)
        .fixed(pointer.signature.as_bytes());
}

fn get_pointer(d: &mut Dec<'_>) -> Result<crate::MutablePointer, WireError> {
    let pointer = crate::MutablePointer {
        pointer_id: PointerId::from_bytes(d.fixed::<32>()?),
        owner_identity: get_identity(d)?,
        content_type: intranet_governance::ContentType::new(d.str()?),
        current_cid: Cid::from_hash(Hash::from_bytes(d.fixed::<32>()?)),
        dek_commitment: Hash::from_bytes(d.fixed::<32>()?),
        version: d.u64()?,
        signature: Signature::from_bytes(d.fixed::<64>()?),
    };
    // Re-verified against the canonically re-encoded payload, so a codec that
    // disagreed with the signing encoding produces a rejected record rather than
    // a record nobody signed — the same property the governance codec relies on.
    pointer.verify().map_err(|_| WireError::BadSignature)?;
    Ok(pointer)
}

fn put_wrapping(e: &mut Enc, wrapping: &crate::DekWrapping) {
    e.fixed(wrapping.pointer_id.as_bytes())
        .bytes(&wrapping.wrapped_dek)
        .fixed(wrapping.rotation_ref.as_bytes());
    wrapping.wrapper_identity.encode(e);
    e.fixed(wrapping.signature.as_bytes());
}

fn get_wrapping(d: &mut Dec<'_>) -> Result<crate::DekWrapping, WireError> {
    let pointer_id = PointerId::from_bytes(d.fixed::<32>()?);
    let wrapped_dek = d.bytes()?;
    if wrapped_dek.len() > MAX_WRAPPED_DEK_BYTES {
        return Err(WireError::TooManyEntries {
            got: wrapped_dek.len(),
            limit: MAX_WRAPPED_DEK_BYTES,
        });
    }
    let wrapping = crate::DekWrapping {
        pointer_id,
        wrapped_dek: wrapped_dek.to_vec(),
        rotation_ref: Hash::from_bytes(d.fixed::<32>()?),
        wrapper_identity: get_identity(d)?,
        signature: Signature::from_bytes(d.fixed::<64>()?),
    };
    wrapping
        .verify_signature()
        .map_err(|_| WireError::BadSignature)?;
    Ok(wrapping)
}
