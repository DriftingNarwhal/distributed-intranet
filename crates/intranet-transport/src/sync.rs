//! Pull-based sync protocols over libp2p — Core Protocol Spec §2.7, §4.5, §5.1.
//!
//! # Why pull rather than a pubsub broadcast
//!
//! §2.7 requires the governance log to need "no new storage or transport
//! primitive beyond what's already specified in §5.1", and §5.1 names no pubsub
//! mechanism — so these are protocols over the libp2p streams already in use,
//! not new ones. §4.5 says the same of the capability ledger, describing it as
//! piggybacking on the mechanisms in §5.
//!
//! There is also a correctness reason, which matters more. The partition tests
//! in Reference Test Harness Spec §3 have each side append entries *while
//! disconnected*. A broadcast has no history: whatever it published while the
//! two halves could not see each other is simply gone, so on heal neither side
//! would ever learn what it missed. Pulling makes healing fall out for free —
//! **a heal is a reconnect, and a reconnect is a sync** — with no separate
//! catch-up path that could rot from disuse.
//!
//! # Two protocols, one codec
//!
//! The governance log and the capability ledger propagate very differently — one
//! is a hash-chained tree reconciled by ancestry, the other a set of per-node
//! records replaced wholesale on refresh — but they move bytes identically. The
//! codec is therefore generic over [`WireMessage`], and each protocol supplies
//! its own message types and its own reconciliation logic in the crate that owns
//! them. Keeping the encoding beside the types it encodes is what makes adding a
//! variant and forgetting the codec a compile error rather than a runtime
//! surprise.

use futures::{AsyncReadExt, AsyncWriteExt};
use intranet_governance::{SyncRequest, SyncResponse};
use intranet_ledger::{LedgerRequest, LedgerResponse};
use intranet_storage::{ChunkRequest, ChunkResponse};
use libp2p::StreamProtocol;
use libp2p::request_response;
use std::io;
use std::marker::PhantomData;

/// The governance log sync protocol's libp2p identifier.
///
/// Versioned, so a future incompatible change to the message set can be
/// introduced as a second protocol rather than as a silent reinterpretation of
/// the same bytes by two builds that disagree.
pub const SYNC_PROTOCOL: StreamProtocol = StreamProtocol::new("/intranet/governance-sync/1.0.0");

/// The capability ledger gossip protocol's libp2p identifier.
pub const LEDGER_PROTOCOL: StreamProtocol =
    StreamProtocol::new("/intranet/capability-ledger/1.0.0");

/// The chunk transfer protocol's libp2p identifier — Storage Spec §4.
pub const CHUNK_PROTOCOL: StreamProtocol = StreamProtocol::new("/intranet/chunk/1.0.0");

/// The largest metadata message this build will read.
///
/// **Flagged: the specs set no wire size limit.** One is required regardless,
/// because both sides of these protocols read a length chosen by the peer. 8 MiB
/// comfortably holds a full governance or ledger response while keeping a
/// hostile peer's maximum allocation bounded; the pull-based design means a
/// requester that needs more simply asks again.
pub const DEFAULT_MAX_MESSAGE_BYTES: u64 = 8 * 1024 * 1024;

/// The largest chunk response this build will read.
///
/// Derived from the storage layer's own chunk ceiling rather than chosen
/// separately, plus a small allowance for framing, so the two cannot drift into
/// a state where a chunk the storage layer accepts is one the transport layer
/// refuses to read.
pub const MAX_CHUNK_MESSAGE_BYTES: u64 = intranet_storage::MAX_CHUNK_BYTES as u64 + 1024;

/// A message that can travel over one of these protocols.
///
/// Implemented here for types owned by other crates so that the encoding stays
/// next to the types it encodes, rather than the dependency running the other
/// way and the transport layer growing opinions about governance and ledger
/// internals.
pub trait WireMessage: Sized + Send + 'static {
    /// The largest frame this message type will be read from.
    ///
    /// Per-type rather than one constant for the whole codec, because the limits
    /// genuinely differ: metadata messages should never approach a megabyte,
    /// while a chunk response legitimately carries bulk content. A single shared
    /// ceiling would have to be the larger of the two, which would let a peer
    /// send a 16 MiB "digest" — or, set to the smaller, would make a chunk at
    /// the size the storage layer permits impossible to read, a bug that would
    /// only appear on unusually large chunks.
    const MAX_BYTES: u64 = DEFAULT_MAX_MESSAGE_BYTES;

    /// Encodes the message.
    fn encode(&self) -> Vec<u8>;
    /// Decodes the message, reporting why if it cannot.
    fn decode(bytes: &[u8]) -> Result<Self, String>;
}

macro_rules! wire_message {
    ($type:ty) => {
        wire_message!($type, DEFAULT_MAX_MESSAGE_BYTES);
    };
    ($type:ty, $max:expr) => {
        impl WireMessage for $type {
            const MAX_BYTES: u64 = $max;
            fn encode(&self) -> Vec<u8> {
                <$type>::encode(self)
            }
            fn decode(bytes: &[u8]) -> Result<Self, String> {
                <$type>::decode(bytes).map_err(|error| error.to_string())
            }
        }
    };
}

wire_message!(SyncRequest);
wire_message!(SyncResponse);
wire_message!(LedgerRequest);
wire_message!(LedgerResponse);
wire_message!(ChunkRequest);
wire_message!(ChunkResponse, MAX_CHUNK_MESSAGE_BYTES);

/// Codec carrying any [`WireMessage`] pair.
///
/// The `PhantomData` is over `fn() -> (Req, Res)` rather than `(Req, Res)` so
/// the codec is `Send` and `Sync` regardless of its message types, which a
/// behaviour requires and which the message types themselves have no reason to
/// guarantee.
#[derive(Debug)]
pub struct WireCodec<Req, Res>(PhantomData<fn() -> (Req, Res)>);

impl<Req, Res> Default for WireCodec<Req, Res> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<Req, Res> Clone for WireCodec<Req, Res> {
    fn clone(&self) -> Self {
        Self::default()
    }
}

/// Codec for governance log sync.
pub type SyncCodec = WireCodec<SyncRequest, SyncResponse>;
/// Codec for capability ledger gossip.
pub type LedgerCodec = WireCodec<LedgerRequest, LedgerResponse>;
/// Codec for chunk transfer.
pub type ChunkCodec = WireCodec<ChunkRequest, ChunkResponse>;

async fn read_framed<T>(io: &mut T, max: u64) -> io::Result<Vec<u8>>
where
    T: futures::AsyncRead + Unpin + Send,
{
    let mut buffer = Vec::new();
    // `take` bounds the read before any allocation grows without limit, which is
    // the difference between a large message and a remote OOM.
    io.take(max).read_to_end(&mut buffer).await?;
    Ok(buffer)
}

fn malformed(error: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

#[async_trait::async_trait]
impl<Req: WireMessage, Res: WireMessage> request_response::Codec for WireCodec<Req, Res> {
    type Protocol = StreamProtocol;
    type Request = Req;
    type Response = Res;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        Req::decode(&read_framed(io, Req::MAX_BYTES).await?).map_err(malformed)
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        // Signatures are verified inside these decodes, so anything reaching the
        // swarm has already been authenticated against its author's key — a peer
        // cannot inject a governance entry nobody signed, nor an advertisement
        // claiming capacity on someone else's behalf.
        Res::decode(&read_framed(io, Res::MAX_BYTES).await?).map_err(malformed)
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        request: Self::Request,
    ) -> io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        io.write_all(&request.encode()).await?;
        io.close().await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        response: Self::Response,
    ) -> io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        io.write_all(&response.encode()).await?;
        io.close().await
    }
}

fn build<Req: WireMessage, Res: WireMessage>(
    protocol: StreamProtocol,
) -> request_response::Behaviour<WireCodec<Req, Res>> {
    request_response::Behaviour::with_codec(
        WireCodec::default(),
        [(protocol, request_response::ProtocolSupport::Full)],
        request_response::Config::default(),
    )
}

/// Builds the governance log sync behaviour.
pub fn behaviour() -> request_response::Behaviour<SyncCodec> {
    build(SYNC_PROTOCOL)
}

/// Builds the capability ledger gossip behaviour.
pub fn ledger_behaviour() -> request_response::Behaviour<LedgerCodec> {
    build(LEDGER_PROTOCOL)
}

/// Builds the chunk transfer behaviour.
pub fn chunk_behaviour() -> request_response::Behaviour<ChunkCodec> {
    build(CHUNK_PROTOCOL)
}
