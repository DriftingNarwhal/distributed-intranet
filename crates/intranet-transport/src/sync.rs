//! Governance log sync over libp2p — Core Protocol Spec §2.7, §5.1.
//!
//! # Why request/response rather than a pubsub broadcast
//!
//! §2.7 requires the governance log to need "no new storage or transport
//! primitive beyond what's already specified in §5.1", and §5.1 names no pubsub
//! mechanism — so this is a protocol over the libp2p streams already in use,
//! not a new one.
//!
//! There is also a correctness reason, which matters more. The partition tests
//! in Reference Test Harness Spec §3 have each side append entries *while
//! disconnected*. A broadcast has no history: whatever it published while the
//! two halves could not see each other is simply gone, so on heal neither side
//! would ever learn what it missed. Pulling makes healing fall out for free —
//! **a heal is a reconnect, and a reconnect is a sync** — with no separate
//! catch-up path that could rot from disuse.
//!
//! # Message size
//!
//! The codec caps what it will read. An unbounded read on a peer-supplied length
//! is a memory-exhaustion vector, and a cap is the only thing standing between a
//! sync and one — see [`MAX_MESSAGE_BYTES`].

use futures::{AsyncReadExt, AsyncWriteExt};
use intranet_governance::{SyncRequest, SyncResponse};
use libp2p::StreamProtocol;
use libp2p::request_response;
use std::io;

/// The sync protocol's libp2p identifier.
///
/// Versioned, so a future incompatible change to the message set can be
/// introduced as a second protocol rather than as a silent reinterpretation of
/// the same bytes by two builds that disagree.
pub const SYNC_PROTOCOL: StreamProtocol = StreamProtocol::new("/intranet/governance-sync/1.0.0");

/// The largest sync message this build will read.
///
/// **Flagged: the specs set no wire size limit.** One is required regardless,
/// because both sides of this protocol read a length chosen by the peer. 8 MiB
/// comfortably holds `MAX_ENTRIES_PER_RESPONSE` entries while keeping a hostile
/// peer's maximum allocation bounded; the pull-based design means a requester
/// that needs more simply asks again.
pub const MAX_MESSAGE_BYTES: u64 = 8 * 1024 * 1024;

/// Codec carrying [`SyncRequest`] and [`SyncResponse`].
///
/// The encoding itself lives in `intranet-governance`'s `wire` module, next to
/// the types it encodes, so that adding a governance entry variant and
/// forgetting the codec is a compile error rather than a runtime surprise. This
/// type only moves the bytes.
#[derive(Debug, Clone, Default)]
pub struct SyncCodec;

async fn read_framed<T>(io: &mut T) -> io::Result<Vec<u8>>
where
    T: futures::AsyncRead + Unpin + Send,
{
    let mut buffer = Vec::new();
    // `take` bounds the read before any allocation grows without limit, which is
    // the difference between a large message and a remote OOM.
    io.take(MAX_MESSAGE_BYTES).read_to_end(&mut buffer).await?;
    Ok(buffer)
}

fn malformed(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

#[async_trait::async_trait]
impl request_response::Codec for SyncCodec {
    type Protocol = StreamProtocol;
    type Request = SyncRequest;
    type Response = SyncResponse;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        SyncRequest::decode(&read_framed(io).await?).map_err(malformed)
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        // Every entry's signature is verified inside this decode, so an entry
        // that reaches the swarm has already been authenticated against its
        // author's key — a peer cannot inject an entry nobody signed.
        SyncResponse::decode(&read_framed(io).await?).map_err(malformed)
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

/// Builds the sync behaviour.
pub fn behaviour() -> request_response::Behaviour<SyncCodec> {
    request_response::Behaviour::with_codec(
        SyncCodec,
        [(SYNC_PROTOCOL, request_response::ProtocolSupport::Full)],
        request_response::Config::default(),
    )
}
