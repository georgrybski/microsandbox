//! Client for connecting to a microsandbox agent relay.
//!
//! [`AgentClient`] communicates with `agentd` through an agent relay transport.
//! During connection, the relay assigns a non-overlapping correlation ID range
//! and sends the cached `core.ready` payload so the client can begin issuing
//! commands immediately. Unix domain sockets are available with the `uds`
//! feature on Unix hosts, Windows named pipes are available with the
//! `named-pipe` feature on Windows hosts, and the `stream` feature drives the client over any
//! `AsyncRead + AsyncWrite` byte stream (e.g. a caller-owned, pre-authenticated
//! transport adapted to bytes).
//!
//! Two API tiers share one socket and one reader task:
//!
//! - **Raw** ([`request_raw`](AgentClient::request_raw),
//!   [`stream_raw`](AgentClient::stream_raw),
//!   [`send_raw`](AgentClient::send_raw)) — exchange [`RawFrame`]s. The client
//!   handles framing and correlation IDs; CBOR encoding/decoding is left to the
//!   caller. Use this when wrapping the client for other languages.
//! - **Typed** ([`request`](AgentClient::request),
//!   [`stream`](AgentClient::stream), [`send`](AgentClient::send)) — same
//!   primitives over [`Message`]; the SDK serializes payloads with CBOR.

use std::collections::HashMap;
#[cfg(feature = "stream")]
use std::future::Future;
#[cfg(any(all(feature = "named-pipe", windows), all(feature = "uds", unix)))]
use std::path::Path;
#[cfg(feature = "stream")]
use std::pin::Pin;
use std::sync::{
    Arc, Weak,
    atomic::{AtomicBool, AtomicU32, Ordering},
};
#[cfg(feature = "stream")]
use std::time::Duration;

#[cfg(feature = "stream")]
use microsandbox_protocol::message::FLAG_TERMINAL;
#[cfg(feature = "stream")]
use microsandbox_protocol::{codec::MAX_FRAME_SIZE, message::FRAME_HEADER_SIZE};
use microsandbox_protocol::{
    codec::{self, RawFrame},
    core::Ready,
    message::{Message, MessageType, PROTOCOL_VERSION},
};
use serde::Serialize;
#[cfg(feature = "stream")]
use tokio::io::{AsyncRead, AsyncWrite};
#[cfg(all(feature = "uds", unix))]
use tokio::net::UnixStream;
#[cfg(all(feature = "named-pipe", windows))]
use tokio::net::windows::named_pipe::ClientOptions;
use tokio::sync::{Mutex, Notify, OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio::task::JoinHandle;
#[cfg(feature = "stream")]
use tokio::time::Instant;

use super::error::{AgentClientError, AgentClientResult};

mod owned;
pub use owned::{AgentSession, AgentSessionEvents, SessionEvent};
use owned::{SESSION_LEASES, SessionLease};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Default handshake timeout used by [`AgentClient::connect`].
#[cfg(feature = "stream")]
const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[cfg(all(feature = "named-pipe", windows))]
const WINDOWS_PIPE_CONNECT_RETRY: Duration = Duration::from_millis(10);

#[cfg(feature = "stream")]
const WRITER_QUEUE_CAPACITY: usize = 1024;
const REQUEST_QUEUE_CAPACITY: usize = 1;
const STREAM_QUEUE_CAPACITY: usize = 1024;

const LEGACY_PROTOCOL_VERSION: u8 = 1;
// TODO(upgrade-0.6): Remove in 0.6.x or later once live-sandbox
// compatibility for versions before 0.5 is no longer supported.
#[cfg(feature = "stream")]
const LEGACY_RELAY_ID_RANGE_STEP: u32 = u32::MAX / 16;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Agent protocol generation spoken by a connected sandbox relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentProtocol {
    /// Current protocol generation.
    Current,

    /// pre-0.5 microsandbox relay handshake and agent protocol.
    ///
    /// TODO(upgrade-0.6): Remove in 0.6.x or later once live-sandbox
    /// compatibility for versions before 0.5 is no longer supported.
    LegacyV1,
}

/// Client for communicating with agentd through the agent relay.
///
/// See the module-level docs for an overview of the two API tiers.
pub struct AgentClient {
    /// Kernel-observed local peer PID; absent for injected/cloud transports.
    peer_pid: Option<u32>,
    /// Channel to the transport writer task.
    writer: mpsc::Sender<WriterCommand>,
    /// Next correlation ID to allocate (starts at `id_min`).
    next_id: AtomicU32,
    /// Lower bound (inclusive) of the assigned ID range, used for wrap-around.
    id_min: u32,
    /// Upper bound (exclusive) of the assigned ID range.
    id_max: u32,
    /// Agent protocol generation for this connection.
    protocol: AgentProtocol,
    /// Negotiated protocol generation: `min(our PROTOCOL_VERSION, the
    /// generation the sandbox echoed in its `core.ready` frame)`. Drives the
    /// capability gate on the typed send path. Distinct from [`Self::protocol`],
    /// which selects the wire codec; see `VERSIONING.md`.
    negotiated_version: u8,
    /// Pending response channels keyed by correlation ID.
    pending: Arc<Mutex<PendingRegistry>>,
    /// A byte budget independent of the number of queued writer commands.
    session_write_bytes: Arc<Semaphore>,
    closed: Arc<AtomicBool>,
    /// Background reader task handle.
    reader_handle: JoinHandle<()>,
    /// Background writer task handle.
    writer_handle: JoinHandle<()>,
    /// Cached `core.ready` frame body (raw CBOR bytes) from the relay handshake.
    ready_body: Vec<u8>,
    /// Decoded `core.ready` payload from the relay handshake.
    ready: Ready,
}

#[cfg(feature = "stream")]
struct AgentHandshake {
    id_min: u32,
    id_max: u32,
    protocol: AgentProtocol,
    negotiated_version: u8,
    ready_body: Vec<u8>,
    ready: Ready,
}

#[cfg_attr(not(feature = "stream"), allow(dead_code))]
struct WriterCommand {
    frame: RawFrame,
    ack: oneshot::Sender<AgentClientResult<()>>,
    lease: Option<Arc<SessionLease>>,
    _bytes: Option<OwnedSemaphorePermit>,
}

#[derive(Clone)]
enum Pending {
    Legacy(mpsc::Sender<RawFrame>),
    Owned(Arc<SessionLease>),
}

#[derive(Default)]
struct PendingRegistry {
    handlers: HashMap<u32, Pending>,
    // Terminals remove handlers, but retained controls and queued writes keep
    // their correlation IDs unavailable until every lease has been released.
    leases: HashMap<u32, Weak<SessionLease>>,
}

impl std::ops::Deref for PendingRegistry {
    type Target = HashMap<u32, Pending>;
    fn deref(&self) -> &Self::Target {
        &self.handlers
    }
}

impl std::ops::DerefMut for PendingRegistry {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.handlers
    }
}

impl PendingRegistry {
    fn release_unopened(&mut self) {
        self.handlers.retain(|_, entry| match entry {
            Pending::Owned(lease) => {
                Arc::strong_count(lease) != 1
                    || lease.sent.load(std::sync::atomic::Ordering::Acquire)
            }
            Pending::Legacy(_) => true,
        });
        self.leases.retain(|_, lease| lease.strong_count() != 0);
    }
}

#[cfg(feature = "stream")]
trait HandshakeReader {
    fn read_exact_handshake<'a>(
        &'a mut self,
        out: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = AgentClientResult<()>> + Send + 'a>>;

    fn read_frame_handshake<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = AgentClientResult<RawFrame>> + Send + 'a>>;
}

//--------------------------------------------------------------------------------------------------
// Methods: Connection lifecycle
//--------------------------------------------------------------------------------------------------

impl AgentProtocol {
    fn version(self) -> u8 {
        match self {
            Self::Current => PROTOCOL_VERSION,
            Self::LegacyV1 => LEGACY_PROTOCOL_VERSION,
        }
    }
}

impl AgentClient {
    /// Connect to a local agent relay using the default 10s handshake timeout.
    ///
    /// Uses a Unix domain socket on Unix when the `uds` feature is enabled, and
    /// a Windows named pipe on Windows when the `named-pipe` feature is enabled.
    #[cfg(any(all(feature = "named-pipe", windows), all(feature = "uds", unix)))]
    pub async fn connect(sock_path: impl AsRef<Path>) -> AgentClientResult<Self> {
        Self::connect_with_timeout(sock_path, DEFAULT_HANDSHAKE_TIMEOUT).await
    }

    /// Connect to a local agent relay using an explicit handshake timeout.
    #[cfg(any(all(feature = "named-pipe", windows), all(feature = "uds", unix)))]
    pub async fn connect_with_timeout(
        sock_path: impl AsRef<Path>,
        timeout: Duration,
    ) -> AgentClientResult<Self> {
        let deadline = Instant::now() + timeout;
        Self::connect_with_deadline(sock_path, deadline).await
    }

    /// Connect with an explicit handshake deadline.
    ///
    /// `deadline` bounds both handshake reads. Without it, an accepted
    /// connection that stalls (e.g. a sandbox alive but wedged before
    /// writing the handshake bytes) would block this call indefinitely.
    #[cfg(any(all(feature = "named-pipe", windows), all(feature = "uds", unix)))]
    pub async fn connect_with_deadline(
        sock_path: impl AsRef<Path>,
        deadline: Instant,
    ) -> AgentClientResult<Self> {
        let sock_path = sock_path.as_ref();
        let stream = connect_local_stream(sock_path, deadline).await?;
        #[cfg(all(feature = "uds", target_os = "linux"))]
        let peer_pid = stream
            .peer_cred()?
            .pid()
            .and_then(|pid| u32::try_from(pid).ok());
        #[cfg(not(all(feature = "uds", target_os = "linux")))]
        let peer_pid = None;
        let mut client = Self::connect_stream_with_deadline(stream, deadline).await?;
        client.peer_pid = peer_pid;
        Ok(client)
    }

    /// Connect over an arbitrary byte-stream transport using the default 10s
    /// handshake timeout.
    ///
    /// The stream must be a transparent pipe to the agent relay: the relay's
    /// `[id_min][id_max]` + `core.ready` prologue and the framed protocol that
    /// follows flow over it verbatim. This is the injection point for
    /// caller-owned transports — e.g. a pre-authenticated WebSocket adapted to
    /// bytes — so the caller owns the dial and its credentials and this crate
    /// stays transport- (and dependency-) agnostic.
    #[cfg(feature = "stream")]
    pub async fn connect_stream<S>(stream: S) -> AgentClientResult<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self::connect_stream_with_timeout(stream, DEFAULT_HANDSHAKE_TIMEOUT).await
    }

    /// Connect over an arbitrary byte-stream transport using an explicit
    /// handshake timeout.
    #[cfg(feature = "stream")]
    pub async fn connect_stream_with_timeout<S>(
        stream: S,
        timeout: Duration,
    ) -> AgentClientResult<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let deadline = Instant::now() + timeout;
        Self::connect_stream_with_deadline(stream, deadline).await
    }

    /// Connect over an arbitrary byte-stream transport with an explicit
    /// handshake deadline.
    ///
    /// `deadline` bounds both handshake reads so an accepted-but-stalled
    /// transport cannot block this call indefinitely.
    #[cfg(feature = "stream")]
    pub async fn connect_stream_with_deadline<S>(
        stream: S,
        deadline: Instant,
    ) -> AgentClientResult<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut reader, writer) = tokio::io::split(stream);
        let handshake = perform_handshake(&mut reader, deadline).await?;

        tracing::info!(
            id_min = handshake.id_min,
            id_max = handshake.id_max,
            protocol = ?handshake.protocol,
            ready_bytes = handshake.ready_body.len(),
            boot_time_ns = handshake.ready.boot_time_ns,
            "agent client: connected to relay"
        );
        if handshake.protocol == AgentProtocol::LegacyV1 {
            // TODO(upgrade-0.6): Remove in 0.6.x or later once live-sandbox
            // compatibility for versions before 0.5 is no longer supported.
            tracing::warn!(
                "agent client: connected to a sandbox started before microsandbox 0.5; exec compatibility is temporary and filesystem/SFTP require stop/start"
            );
        }

        let pending = Arc::new(Mutex::new(PendingRegistry::default()));
        let closed = Arc::new(AtomicBool::new(false));
        let writer_failed = Arc::new(Notify::new());

        let (writer_tx, writer_rx) = mpsc::channel(WRITER_QUEUE_CAPACITY);
        let reader_handle = tokio::spawn(reader_loop(
            reader,
            Arc::clone(&pending),
            closed.clone(),
            writer_failed.clone(),
        ));
        let writer_handle = tokio::spawn(stream_writer_loop(
            writer,
            writer_rx,
            closed.clone(),
            writer_failed,
        ));

        Ok(Self {
            peer_pid: None,
            writer: writer_tx,
            next_id: AtomicU32::new(first_request_id(handshake.id_min)),
            id_min: handshake.id_min,
            id_max: handshake.id_max,
            protocol: handshake.protocol,
            negotiated_version: handshake.negotiated_version,
            pending,
            session_write_bytes: Arc::new(Semaphore::new(4 * 1024 * 1024)),
            closed,
            reader_handle,
            writer_handle,
            ready_body: handshake.ready_body,
            ready: handshake.ready,
        })
    }

    /// Close the connection. Drops the writer and aborts the reader task;
    /// any in-flight requests resolve with [`AgentClientError::Closed`].
    pub async fn close(self) {
        self.disconnect().await;
    }

    /// Close this transport even while owned session leases retain the client.
    /// Transport loss is not evidence that a guest process terminated.
    pub async fn disconnect(&self) {
        self.closed.store(true, Ordering::Release);
        self.reader_handle.abort();
        self.writer_handle.abort();
        let mut pending = self.pending.lock().await;
        for handler in pending.values() {
            if let Pending::Owned(lease) = handler {
                lease.transport_closed();
            }
        }
        pending.clear();
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: Raw transport (CBOR-blind)
//--------------------------------------------------------------------------------------------------

impl AgentClient {
    /// Reserve a connection-bound session without sending its opening request.
    ///
    /// The caller must own both the request and its bounded cleanup. Unlike
    /// raw correlation IDs, retained controls and queued sends prevent ID reuse
    /// after a terminal. Slow receivers never block unrelated reply delivery.
    pub async fn owned_session(
        self: &Arc<Self>,
    ) -> AgentClientResult<(AgentSession, AgentSessionEvents)> {
        let mut pending = self.pending.lock().await;
        if self.closed.load(Ordering::Acquire) || self.writer.is_closed() {
            return Err(AgentClientError::Closed);
        }
        pending.release_unopened();
        if pending.leases.len() >= SESSION_LEASES {
            return Err(AgentClientError::IdRangeExhausted);
        }
        let id = self.next_available_id(&pending)?;
        let lease = SessionLease::new(id);
        let events = lease.receiver();
        pending.leases.insert(id, Arc::downgrade(&lease));
        pending.insert(id, Pending::Owned(lease.clone()));
        Ok((
            AgentSession {
                client: self.clone(),
                lease,
            },
            events,
        ))
    }

    /// One-shot raw request: alloc id, send a frame with `(flags, body)`,
    /// await one response frame with the matching id.
    ///
    /// Use this for protocol RPCs that produce exactly one terminal response
    /// (e.g. `FsRequest` → `FsResponse`).
    pub async fn request_raw(&self, flags: u8, body: Vec<u8>) -> AgentClientResult<RawFrame> {
        let (tx, mut rx) = mpsc::channel(REQUEST_QUEUE_CAPACITY);
        let id = self.reserve_id(tx).await?;

        if let Err(e) = self.write_frame_owned(id, flags, body).await {
            self.pending.lock().await.remove(&id);
            return Err(e);
        }

        let frame = rx.recv().await.ok_or(AgentClientError::ReaderClosed(id))?;
        self.pending.lock().await.remove(&id);
        Ok(frame)
    }

    /// Open a streaming raw session: alloc id, register a subscription,
    /// send the opening frame, return `(id, receiver)`.
    ///
    /// The receiver yields every frame the relay forwards for this `id`
    /// until a frame with [`FLAG_TERMINAL`] arrives or the receiver is dropped.
    /// Use [`send_raw`](Self::send_raw) with the returned id to send
    /// follow-up frames within the session.
    pub async fn stream_raw(
        &self,
        flags: u8,
        body: Vec<u8>,
    ) -> AgentClientResult<(u32, mpsc::Receiver<RawFrame>)> {
        let (tx, rx) = mpsc::channel(STREAM_QUEUE_CAPACITY);
        let id = self.reserve_id(tx).await?;

        if let Err(e) = self.write_frame_owned(id, flags, body).await {
            self.pending.lock().await.remove(&id);
            return Err(e);
        }

        Ok((id, rx))
    }

    /// Send a follow-up raw frame on an existing correlation id.
    ///
    /// Use for messages that belong to a session started via
    /// [`stream_raw`](Self::stream_raw) (e.g. `ExecStdin`, `ExecSignal`,
    /// `ExecResize`, `FsData` chunks).
    pub async fn send_raw(&self, id: u32, flags: u8, body: &[u8]) -> AgentClientResult<()> {
        self.write_frame(id, flags, body).await
    }

    /// The cached `core.ready` handshake frame body bytes (CBOR-encoded).
    ///
    /// Useful for bindings that want to deserialize the ready payload with
    /// their own CBOR tooling. For typed access, use [`ready`](Self::ready).
    pub fn ready_bytes(&self) -> &[u8] {
        &self.ready_body
    }

    /// Agent protocol generation for this connection.
    pub fn protocol(&self) -> AgentProtocol {
        self.protocol
    }

    /// Returns `true` if this connection is using the legacy pre-0.5 protocol.
    pub fn is_legacy_protocol(&self) -> bool {
        self.protocol == AgentProtocol::LegacyV1
    }

    /// The negotiated protocol generation for this connection: the lower of what
    /// this client speaks and what the sandbox advertised at handshake.
    pub fn negotiated_version(&self) -> u8 {
        self.negotiated_version
    }

    /// The runtime's self-reported package version, taken from its `core.ready`
    /// frame. Empty when the runtime predates this field (an older agent), in
    /// which case fall back to the generation for diagnostics.
    pub fn agent_version(&self) -> &str {
        &self.ready.agent_version
    }

    /// Whether the connected sandbox is new enough to handle the given message
    /// type. The single source of truth for feature gating: callers that can't
    /// gate by sending (e.g. the SSH/SFTP layer) consult this instead of
    /// inspecting the protocol generation directly.
    pub fn supports(&self, t: MessageType) -> bool {
        t.min_protocol_version() <= self.negotiated_version
    }

    /// Reject a message type the connected sandbox is too old to handle, against
    /// this connection's negotiated generation. Fails before any bytes are sent,
    /// so only that one operation fails and the session continues.
    pub fn ensure_version_compat(&self, t: MessageType) -> AgentClientResult<()> {
        Self::ensure_version_compat_for(t, self.negotiated_version)
    }

    /// Check a message type against an explicit negotiated generation.
    ///
    /// The single place the rule lives. Exposed for callers that hold the
    /// negotiated generation but not the live client (e.g. the SSH/SFTP layer).
    pub fn ensure_version_compat_for(t: MessageType, negotiated: u8) -> AgentClientResult<()> {
        if t.is_available_at(negotiated) {
            return Ok(());
        }
        Err(AgentClientError::UnsupportedOperation {
            msg_type: t.as_str(),
            needs: t.min_protocol_version(),
            peer: negotiated,
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: Typed transport (CBOR-aware)
//--------------------------------------------------------------------------------------------------

impl AgentClient {
    /// One-shot typed request. Flags are derived from the message type.
    pub async fn request<T: Serialize>(
        &self,
        t: MessageType,
        payload: &T,
    ) -> AgentClientResult<Message> {
        self.ensure_version_compat(t)?;
        let flags = t.flags();
        let body = encode_message_body(self.protocol.version(), t, payload)?;
        let frame = self.request_raw(flags, body).await?;
        Ok(codec::raw_frame_to_message(frame)?)
    }

    /// Open a streaming typed session. Flags are derived from the message type.
    /// Returns the assigned id and a typed receiver.
    pub async fn stream<T: Serialize>(
        &self,
        t: MessageType,
        payload: &T,
    ) -> AgentClientResult<(u32, mpsc::Receiver<Message>)> {
        self.ensure_version_compat(t)?;
        let flags = t.flags();
        let body = encode_message_body(self.protocol.version(), t, payload)?;
        let (id, raw_rx) = self.stream_raw(flags, body).await?;

        let (tx, rx) = mpsc::channel(STREAM_QUEUE_CAPACITY);
        tokio::spawn(decode_stream_task(raw_rx, tx));
        Ok((id, rx))
    }

    /// Send a follow-up typed message on an existing correlation id.
    pub async fn send<T: Serialize>(
        &self,
        id: u32,
        t: MessageType,
        payload: &T,
    ) -> AgentClientResult<()> {
        self.ensure_version_compat(t)?;
        let flags = t.flags();
        let body = encode_message_body(self.protocol.version(), t, payload)?;
        self.write_frame_owned(id, flags, body).await
    }

    /// Decode the cached handshake `core.ready` payload.
    pub fn ready(&self) -> AgentClientResult<Ready> {
        Ok(self.ready.clone())
    }

    /// Kernel-reported server PID on a Linux Unix-domain connection.
    ///
    /// This is local transport evidence, never information supplied by agentd.
    /// Other transports return `None` rather than inventing a process identity.
    pub fn peer_pid(&self) -> Option<u32> {
        self.peer_pid
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: Internals
//--------------------------------------------------------------------------------------------------

impl AgentClient {
    /// Reserve a unique correlation ID from the relay-assigned range.
    ///
    /// Wraps around within the assigned range and skips IDs that still have an
    /// active pending request or stream.
    async fn reserve_id(&self, tx: mpsc::Sender<RawFrame>) -> AgentClientResult<u32> {
        let mut pending = self.pending.lock().await;
        pending.release_unopened();
        let id = self.next_available_id(&pending)?;
        pending.insert(id, Pending::Legacy(tx));
        Ok(id)
    }

    fn next_available_id(&self, pending: &PendingRegistry) -> AgentClientResult<u32> {
        let attempts = usable_id_count(self.id_min, self.id_max);
        for _ in 0..attempts {
            let id = self
                .next_id
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if self.next_id.load(std::sync::atomic::Ordering::Relaxed) >= self.id_max {
                self.next_id.store(
                    first_request_id(self.id_min),
                    std::sync::atomic::Ordering::Relaxed,
                );
            }
            if id == 0
                || id < self.id_min
                || id >= self.id_max
                || pending.contains_key(&id)
                || pending
                    .leases
                    .get(&id)
                    .is_some_and(|lease| lease.strong_count() != 0)
            {
                continue;
            }
            return Ok(id);
        }

        Err(AgentClientError::IdRangeExhausted)
    }

    /// Write a single framed message to the socket.
    async fn write_frame(&self, id: u32, flags: u8, body: &[u8]) -> AgentClientResult<()> {
        self.write_frame_owned(id, flags, body.to_vec()).await
    }

    /// Write a single framed message to the socket, taking ownership of the body.
    async fn write_frame_owned(&self, id: u32, flags: u8, body: Vec<u8>) -> AgentClientResult<()> {
        let (ack, written) = oneshot::channel();
        self.writer
            .send(WriterCommand {
                frame: RawFrame { id, flags, body },
                ack,
                lease: None,
                _bytes: None,
            })
            .await
            .map_err(|_| AgentClientError::Closed)?;
        written.await.map_err(|_| AgentClientError::Closed)?
    }

    async fn write_session_frame(
        &self,
        lease: Arc<SessionLease>,
        flags: u8,
        body: Vec<u8>,
        bytes: OwnedSemaphorePermit,
    ) -> AgentClientResult<()> {
        if !lease.active.load(std::sync::atomic::Ordering::Acquire) {
            return Err(AgentClientError::SessionClosed(lease.id));
        }
        let (ack, written) = oneshot::channel();
        self.writer
            .try_send(WriterCommand {
                frame: RawFrame {
                    id: lease.id,
                    flags,
                    body,
                },
                ack,
                lease: Some(lease),
                _bytes: Some(bytes),
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => AgentClientError::SessionWriteQueueFull,
                mpsc::error::TrySendError::Closed(_) => AgentClientError::Closed,
            })?;
        written.await.map_err(|_| AgentClientError::Closed)?
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

#[cfg(all(feature = "uds", unix))]
async fn connect_local_stream(
    sock_path: &Path,
    _deadline: Instant,
) -> AgentClientResult<UnixStream> {
    UnixStream::connect(sock_path)
        .await
        .map_err(|source| AgentClientError::Connect {
            path: sock_path.to_path_buf(),
            source,
        })
}

#[cfg(all(feature = "named-pipe", windows))]
async fn connect_local_stream(
    pipe_path: &Path,
    deadline: Instant,
) -> AgentClientResult<tokio::net::windows::named_pipe::NamedPipeClient> {
    loop {
        match ClientOptions::new().open(pipe_path) {
            Ok(stream) => return Ok(stream),
            Err(source)
                if is_retryable_named_pipe_connect_error(&source) && Instant::now() < deadline =>
            {
                tokio::time::sleep(WINDOWS_PIPE_CONNECT_RETRY).await;
            }
            Err(source) => {
                return Err(AgentClientError::Connect {
                    path: pipe_path.to_path_buf(),
                    source,
                });
            }
        }
    }
}

#[cfg(all(feature = "named-pipe", windows))]
fn is_retryable_named_pipe_connect_error(error: &std::io::Error) -> bool {
    const ERROR_PIPE_BUSY: i32 = 231;

    error.kind() == std::io::ErrorKind::NotFound || error.raw_os_error() == Some(ERROR_PIPE_BUSY)
}

#[cfg(feature = "stream")]
async fn perform_handshake<R>(
    reader: &mut R,
    deadline: Instant,
) -> AgentClientResult<AgentHandshake>
where
    R: HandshakeReader + ?Sized,
{
    // Current handshake:
    // [id_min: u32 BE][id_max: u32 BE][ready_frame_bytes...]
    //
    // Legacy pre-0.5 handshake:
    // [id_offset: u32 BE][ready_frame_bytes...]
    //
    // Reading 8 bytes up-front lets us distinguish the two forms. For legacy
    // relays, the second word is the ready-frame length prefix.
    let mut range_buf = [0u8; 8];
    tokio::time::timeout_at(deadline, reader.read_exact_handshake(&mut range_buf))
        .await
        .map_err(|_| {
            AgentClientError::Handshake("read id range: timed out before relay sent bytes".into())
        })??;
    let id_start_or_offset = u32::from_be_bytes(range_buf[0..4].try_into().unwrap());
    let id_max_or_frame_len = u32::from_be_bytes(range_buf[4..8].try_into().unwrap());

    let legacy_handshake =
        looks_like_legacy_relay_handshake(id_start_or_offset, id_max_or_frame_len);
    let (id_min, id_max, ready_frame, protocol) = if legacy_handshake {
        let id_offset = id_start_or_offset;
        let ready_frame =
            read_raw_frame_after_len_prefix(reader, range_buf[4..8].try_into().unwrap(), deadline)
                .await?;
        (
            id_offset.saturating_add(1),
            id_offset.saturating_add(LEGACY_RELAY_ID_RANGE_STEP),
            ready_frame,
            AgentProtocol::LegacyV1,
        )
    } else if id_start_or_offset >= id_max_or_frame_len {
        return Err(AgentClientError::Handshake(format!(
            "invalid relay id range: start={id_start_or_offset}, end={id_max_or_frame_len}"
        )));
    } else {
        let ready_frame = tokio::time::timeout_at(deadline, reader.read_frame_handshake())
            .await
            .map_err(|_| {
                AgentClientError::Handshake(
                    "read ready frame: timed out before relay sent frame".into(),
                )
            })?
            .map_err(|e| AgentClientError::Handshake(format!("read ready frame: {e}")))?;
        (
            id_start_or_offset,
            id_max_or_frame_len,
            ready_frame,
            AgentProtocol::Current,
        )
    };
    ensure_usable_id_range(id_min, id_max)?;

    let ready_msg = codec::raw_frame_to_message(ready_frame.clone())
        .map_err(|e| AgentClientError::Handshake(format!("decode ready frame: {e}")))?;
    if ready_msg.t != MessageType::Ready {
        return Err(AgentClientError::Handshake(format!(
            "expected core.ready frame, got {}",
            ready_msg.t.as_str()
        )));
    }
    let ready: Ready = ready_msg
        .payload()
        .map_err(|e| AgentClientError::Handshake(format!("decode ready payload: {e}")))?;

    // The negotiated capability generation is the lower of what we speak and
    // what the sandbox echoed in its ready frame (`ready_msg.v`). For the
    // load-bearing case — a newer host meeting an older runtime — this is the
    // runtime's generation, so the send gate withholds features it can't
    // handle. The codec generation (`protocol`) is negotiated separately.
    let negotiated_version = protocol.version().min(ready_msg.v);

    Ok(AgentHandshake {
        id_min,
        id_max,
        protocol,
        negotiated_version,
        ready_body: ready_frame.body,
        ready,
    })
}

fn first_request_id(id_min: u32) -> u32 {
    id_min.max(1)
}

#[cfg(feature = "stream")]
fn ensure_usable_id_range(id_min: u32, id_max: u32) -> AgentClientResult<()> {
    if usable_id_count(id_min, id_max) == 0 {
        return Err(AgentClientError::Handshake(format!(
            "relay id range contains no usable nonzero ids: start={id_min}, end={id_max}"
        )));
    }
    Ok(())
}

fn usable_id_count(id_min: u32, id_max: u32) -> u32 {
    id_max.saturating_sub(first_request_id(id_min))
}

#[cfg(feature = "stream")]
fn looks_like_legacy_relay_handshake(id_min: u32, id_max: u32) -> bool {
    // TODO(upgrade-0.6): Remove in 0.6.x or later once pre-0.5 relay
    // handshakes are no longer accepted.
    // In the legacy relay handshake, the first 4 bytes are the id offset and
    // the next 4 bytes are already the ready-frame length prefix. In the v2
    // handshake, the second word is the exclusive upper id bound, which is far
    // larger than any valid frame length. Tiny current ranges are possible in
    // tests, so prefer the current interpretation when the range is otherwise
    // valid and starts at a nonzero id.
    id_max >= FRAME_HEADER_SIZE as u32
        && id_max <= MAX_FRAME_SIZE
        && (id_min == 0 || id_min >= id_max)
}

#[cfg(feature = "stream")]
async fn read_raw_frame_after_len_prefix<R>(
    reader: &mut R,
    len_buf: [u8; 4],
    deadline: Instant,
) -> AgentClientResult<RawFrame>
where
    R: HandshakeReader + ?Sized,
{
    let frame_len = u32::from_be_bytes(len_buf);
    if frame_len > MAX_FRAME_SIZE {
        return Err(AgentClientError::Handshake(format!(
            "legacy ready frame too large: {frame_len} bytes (max {MAX_FRAME_SIZE})"
        )));
    }
    if frame_len < FRAME_HEADER_SIZE as u32 {
        return Err(AgentClientError::Handshake(format!(
            "legacy ready frame too short: {frame_len} bytes"
        )));
    }

    let mut data = vec![0u8; frame_len as usize];
    tokio::time::timeout_at(deadline, reader.read_exact_handshake(&mut data))
        .await
        .map_err(|_| {
            AgentClientError::Handshake(
                "read legacy ready frame: timed out before relay sent frame".into(),
            )
        })?
        .map_err(|e| AgentClientError::Handshake(format!("read legacy ready frame: {e}")))?;

    let id = u32::from_be_bytes(data[0..4].try_into().unwrap());
    let flags = data[4];
    let body = data[FRAME_HEADER_SIZE..].to_vec();

    Ok(RawFrame { id, flags, body })
}

#[cfg(feature = "stream")]
impl<R> HandshakeReader for R
where
    R: tokio::io::AsyncRead + Unpin + Send,
{
    fn read_exact_handshake<'a>(
        &'a mut self,
        out: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = AgentClientResult<()>> + Send + 'a>> {
        Box::pin(async move {
            tokio::io::AsyncReadExt::read_exact(self, out)
                .await
                .map(|_| ())
                .map_err(|e| AgentClientError::Handshake(e.to_string()))
        })
    }

    fn read_frame_handshake<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = AgentClientResult<RawFrame>> + Send + 'a>> {
        Box::pin(async move {
            codec::read_raw_frame(self)
                .await
                .map_err(AgentClientError::Protocol)
        })
    }
}

#[cfg(feature = "stream")]
async fn stream_writer_loop<W>(
    mut writer: W,
    mut rx: mpsc::Receiver<WriterCommand>,
    closed: Arc<AtomicBool>,
    writer_failed: Arc<Notify>,
) where
    W: tokio::io::AsyncWrite + Unpin,
{
    while let Some(command) = rx.recv().await {
        if closed.load(Ordering::Acquire) {
            let _ = command.ack.send(Err(AgentClientError::Closed));
            break;
        }
        if let Some(lease) = &command.lease
            && !lease.active.load(std::sync::atomic::Ordering::Acquire)
        {
            let _ = command
                .ack
                .send(Err(AgentClientError::SessionClosed(lease.id)));
            continue;
        }
        if let Some(lease) = &command.lease {
            lease.sent.store(true, std::sync::atomic::Ordering::Release);
        }
        if let Err(e) = codec::write_raw_frame(&mut writer, &command.frame).await {
            tracing::debug!("agent client: stream writer error: {e}");
            let _ = command.ack.send(Err(AgentClientError::Protocol(e)));
            closed.store(true, Ordering::Release);
            writer_failed.notify_one();
            break;
        }
        let _ = command.ack.send(Ok(()));
    }
}

/// Background task that reads frames from the relay and dispatches them to
/// pending channels by correlation ID. Operates on raw frames — no CBOR.
#[cfg(feature = "stream")]
async fn reader_loop<R>(
    mut reader: R,
    pending: Arc<Mutex<PendingRegistry>>,
    closed: Arc<AtomicBool>,
    writer_failed: Arc<Notify>,
) where
    R: tokio::io::AsyncRead + Unpin,
{
    loop {
        let incoming = tokio::select! {
            _ = writer_failed.notified() => break,
            incoming = codec::read_raw_frame(&mut reader) => incoming,
        };
        let frame = match incoming {
            Ok(frame) => frame,
            Err(e) => {
                tracing::debug!("agent client: reader EOF or error: {e}");
                break;
            }
        };

        dispatch_frame(frame, &pending).await;
    }

    // Reader exited — drop all senders so outstanding receivers wake up.
    closed.store(true, Ordering::Release);
    let mut map = pending.lock().await;
    for handler in map.values() {
        if let Pending::Owned(lease) = handler {
            lease.transport_closed();
        }
    }
    map.clear();
}

#[cfg(feature = "stream")]
async fn dispatch_frame(frame: RawFrame, pending: &Arc<Mutex<PendingRegistry>>) {
    let id = frame.id;
    let is_terminal = (frame.flags & FLAG_TERMINAL) != 0;

    let tx = {
        let mut map = pending.lock().await;
        let Some(tx) = map.get(&id).cloned() else {
            tracing::trace!("agent client: no pending handler for id={id}");
            return;
        };
        if let Pending::Owned(lease) = &tx {
            // Set the lease inactive before making the ID reusable to any
            // response routing path. Retained references still reserve it.
            lease.push(frame);
            if is_terminal {
                map.remove(&id);
            }
            return;
        }
        if is_terminal {
            map.remove(&id);
        }
        tx
    };

    // A slow legacy receiver must not block the shared transport reader either.
    // Closing without a terminal is an incomplete stream, never success.
    if let Pending::Legacy(tx) = tx
        && tx.try_send(frame).is_err()
    {
        pending.lock().await.remove(&id);
    }
}

/// Translate a stream of raw frames into typed messages.
async fn decode_stream_task(mut raw_rx: mpsc::Receiver<RawFrame>, tx: mpsc::Sender<Message>) {
    while let Some(frame) = raw_rx.recv().await {
        match codec::raw_frame_to_message(frame) {
            Ok(msg) => {
                if tx.send(msg).await.is_err() {
                    break;
                }
            }
            Err(e) => {
                tracing::warn!("agent client: failed to decode frame in stream: {e}");
                // Continue — single malformed frame shouldn't kill the stream.
            }
        }
    }
}

/// Encode a typed payload to a CBOR `Message` body.
fn encode_message_body<T: Serialize>(
    version: u8,
    t: MessageType,
    payload: &T,
) -> AgentClientResult<Vec<u8>> {
    let mut msg = Message::with_payload(t, 0, payload)?;
    msg.v = version;
    let mut body = Vec::new();
    ciborium::into_writer(&msg, &mut body).map_err(microsandbox_protocol::ProtocolError::from)?;
    Ok(body)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "uds", unix))]
    use microsandbox_protocol::core::Ready;
    #[cfg(all(feature = "uds", unix))]
    use microsandbox_protocol::exec::ExecRequest;
    #[cfg(all(feature = "uds", unix))]
    use microsandbox_protocol::message::PROTOCOL_VERSION;
    #[cfg(all(feature = "uds", unix))]
    use tokio::io::AsyncWriteExt;
    #[cfg(all(feature = "uds", unix))]
    use tokio::net::UnixListener;
    #[cfg(all(feature = "uds", unix))]
    use tokio::sync::oneshot;

    use super::*;

    #[cfg(all(feature = "uds", unix))]
    #[tokio::test]
    async fn connect_decodes_ready_payload() {
        let temp = tempfile::tempdir().unwrap();
        let sock_path = temp.path().join("agent.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();
        let ready = Ready {
            boot_time_ns: 11,
            init_time_ns: 22,
            ready_time_ns: 33,
            agent_version: "9.9.9".to_string(),
        };
        let ready_msg = Message::with_payload(MessageType::Ready, 0, &ready).unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(&1u32.to_be_bytes()).await.unwrap();
            socket.write_all(&8u32.to_be_bytes()).await.unwrap();
            codec::write_message(&mut socket, &ready_msg).await.unwrap();
        });

        let client =
            AgentClient::connect_with_deadline(&sock_path, Instant::now() + Duration::from_secs(1))
                .await
                .unwrap();

        assert_eq!(client.protocol(), AgentProtocol::Current);
        // Both peers speak the current generation, so that is what is negotiated.
        assert_eq!(client.negotiated_version(), PROTOCOL_VERSION);
        assert!(client.supports(MessageType::FsRequest));
        // The runtime's self-reported version round-trips from the ready frame.
        assert_eq!(client.agent_version(), "9.9.9");
        let decoded = client.ready().unwrap();
        assert_eq!(decoded.boot_time_ns, ready.boot_time_ns);
        assert_eq!(decoded.init_time_ns, ready.init_time_ns);
        assert_eq!(decoded.ready_time_ns, ready.ready_time_ns);

        let raw_msg: Message = ciborium::from_reader(client.ready_bytes()).unwrap();
        assert_eq!(raw_msg.t, MessageType::Ready);
    }

    #[cfg(all(feature = "named-pipe", windows))]
    #[tokio::test]
    async fn connect_decodes_ready_payload_from_named_pipe() {
        use microsandbox_protocol::core::Ready;
        use microsandbox_protocol::message::PROTOCOL_VERSION;
        use tokio::io::AsyncWriteExt;
        use tokio::net::windows::named_pipe::{PipeMode, ServerOptions};

        let pipe_path = unique_named_pipe("ready");
        let server = ServerOptions::new()
            .first_pipe_instance(true)
            .pipe_mode(PipeMode::Byte)
            .create(&pipe_path)
            .unwrap();
        let ready = Ready {
            boot_time_ns: 11,
            init_time_ns: 22,
            ready_time_ns: 33,
            agent_version: "named-pipe-test".to_string(),
        };
        let ready_msg = Message::with_payload(MessageType::Ready, 0, &ready).unwrap();

        tokio::spawn(async move {
            let mut server = server;
            server.connect().await.unwrap();
            server.write_all(&1u32.to_be_bytes()).await.unwrap();
            server.write_all(&8u32.to_be_bytes()).await.unwrap();
            codec::write_message(&mut server, &ready_msg).await.unwrap();
        });

        let client = AgentClient::connect_with_deadline(
            std::path::Path::new(&pipe_path),
            Instant::now() + Duration::from_secs(1),
        )
        .await
        .unwrap();

        assert_eq!(client.protocol(), AgentProtocol::Current);
        assert_eq!(client.negotiated_version(), PROTOCOL_VERSION);
        assert_eq!(client.agent_version(), "named-pipe-test");
        let decoded = client.ready().unwrap();
        assert_eq!(decoded.boot_time_ns, ready.boot_time_ns);
        assert_eq!(decoded.init_time_ns, ready.init_time_ns);
        assert_eq!(decoded.ready_time_ns, ready.ready_time_ns);
    }

    #[cfg(all(feature = "uds", unix))]
    #[tokio::test]
    async fn connect_negotiates_down_to_older_guest_generation() {
        let temp = tempfile::tempdir().unwrap();
        let sock_path = temp.path().join("agent.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();
        let ready = Ready {
            boot_time_ns: 1,
            init_time_ns: 2,
            ready_time_ns: 3,
            ..Default::default()
        };
        // A current-codec guest that advertises an older capability generation in
        // its ready frame (a runtime one generation behind this host).
        let mut ready_msg = Message::with_payload(MessageType::Ready, 0, &ready).unwrap();
        ready_msg.v = 1;

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(&1u32.to_be_bytes()).await.unwrap();
            socket
                .write_all(&microsandbox_protocol::AGENT_RELAY_ID_RANGE_STEP.to_be_bytes())
                .await
                .unwrap();
            codec::write_message(&mut socket, &ready_msg).await.unwrap();
        });

        let client =
            AgentClient::connect_with_deadline(&sock_path, Instant::now() + Duration::from_secs(1))
                .await
                .unwrap();

        // Current codec, but the capability gate is pinned to the guest's older
        // generation: min(host PROTOCOL_VERSION, guest's advertised 1) == 1.
        assert_eq!(client.protocol(), AgentProtocol::Current);
        assert_eq!(client.negotiated_version(), 1);
        // Exec is in the baseline; filesystem is not, at generation 1.
        assert!(client.supports(MessageType::ExecRequest));
        assert!(!client.supports(MessageType::FsRequest));
    }

    #[cfg(all(feature = "uds", unix))]
    #[tokio::test]
    async fn connect_accepts_legacy_relay_handshake() {
        assert_accepts_legacy_relay_handshake(0).await;
        assert_accepts_legacy_relay_handshake(268_435_455).await;
    }

    #[cfg(all(feature = "uds", unix))]
    #[tokio::test]
    async fn legacy_relay_requests_use_v1_and_legacy_id_range() {
        let temp = tempfile::tempdir().unwrap();
        let sock_path = temp.path().join("agent.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();
        let ready = Ready {
            boot_time_ns: 11,
            init_time_ns: 22,
            ready_time_ns: 33,
            ..Default::default()
        };
        let ready_msg = Message::with_payload(MessageType::Ready, 0, &ready).unwrap();
        let id_offset = 268_435_455u32;
        let (frame_tx, frame_rx) = oneshot::channel();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(&id_offset.to_be_bytes()).await.unwrap();
            codec::write_message(&mut socket, &ready_msg).await.unwrap();
            let frame = codec::read_raw_frame(&mut socket).await.unwrap();
            frame_tx.send(frame).unwrap();
        });

        let client =
            AgentClient::connect_with_deadline(&sock_path, Instant::now() + Duration::from_secs(1))
                .await
                .unwrap();
        let request = ExecRequest {
            cmd: "/bin/true".into(),
            args: Vec::new(),
            env: Vec::new(),
            cwd: None,
            user: None,
            tty: false,
            rows: 24,
            cols: 80,
            rlimits: Vec::new(),
        };
        let (id, _rx) = client
            .stream(MessageType::ExecRequest, &request)
            .await
            .unwrap();

        let frame = frame_rx.await.unwrap();
        let message = codec::raw_frame_to_message(frame).unwrap();

        assert_eq!(id, id_offset + 1);
        assert_eq!(message.id, id_offset + 1);
        assert_eq!(message.v, LEGACY_PROTOCOL_VERSION);
        assert_eq!(message.t, MessageType::ExecRequest);
    }

    #[test]
    fn version_compat_across_generations() {
        use MessageType::{ExecRequest, FsRequest};
        // (message type, peer generation, expected allowed). Generation 1 is the
        // pre-0.5 legacy runtime (no filesystem); generation 2 introduced the
        // Fs* types; generation 6 is current.
        let cases = [
            (ExecRequest, 1, true),
            (ExecRequest, 2, true),
            (ExecRequest, 3, true),
            (FsRequest, 1, false),
            (FsRequest, 2, true),
            (FsRequest, 3, true),
        ];
        for (t, generation, allowed) in cases {
            assert_eq!(
                AgentClient::ensure_version_compat_for(t, generation).is_ok(),
                allowed,
                "{t:?} at generation {generation}"
            );
        }
    }

    #[test]
    fn version_compat_rejection_is_typed() {
        // Filesystem on the legacy (generation 1) runtime is rejected before any
        // send, with the structured error whose message tells the user to restart.
        let err =
            AgentClient::ensure_version_compat_for(MessageType::FsRequest, LEGACY_PROTOCOL_VERSION)
                .unwrap_err();
        assert!(matches!(
            err,
            AgentClientError::UnsupportedOperation {
                needs: 2,
                peer: 1,
                ..
            }
        ));
    }

    #[cfg(all(feature = "uds", unix))]
    #[tokio::test]
    async fn connect_preserves_current_peer_protocol_version() {
        let temp = tempfile::tempdir().unwrap();
        let sock_path = temp.path().join("agent.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();
        let ready = Ready {
            boot_time_ns: 11,
            init_time_ns: 22,
            ready_time_ns: 33,
            ..Default::default()
        };
        let mut ready_msg = Message::with_payload(MessageType::Ready, 0, &ready).unwrap();
        ready_msg.v = 2;

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(&1u32.to_be_bytes()).await.unwrap();
            socket
                .write_all(&microsandbox_protocol::AGENT_RELAY_ID_RANGE_STEP.to_be_bytes())
                .await
                .unwrap();
            codec::write_message(&mut socket, &ready_msg).await.unwrap();
        });

        let client =
            AgentClient::connect_with_deadline(&sock_path, Instant::now() + Duration::from_secs(1))
                .await
                .unwrap();

        assert_eq!(client.protocol(), AgentProtocol::Current);
        // The runtime reported generation 2, so that is the negotiated capability.
        assert_eq!(client.negotiated_version(), 2);
        // TCP forwarding (generation 4) is unavailable to a generation-2 runtime.
        assert!(!client.supports(MessageType::TcpConnect));
    }

    #[cfg(all(feature = "uds", unix))]
    async fn assert_accepts_legacy_relay_handshake(id_offset: u32) {
        let temp = tempfile::tempdir().unwrap();
        let sock_path = temp.path().join("agent.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();
        let ready = Ready {
            boot_time_ns: 11,
            init_time_ns: 22,
            ready_time_ns: 33,
            ..Default::default()
        };
        let ready_msg = Message::with_payload(MessageType::Ready, 0, &ready).unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(&id_offset.to_be_bytes()).await.unwrap();
            codec::write_message(&mut socket, &ready_msg).await.unwrap();
        });

        let client =
            AgentClient::connect_with_deadline(&sock_path, Instant::now() + Duration::from_secs(1))
                .await
                .unwrap();

        assert_eq!(client.protocol(), AgentProtocol::LegacyV1);
        assert_eq!(client.negotiated_version(), LEGACY_PROTOCOL_VERSION);
        let decoded = client.ready().unwrap();
        assert_eq!(decoded.boot_time_ns, ready.boot_time_ns);
        assert_eq!(decoded.init_time_ns, ready.init_time_ns);
        assert_eq!(decoded.ready_time_ns, ready.ready_time_ns);
    }

    #[cfg(all(feature = "named-pipe", windows))]
    fn unique_named_pipe(name: &str) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!(
            r"\\.\pipe\msb-agent-client-{name}-{}-{nanos}",
            std::process::id()
        )
    }

    #[cfg(feature = "stream")]
    #[tokio::test]
    async fn connect_stream_handshakes_and_streams_exec() {
        use microsandbox_protocol::exec::{ExecExited, ExecRequest, ExecStdout};
        use tokio::io::AsyncWriteExt;

        let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);
        let ready = Ready {
            boot_time_ns: 11,
            init_time_ns: 22,
            ready_time_ns: 33,
            agent_version: "stream-test".to_string(),
        };
        let ready_msg = Message::with_payload(MessageType::Ready, 0, &ready).unwrap();

        tokio::spawn(async move {
            // Relay handshake: [id_min][id_max] then the core.ready frame.
            server_io.write_all(&1u32.to_be_bytes()).await.unwrap();
            server_io.write_all(&1024u32.to_be_bytes()).await.unwrap();
            codec::write_message(&mut server_io, &ready_msg)
                .await
                .unwrap();

            // One exec stream echoed back: stdout, then a terminal exited.
            let request = codec::read_raw_frame(&mut server_io).await.unwrap();
            let stdout = Message::with_payload(
                MessageType::ExecStdout,
                request.id,
                &ExecStdout {
                    data: b"hi".to_vec(),
                },
            )
            .unwrap();
            codec::write_message(&mut server_io, &stdout).await.unwrap();
            let exited =
                Message::with_payload(MessageType::ExecExited, request.id, &ExecExited { code: 0 })
                    .unwrap();
            codec::write_message(&mut server_io, &exited).await.unwrap();
        });

        let client = AgentClient::connect_stream_with_deadline(
            client_io,
            Instant::now() + Duration::from_secs(1),
        )
        .await
        .unwrap();

        assert_eq!(client.protocol(), AgentProtocol::Current);
        assert_eq!(client.agent_version(), "stream-test");
        assert!(client.supports(MessageType::ExecRequest));

        let request = ExecRequest {
            cmd: "echo".into(),
            args: vec!["hi".into()],
            env: Vec::new(),
            cwd: None,
            user: None,
            tty: false,
            rows: 24,
            cols: 80,
            rlimits: Vec::new(),
        };
        let (_id, mut rx) = client
            .stream(MessageType::ExecRequest, &request)
            .await
            .unwrap();

        let first = rx.recv().await.unwrap();
        assert_eq!(first.t, MessageType::ExecStdout);
        let out: ExecStdout = first.payload().unwrap();
        assert_eq!(out.data, b"hi");

        let second = rx.recv().await.unwrap();
        assert_eq!(second.t, MessageType::ExecExited);
        let exit: ExecExited = second.payload().unwrap();
        assert_eq!(exit.code, 0);
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for AgentClient {
    fn drop(&mut self) {
        self.reader_handle.abort();
        self.writer_handle.abort();
    }
}
