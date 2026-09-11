//! SSH termination toward the guest and reorigination toward upstream.
//!
//! brokerd acts as SSH server toward the guest (terminating the diverted
//! guest client session) and SSH client toward upstream (authenticating
//! with the sealed Ed25519 key). After both sessions establish, channels
//! relay guest↔upstream: session channels (shell, exec, pty, env, signal,
//! window-change) proxy transparently, while `direct-tcpip` and subsystem
//! (SFTP) requests are refused as out of scope for this broker.
//!
//! The guest's requested SSH username must exactly match the provisioned
//! upstream username. It is a login principal, not a workload identity:
//! instance attribution comes from the trusted divert context, never from
//! a guest username or public key. The broker accepts proof with any guest
//! public key within that context; the upstream credential stays in custody.
//! Endpoint admission alone is not complete per-instance key authorization.
//! The upstream dial and SSH authentication start only after the username check
//! and guest public-key proof, with pinned host-key verification and no fallback.
//!
//! Upstream password or keyboard-interactive authentication has no path
//! through the broker (there is no password custody), so only upstream
//! public-key authentication is attempted.
//!
//! Relayed bytes pass through the DLP scanner: guest-to-upstream channel
//! data, extended data, and exec commands enforce the session's match
//! library (block closes the channel, block-and-terminate tears down the
//! session), while upstream-to-guest relayed data is audit/count-only by
//! default and always forwards (see [`UPSTREAM_RESPONSE_ENFORCEMENT`]).

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use microsandbox_scan::{PatternLibrary, ScanReport, ScanState, Severity};
use russh::keys::{Algorithm, PrivateKey, PrivateKeyWithHashAlg, PublicKey, PublicKeyBase64};
use russh::server::{Auth, ChannelOpenHandle, Session};
use russh::{ChannelId, ChannelMsg, Sig};
use tokio::sync::{Mutex, Notify, OnceCell, oneshot};

use microsandbox_protocol::bootstrap::BrokerUpstreamHost;

use crate::audit::{AuditIdentity, ChannelDirection};
use crate::broker::Broker;
use crate::error::{BrokerError, BrokerResult};
use crate::keys::BrokerKey;
use crate::policy::TransportAdmission;
use crate::prelude::SessionIdentity;
use crate::ssh_io::CancellableIo;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Time allowed for one upstream channel-request reply.
const REPLY_TIMEOUT_SECS: u64 = 30;

/// Time allowed for upstream dialing, handshake and authentication together.
const UPSTREAM_AUTH_TIMEOUT_SECS: u64 = 30;

/// One bounded grace period for observed completion after cancellation.
const RETIREMENT_TIMEOUT_SECS: u64 = 5;

/// Upstream-to-guest relay enforcement switch (audit-only by default).
///
/// `false` keeps the response leg audit/count-only: reports still feed the
/// response counters and audit records, but every chunk forwards. A
/// 25-fixture realistic-corpus battery (150 chunks across both legs, whole
/// and midpoint-split) reports no hits for 32-byte credentials, yet the
/// response leg stays non-enforcing until response-side enforcement is
/// explicitly adopted: flipping to `true` routes the pump through
/// [`enforcement_for`], so a block closes the channel and a terminate
/// tears down the session.
pub const UPSTREAM_RESPONSE_ENFORCEMENT: bool = false;

/// Each managed relay admits at most this many unjoined channel pumps.
/// Legacy fixture/console mode retains its existing channel policy.
pub(crate) const MANAGED_CHANNEL_LIMIT: usize = 16;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A parsed upstream pin: who to be upstream and what key to require.
#[derive(Debug, Clone)]
pub struct UpstreamPin {
    /// Login user for upstream public-key authentication.
    pub user: String,

    /// Expected upstream server public key.
    pub expected: PublicKey,
}

/// Guest-facing SSH server state shared across channels of one session.
struct RelayShared {
    /// Published only after guest authentication and pinned upstream setup.
    upstream: Mutex<Option<russh::client::Handle<UpstreamVerifier>>>,

    /// Authentication completed for this one exact upstream principal.
    authenticated: OnceCell<()>,

    /// A timed-out hidden library task is not an observed completed retirement.
    retirement_incomplete: AtomicBool,

    /// Upstream write halves keyed by guest channel id.
    channels: Mutex<HashMap<ChannelId, Arc<UpstreamChannel>>>,

    /// In-flight relay tasks, aborted when the guest session ends.
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,

    /// Managed mode bounds retained channel resources, including closed pumps
    /// until their task completion has actually been joined.
    managed_channel_limit: Option<usize>,

    /// Validated session identity threaded from the divert prelude.
    identity: AuditIdentity,

    /// Compiled DLP match library shared across sessions.
    library: Arc<PatternLibrary>,

    /// Guest-to-upstream scan state (channel data, extended data, exec).
    scan_request: Mutex<ScanState>,

    /// Upstream-to-guest scan state (relayed data only).
    scan_response: Mutex<ScanState>,

    /// Per-session teardown trigger for block-and-terminate enforcement.
    termination: TerminationHandle,

    /// Guest-to-upstream chunks that hit with counting enabled.
    request_hits: AtomicU64,

    /// Upstream-to-guest chunks that hit with counting enabled.
    response_hits: AtomicU64,
}

/// Per-session teardown trigger for block-and-terminate enforcement.
///
/// Cloned into the shared relay state so any guest-to-upstream handler
/// can terminate its own session. Termination cancels that session's relay
/// tasks and disconnects both SSH legs; the global vsock accept loop is
/// untouched — per-session teardown never stops other sessions. (The only
/// global stop is console shutdown, which powers off the guest.)
#[derive(Debug, Clone)]
pub struct TerminationHandle {
    /// Set before notifying, so late waiters observe termination.
    flag: Arc<AtomicBool>,

    /// Wakes the reoriginate teardown select.
    notify: Arc<Notify>,
}

/// Relay decision for one scanned chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanEnforcement {
    /// Forward the chunk unchanged.
    Forward,

    /// Drop the chunk and close the channel on both legs; the session lives.
    CloseChannel,

    /// Drop the chunk and tear down the whole relay session.
    TerminateSession,
}

/// One relayed channel: the upstream write half plus its pending reply.
struct UpstreamChannel {
    /// Upstream write half for guest→upstream forwarding.
    tx: Mutex<russh::ChannelWriteHalf<russh::client::Msg>>,

    /// Completer for the oldest request awaiting an upstream reply.
    pending: Mutex<Option<oneshot::Sender<bool>>>,
}

/// Guest-facing SSH server handler: one per diverted connection.
struct GuestServer<F> {
    /// Shared relay state for this diverted connection.
    shared: Arc<RelayShared>,

    /// Lazy upstream connection and credential, unused until guest proof succeeds.
    pending_upstream: Option<F>,

    /// Existing host-provisioned upstream identity and server pin.
    authority: GuestAuthority,
}

/// One credential source, selected explicitly by the broker mode. Managed
/// sessions never fall back to the legacy global pin or credential.
pub(crate) enum GuestAuthority {
    Legacy {
        key: Arc<PrivateKey>,
        pin: UpstreamPin,
    },
    Managed {
        broker: Arc<Broker>,
        admission: Arc<TransportAdmission>,
    },
}

impl GuestAuthority {
    async fn allows_user(&self, user: &str) -> bool {
        match self {
            Self::Legacy { pin, .. } => pin.matches_user(user),
            Self::Managed { broker, admission } => match broker.managed_policy() {
                Ok(store) => store.lock().await.select_transport(admission, user).is_ok(),
                Err(_) => false,
            },
        }
    }

    async fn select(&self, user: &str) -> Option<(Arc<PrivateKey>, UpstreamPin)> {
        match self {
            Self::Legacy { key, pin } => pin
                .matches_user(user)
                .then(|| (Arc::clone(key), pin.clone())),
            Self::Managed { broker, admission } => {
                let credential = broker
                    .managed_policy()
                    .ok()?
                    .lock()
                    .await
                    .select_transport(admission, user)
                    .ok()?;
                let (key, pin) = credential.material();
                Some((Arc::new(key.private_key().clone()), pin.clone()))
            }
        }
    }
}

/// Upstream client handler enforcing strict pinned host-key verification.
#[derive(Clone)]
struct UpstreamVerifier {
    /// The only server key accepted on this connection.
    expected: PublicKey,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl UpstreamPin {
    /// Login user for upstream public-key authentication.
    pub fn user(&self) -> &str {
        &self.user
    }

    /// Match the login principal without aliases, case folding or remapping.
    /// This does not establish the originating workload's identity.
    fn matches_user(&self, requested: &str) -> bool {
        !requested.is_empty() && requested == self.user
    }
}

impl TerminationHandle {
    /// Create an untriggered termination handle.
    pub fn new() -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(Notify::new()),
        }
    }

    /// Terminate the session: prompt waiters and mark late checks.
    pub fn terminate(&self) {
        self.flag.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    /// Whether termination was triggered.
    pub fn is_terminated(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    /// Wait until termination is triggered.
    pub async fn terminated(&self) {
        self.terminated_registered(|| {}).await;
    }

    async fn terminated_registered(&self, mut registered: impl FnMut()) {
        loop {
            // Register before observing the flag: notify_waiters does not retain
            // a permit if termination races between the check and registration.
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            registered();
            if self.is_terminated() {
                return;
            }
            notified.await;
        }
    }
}
impl<Upstream> GuestServer<Upstream> {
    /// Run `f` against the upstream channel for `channel`, if still present.
    ///
    /// A channel that already closed resolves to `false` so the guest gets
    /// a clean failure instead of a stalled request.
    async fn with_channel<F, Fut>(&mut self, channel: ChannelId, f: F) -> bool
    where
        F: FnOnce(Arc<UpstreamChannel>) -> Fut,
        Fut: Future<Output = bool>,
    {
        let Some(state) = self.shared.channels.lock().await.get(&channel).cloned() else {
            return false;
        };
        f(state).await
    }

    /// Count and audit a guest-to-upstream scan report, then return whether
    /// the chunk may forward.
    async fn observe_request(
        &mut self,
        channel: ChannelId,
        report: &ScanReport,
    ) -> ScanEnforcement {
        self.shared
            .observe(
                channel,
                ChannelDirection::GuestToUpstream,
                report,
                &self.shared.request_hits,
            )
            .await
    }

    /// Close a blocked channel on both legs; the session lives.
    ///
    /// Best-effort: either leg may already be closing when enforcement
    /// fires, and a failed close carries no further action.
    async fn close_blocked_channel(&mut self, channel: ChannelId, session: &mut Session) {
        if let Some(state) = self.shared.channels.lock().await.remove(&channel) {
            let tx = state.tx.lock().await;
            let _ = tx.close().await;
        }
        let _ = session.close(channel);
    }
}

impl RelayShared {
    /// Reclaim only observed completed pumps before counting capacity. Channel
    /// admission callbacks are serialized by the guest SSH handler; pumps do
    /// not acquire this task-list lock.
    async fn channel_capacity(&self) -> bool {
        let Some(limit) = self.managed_channel_limit else {
            return true;
        };
        let mut tasks = self.tasks.lock().await;
        let mut index = 0;
        while index < tasks.len() {
            if tasks[index].is_finished() {
                if tasks.swap_remove(index).await.is_err() {
                    self.termination.terminate();
                    return false;
                }
            } else {
                index += 1;
            }
        }
        !self.termination.is_terminated() && tasks.len() < limit
    }

    /// Wait for actual native-client completion after cancellation closes I/O.
    async fn join_upstream(&self) -> bool {
        tokio::time::timeout(Duration::from_secs(RETIREMENT_TIMEOUT_SECS), async {
            let upstream = self.upstream.lock().await.take();
            if let Some(upstream) = upstream {
                let _ = upstream.await;
            }
        })
        .await
        .is_ok()
    }

    /// Abort all owned pumps first, then await every JoinHandle. Abort alone
    /// does not establish that a future released its stream or key references.
    async fn join_pumps(&self) -> bool {
        tokio::time::timeout(Duration::from_secs(RETIREMENT_TIMEOUT_SECS), async {
            let tasks: Vec<_> = self.tasks.lock().await.drain(..).collect();
            for task in &tasks {
                task.abort();
            }
            for task in tasks {
                let _ = task.await;
            }
        })
        .await
        .is_ok()
    }

    /// Count and audit one scan report, returning the relay decision.
    ///
    /// Counting and audit lines follow the report's strictest action
    /// flags; the decision follows its enforcement. Upstream-to-guest
    /// callers pass reports through this for audit/count only and forward
    /// regardless of the returned decision.
    async fn observe(
        &self,
        channel: ChannelId,
        direction: ChannelDirection,
        report: &ScanReport,
        counter: &AtomicU64,
    ) -> ScanEnforcement {
        let Some(action) = report.strictest_action else {
            return ScanEnforcement::Forward;
        };
        if action.count {
            counter.fetch_add(1, Ordering::Relaxed);
        }
        if action.audit {
            for hit in &report.hits {
                let credential_id = self
                    .library
                    .lookup(&hit.pattern_id)
                    .map(|meta| meta.credential_id.to_string());
                self.identity.emit(
                    channel.number(),
                    direction,
                    credential_id,
                    hit.pattern_id,
                    hit.digest,
                    action,
                );
            }
        }
        enforcement_for(report)
    }
}

/// One guest channel request to forward upstream with a reply.
enum ChannelOp {
    /// Environment variable request.
    SetEnv {
        /// Variable name.
        name: String,

        /// Variable value.
        value: String,
    },

    /// PTY allocation request.
    Pty {
        /// Terminal name.
        term: String,

        /// Column width.
        col_width: u32,

        /// Row height.
        row_height: u32,

        /// Pixel width.
        pix_width: u32,

        /// Pixel height.
        pix_height: u32,

        /// Terminal modes.
        modes: Vec<(russh::Pty, u32)>,
    },

    /// Shell request.
    Shell,

    /// Exec request.
    Exec {
        /// Command bytes.
        command: Vec<u8>,
    },
}

impl UpstreamChannel {
    /// Send one channel request upstream and await its reply.
    ///
    /// The reply arrives on the pump task as `Success`/`Failure`; this
    /// completer bridges it back to the requesting handler method, which
    /// then answers the guest. Times out closed rather than stalling the
    /// guest channel forever.
    async fn request(&self, op: ChannelOp) -> bool {
        let (reply_tx, reply_rx) = oneshot::channel();
        *self.pending.lock().await = Some(reply_tx);
        let sent = {
            let tx = self.tx.lock().await;
            match op {
                ChannelOp::SetEnv { name, value } => tx.set_env(true, name, value).await.is_ok(),
                ChannelOp::Pty {
                    term,
                    col_width,
                    row_height,
                    pix_width,
                    pix_height,
                    modes,
                } => tx
                    .request_pty(
                        true, &term, col_width, row_height, pix_width, pix_height, &modes,
                    )
                    .await
                    .is_ok(),
                ChannelOp::Shell => tx.request_shell(true).await.is_ok(),
                ChannelOp::Exec { command } => tx.exec(true, command).await.is_ok(),
            }
        };
        if !sent {
            *self.pending.lock().await = None;
            return false;
        }
        match tokio::time::timeout(Duration::from_secs(REPLY_TIMEOUT_SECS), reply_rx).await {
            Ok(Ok(ok)) => ok,
            _ => {
                *self.pending.lock().await = None;
                false
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for TerminationHandle {
    /// An untriggered termination handle.
    fn default() -> Self {
        Self::new()
    }
}

impl<F, U> russh::server::Handler for GuestServer<F>
where
    F: Future<Output = BrokerResult<U>> + Send + 'static,
    U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    type Error = BrokerError;

    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        _public_key: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        // Guest keys prove this SSH exchange, not workload identity or
        // entitlement to a different upstream principal.
        Ok(
            if !self.shared.termination.is_terminated() && self.authority.allows_user(user).await {
                Auth::Accept
            } else {
                Auth::reject()
            },
        )
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        _public_key: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        // Recheck the signed request independently of any earlier unsigned
        // offer, and before reusing or authenticating an upstream session.
        if self.shared.termination.is_terminated() {
            return Ok(Auth::reject());
        }
        let Some((key, pin)) = self.authority.select(user).await else {
            return Ok(Auth::reject());
        };
        if self.shared.authenticated.get().is_some() {
            return Ok(Auth::Accept);
        }
        let Some(upstream) = self.pending_upstream.take() else {
            return Ok(Auth::reject());
        };
        // russh calls this handler only after verifying the guest signature.
        // In particular, host-key rejection and unsigned key offers cannot
        // trigger an upstream connection or use the broker-owned credential.
        let setup = async {
            if self.shared.termination.is_terminated() {
                return Err(BrokerError::Ssh("upstream authentication cancelled".into()));
            }
            let stream = upstream.await?;
            authenticate_upstream(stream, key, &pin, &self.shared).await
        };
        tokio::pin!(setup);
        tokio::select! {
            result = &mut setup => result?,
            _ = self.shared.termination.terminated() => {
                if tokio::time::timeout(Duration::from_secs(RETIREMENT_TIMEOUT_SECS), &mut setup).await.is_err() {
                    self.shared.retirement_incomplete.store(true, Ordering::SeqCst);
                }
                return Err(BrokerError::Ssh("upstream authentication cancelled".into()));
            }
            _ = tokio::time::sleep(Duration::from_secs(UPSTREAM_AUTH_TIMEOUT_SECS)) => {
                self.shared.termination.terminate();
                if tokio::time::timeout(Duration::from_secs(RETIREMENT_TIMEOUT_SECS), &mut setup).await.is_err() {
                    self.shared.retirement_incomplete.store(true, Ordering::SeqCst);
                }
                return Err(BrokerError::Ssh("upstream authentication timed out".into()));
            }
        }
        if self.shared.termination.is_terminated() {
            return Ok(Auth::reject());
        }
        self.shared
            .authenticated
            .set(())
            .map_err(|_| BrokerError::Ssh("upstream session already initialized".into()))?;
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: russh::Channel<russh::server::Msg>,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let guest_id = channel.id();
        if !self.shared.channel_capacity().await {
            reply
                .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        }
        let client = self.shared.upstream.lock().await;
        let Some(client) = client.as_ref() else {
            reply
                .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        };
        let upstream = match client.channel_open_session().await {
            Ok(channel) => channel,
            Err(_) => {
                reply
                    .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                    .await;
                return Ok(());
            }
        };
        let (rx, tx) = upstream.split();
        let state = Arc::new(UpstreamChannel {
            tx: Mutex::new(tx),
            pending: Mutex::new(None),
        });
        self.shared
            .channels
            .lock()
            .await
            .insert(guest_id, Arc::clone(&state));
        let pump = tokio::spawn(pump_upstream_to_guest(
            session.handle(),
            guest_id,
            rx,
            Arc::clone(&state),
            Arc::clone(&self.shared),
        ));
        self.shared.tasks.lock().await.push(pump);
        reply.accept().await;
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        _channel: russh::Channel<russh::server::Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // No forwarded-tcpip through the broker: the diverted session
        // carries the guest's own channels, not new outbound tunnels.
        reply
            .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let ok = self
            .with_channel(channel, |state| async move {
                state
                    .request(ChannelOp::SetEnv {
                        name: variable_name.to_string(),
                        value: variable_value.to_string(),
                    })
                    .await
            })
            .await;
        answer(session, channel, ok)
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let modes = modes.to_vec();
        let ok = self
            .with_channel(channel, |state| async move {
                state
                    .request(ChannelOp::Pty {
                        term: term.to_string(),
                        col_width,
                        row_height,
                        pix_width,
                        pix_height,
                        modes,
                    })
                    .await
            })
            .await;
        answer(session, channel, ok)
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let ok = self
            .with_channel(channel, |state| async move {
                state.request(ChannelOp::Shell).await
            })
            .await;
        answer(session, channel, ok)
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Exec commands are guest-to-upstream bytes: scan the command and
        // enforce before anything reaches the upstream channel.
        let report = self.shared.scan_request.lock().await.scan_chunk(data);
        match self.observe_request(channel, &report).await {
            ScanEnforcement::Forward => {}
            ScanEnforcement::CloseChannel => {
                self.close_blocked_channel(channel, session).await;
                return Ok(());
            }
            ScanEnforcement::TerminateSession => {
                self.close_blocked_channel(channel, session).await;
                self.shared.termination.terminate();
                return Ok(());
            }
        }
        let command = data.to_vec();
        let ok = self
            .with_channel(channel, |state| async move {
                state.request(ChannelOp::Exec { command }).await
            })
            .await;
        answer(session, channel, ok)
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        _name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // No SFTP/subsystem path through the broker.
        answer(session, channel, false)
    }

    async fn signal(
        &mut self,
        channel: ChannelId,
        signal: Sig,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(state) = self.shared.channels.lock().await.get(&channel).cloned() {
            let tx = state.tx.lock().await;
            let _ = tx.signal(signal).await;
        }
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(state) = self.shared.channels.lock().await.get(&channel).cloned() {
            let tx = state.tx.lock().await;
            let _ = tx
                .window_change(col_width, row_height, pix_width, pix_height)
                .await;
        }
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let report = self.shared.scan_request.lock().await.scan_chunk(data);
        match self.observe_request(channel, &report).await {
            ScanEnforcement::Forward => {
                if let Some(state) = self.shared.channels.lock().await.get(&channel).cloned() {
                    let tx = state.tx.lock().await;
                    let _ = tx.data_bytes(data.to_vec()).await;
                }
            }
            ScanEnforcement::CloseChannel => {
                self.close_blocked_channel(channel, session).await;
            }
            ScanEnforcement::TerminateSession => {
                self.close_blocked_channel(channel, session).await;
                self.shared.termination.terminate();
            }
        }
        Ok(())
    }

    async fn extended_data(
        &mut self,
        channel: ChannelId,
        code: u32,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let report = self.shared.scan_request.lock().await.scan_chunk(data);
        match self.observe_request(channel, &report).await {
            ScanEnforcement::Forward => {
                if let Some(state) = self.shared.channels.lock().await.get(&channel).cloned() {
                    let tx = state.tx.lock().await;
                    let _ = tx.extended_data_bytes(code, data.to_vec()).await;
                }
            }
            ScanEnforcement::CloseChannel => {
                self.close_blocked_channel(channel, session).await;
            }
            ScanEnforcement::TerminateSession => {
                self.close_blocked_channel(channel, session).await;
                self.shared.termination.terminate();
            }
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(state) = self.shared.channels.lock().await.get(&channel).cloned() {
            let tx = state.tx.lock().await;
            let _ = tx.eof().await;
        }
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(state) = self.shared.channels.lock().await.remove(&channel) {
            let tx = state.tx.lock().await;
            let _ = tx.close().await;
        }
        Ok(())
    }
}

impl russh::client::Handler for UpstreamVerifier {
    type Error = BrokerError;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        // Strict pinning with no fallback to unverified: only the exact
        // pinned key (algorithm and bytes) is accepted. Certificates are
        // never accepted; a mismatch fails the handshake.
        let matches = match server_public_key {
            russh::keys::PublicKeyOrCertificate::PublicKey { key, .. } => {
                key.algorithm() == self.expected.algorithm()
                    && key.public_key_base64() == self.expected.public_key_base64()
            }
            russh::keys::PublicKeyOrCertificate::Certificate(_) => false,
        };
        Ok(matches)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Map a scan report's strictest action to a relay decision.
///
/// No hits — or a passthrough strictest action — forwards. Block and
/// block-and-log close the offending channel on both legs while the
/// session lives; block-and-terminate tears down the whole relay session.
/// Pure over the report, so the mapping is unit-testable without SSH.
pub fn enforcement_for(report: &ScanReport) -> ScanEnforcement {
    match report.strictest_action.and_then(|action| action.enforce) {
        None => ScanEnforcement::Forward,
        Some(Severity::Block | Severity::BlockAndLog) => ScanEnforcement::CloseChannel,
        Some(Severity::BlockAndTerminate) => ScanEnforcement::TerminateSession,
    }
}

/// Map an upstream-to-guest scan report to a relay decision under the
/// response-enforcement switch.
///
/// Audit-only (the default) always forwards; enabled routes through
/// [`enforcement_for`]. Pure over the report and the switch, so both the
/// current audit-only behavior and the future enforcing behavior are
/// unit-testable without SSH.
pub fn response_enforcement_for(report: &ScanReport) -> ScanEnforcement {
    if UPSTREAM_RESPONSE_ENFORCEMENT {
        enforcement_for(report)
    } else {
        ScanEnforcement::Forward
    }
}

/// Reoriginate one diverted guest session toward its pinned upstream.
///
/// `guest` is the accepted divert stream (starting with the guest's first
/// flight); `upstream` is an unpolled future opening the egress tunnel to the
/// pinned destination. It must perform no eager connection work. brokerd runs
/// the SSH server side on `guest` and, after authorization, the SSH client side
/// on the resulting upstream stream, relaying channels until the guest session
/// ends or DLP enforcement terminates it. `identity` is the validated
/// prelude identity attributed to every scan hit; `library` is the
/// compiled DLP match library shared across sessions.
///
/// The host must select this route before exposing any upstream SSH bytes
/// to the guest. Session A sees only this server's handshake; session B is
/// independent and uses the sealed credential only after guest proof succeeds.
pub async fn reoriginate<G, F, U>(
    guest: G,
    upstream: F,
    key: &BrokerKey,
    pin: &UpstreamPin,
    server_config: Arc<russh::server::Config>,
    identity: SessionIdentity,
    library: Arc<PatternLibrary>,
) -> BrokerResult<()>
where
    G: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    F: Future<Output = BrokerResult<U>> + Send + 'static,
    U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let outcome = reoriginate_owned(
        guest,
        upstream,
        key,
        pin,
        RelayOptions {
            server_config,
            identity: AuditIdentity::Legacy(identity),
            library,
            termination: TerminationHandle::new(),
        },
    )
    .await;
    outcome.result?;
    if !outcome.retired {
        return Err(BrokerError::Ssh("SSH relay retirement incomplete".into()));
    }
    Ok(())
}

/// Explicit runtime inputs for one owned SSH relay.
pub(crate) struct RelayOptions {
    pub(crate) server_config: Arc<russh::server::Config>,
    pub(crate) identity: AuditIdentity,
    pub(crate) library: Arc<PatternLibrary>,
    pub(crate) termination: TerminationHandle,
}

/// Protocol result and independently observed native task retirement.
pub(crate) struct RelayCompletion {
    pub(crate) result: BrokerResult<()>,
    pub(crate) retired: bool,
}

/// Never replace observed native-task completion with a cancellation flag.
pub(crate) async fn reoriginate_owned<G, F, U>(
    guest: G,
    upstream: F,
    key: &BrokerKey,
    pin: &UpstreamPin,
    options: RelayOptions,
) -> RelayCompletion
where
    G: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    F: Future<Output = BrokerResult<U>> + Send + 'static,
    U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    reoriginate_authorized(
        guest,
        upstream,
        GuestAuthority::Legacy {
            key: Arc::new(key.private_key().clone()),
            pin: pin.clone(),
        },
        options,
    )
    .await
}

/// Share the existing SSH/channel implementation with managed admission.
pub(crate) async fn reoriginate_authorized<G, F, U>(
    guest: G,
    upstream: F,
    authority: GuestAuthority,
    options: RelayOptions,
) -> RelayCompletion
where
    G: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    F: Future<Output = BrokerResult<U>> + Send + 'static,
    U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let RelayOptions {
        server_config,
        identity,
        library,
        termination,
    } = options;
    let managed_channel_limit =
        matches!(&authority, GuestAuthority::Managed { .. }).then_some(MANAGED_CHANNEL_LIMIT);
    let shared = Arc::new(RelayShared {
        upstream: Mutex::new(None),
        authenticated: OnceCell::new(),
        retirement_incomplete: AtomicBool::new(false),
        channels: Mutex::new(HashMap::new()),
        tasks: Mutex::new(Vec::new()),
        managed_channel_limit,
        identity,
        scan_request: Mutex::new(ScanState::new(&library)),
        scan_response: Mutex::new(ScanState::new(&library)),
        library,
        termination: termination.clone(),
        request_hits: AtomicU64::new(0),
        response_hits: AtomicU64::new(0),
    });
    // run_stream spawns only after reading the guest identification and has no
    // await after spawn. A failed/timed-out identification owns no hidden task.
    let setup = russh::server::run_stream(
        server_config,
        CancellableIo::new(guest, termination.clone()),
        GuestServer {
            shared: Arc::clone(&shared),
            pending_upstream: Some(upstream),
            authority,
        },
    );
    let mut session =
        match tokio::time::timeout(Duration::from_secs(UPSTREAM_AUTH_TIMEOUT_SECS), setup).await {
            Ok(Ok(session)) => session,
            result => {
                let message = match result {
                    Ok(Err(error)) => format!("guest handshake: {error}"),
                    _ => "guest identification timed out".to_string(),
                };
                return RelayCompletion {
                    result: Err(BrokerError::Ssh(message)),
                    retired: true,
                };
            }
        };

    // The guest session and per-session termination race: whichever wins
    // tears down this session's relay tasks and upstream leg. Other
    // sessions and the global vsock accept loop are unaffected.
    let (result, guest_joined) = tokio::select! {
        result = &mut session => (result.map_err(|e| BrokerError::Ssh(format!("guest session failed: {e}"))), true),
        _ = termination.terminated() => {
            let joined = tokio::time::timeout(Duration::from_secs(RETIREMENT_TIMEOUT_SECS), &mut session).await.is_ok();
            (Err(BrokerError::Ssh("SSH relay cancelled".into())), joined)
        }
    };
    termination.terminate();
    let pumps_joined = shared.join_pumps().await;
    let upstream_joined = shared.join_upstream().await;
    RelayCompletion {
        result,
        retired: guest_joined
            && pumps_joined
            && upstream_joined
            && !shared.retirement_incomplete.load(Ordering::SeqCst),
    }
}

/// Establish the independent upstream SSH session after guest proof succeeds.
async fn authenticate_upstream<U>(
    upstream: U,
    key: Arc<PrivateKey>,
    pin: &UpstreamPin,
    shared: &RelayShared,
) -> BrokerResult<()>
where
    U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let verifier = UpstreamVerifier {
        expected: pin.expected.clone(),
    };
    let client = russh::client::connect_stream(
        Arc::new(russh::client::Config::default()),
        CancellableIo::new(upstream, shared.termination.clone()),
        verifier,
    )
    .await
    .map_err(|e| BrokerError::Ssh(format!("upstream handshake: {e}")))?;
    // Publish the native task owner before any subsequent fallible auth step.
    // Even auth refusal/error must join this handle during relay cleanup.
    let mut owner = shared.upstream.lock().await;
    *owner = Some(client);
    let client = owner
        .as_mut()
        .expect("native upstream handle was just installed");
    let hash = client
        .best_supported_rsa_hash()
        .await
        .map_err(|e| BrokerError::Ssh(format!("upstream signature algorithms: {e}")))?
        .flatten();
    let auth = client
        .authenticate_publickey(pin.user.clone(), PrivateKeyWithHashAlg::new(key, hash))
        .await
        .map_err(|e| BrokerError::Ssh(format!("upstream public-key authentication: {e}")))?;
    if !auth.success() {
        return Err(BrokerError::Ssh(
            "upstream public-key authentication failed".to_string(),
        ));
    }
    Ok(())
}

/// Build the guest-facing SSH server configuration.
///
/// The host key is ephemeral per boot: generated in-guest at startup and
/// never persisted. Guests therefore see an unknown host key on every
/// broker boot; that is inherent to a broker that owns no stable identity.
pub fn build_server_config() -> BrokerResult<Arc<russh::server::Config>> {
    let mut rng = russh::keys::key::safe_rng();
    let host_key = russh::keys::PrivateKey::random(&mut rng, Algorithm::Ed25519)
        .map_err(|e| BrokerError::Ssh(format!("generate broker host key: {e}")))?;
    Ok(Arc::new(russh::server::Config {
        auth_rejection_time: Duration::from_secs(3),
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        keys: vec![host_key],
        ..Default::default()
    }))
}

/// Parse one bootstrap upstream entry into a dialable pin.
pub fn parse_upstream_pin(entry: &BrokerUpstreamHost) -> BrokerResult<UpstreamPin> {
    // Accept a full `authorized_keys` line; tolerate a trailing comment by
    // parsing the leading algorithm and base64 fields.
    let mut parts = entry.public_key.split_whitespace();
    let (Some(algorithm), Some(base64)) = (parts.next(), parts.next()) else {
        return Err(BrokerError::Ssh(format!(
            "upstream pin for {}:{} is not an authorized_keys line",
            entry.host, entry.port
        )));
    };
    let expected: PublicKey = format!("{algorithm} {base64}").parse().map_err(|e| {
        BrokerError::Ssh(format!(
            "upstream pin for {}:{} does not parse: {e}",
            entry.host, entry.port
        ))
    })?;
    if entry.user.is_empty() {
        return Err(BrokerError::Ssh(format!(
            "upstream pin for {}:{} names no login user",
            entry.host, entry.port
        )));
    }
    Ok(UpstreamPin {
        user: entry.user.clone(),
        expected,
    })
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Close a response-enforced channel on the guest leg.
///
/// Best-effort like the request-leg close: either leg may already be
/// closing when enforcement fires. A terminate decision tears down the
/// whole session first; a block only closes the offending channel.
async fn close_response_channel(
    guest: &russh::server::Handle,
    shared: &RelayShared,
    channel: ChannelId,
    decision: ScanEnforcement,
) {
    if decision == ScanEnforcement::TerminateSession {
        shared.termination.terminate();
    }
    let _ = guest.close(channel).await;
    shared.channels.lock().await.remove(&channel);
}

/// Answer a guest channel request from an upstream reply.
fn answer(session: &mut Session, channel: ChannelId, ok: bool) -> Result<(), BrokerError> {
    if ok {
        session
            .channel_success(channel)
            .map_err(|e| BrokerError::Ssh(format!("answer guest channel: {e}")))?;
    } else {
        session
            .channel_failure(channel)
            .map_err(|e| BrokerError::Ssh(format!("answer guest channel: {e}")))?;
    }
    Ok(())
}

/// Pump one upstream channel into its guest channel until either side ends.
///
/// Upstream-to-guest bytes are audit/count-only by default: hits are
/// observed for attribution and the bytes forward unless
/// [`UPSTREAM_RESPONSE_ENFORCEMENT`] routes the report's decision into
/// enforcement.
async fn pump_upstream_to_guest(
    guest: russh::server::Handle,
    guest_channel: ChannelId,
    mut rx: russh::ChannelReadHalf,
    state: Arc<UpstreamChannel>,
    shared: Arc<RelayShared>,
) {
    loop {
        match rx.wait().await {
            Some(ChannelMsg::Data { data }) => {
                let report = shared.scan_response.lock().await.scan_chunk(&data);
                // Count and audit every response report; the relay decision
                // stays behind the response-enforcement switch, so the
                // observed decision is dropped and resolved below.
                let _ = shared
                    .observe(
                        guest_channel,
                        ChannelDirection::UpstreamToGuest,
                        &report,
                        &shared.response_hits,
                    )
                    .await;
                match response_enforcement_for(&report) {
                    ScanEnforcement::Forward => {
                        if guest.data(guest_channel, data).await.is_err() {
                            break;
                        }
                    }
                    decision => {
                        close_response_channel(&guest, &shared, guest_channel, decision).await;
                        break;
                    }
                }
            }
            Some(ChannelMsg::ExtendedData { data, ext }) => {
                let report = shared.scan_response.lock().await.scan_chunk(&data);
                // Count and audit every response report; the relay decision
                // stays behind the response-enforcement switch, so the
                // observed decision is dropped and resolved below.
                let _ = shared
                    .observe(
                        guest_channel,
                        ChannelDirection::UpstreamToGuest,
                        &report,
                        &shared.response_hits,
                    )
                    .await;
                match response_enforcement_for(&report) {
                    ScanEnforcement::Forward => {
                        if guest.extended_data(guest_channel, ext, data).await.is_err() {
                            break;
                        }
                    }
                    decision => {
                        close_response_channel(&guest, &shared, guest_channel, decision).await;
                        break;
                    }
                }
            }
            Some(ChannelMsg::Eof) => {
                let _ = guest.eof(guest_channel).await;
            }
            Some(ChannelMsg::ExitStatus { exit_status }) => {
                let _ = guest.exit_status_request(guest_channel, exit_status).await;
            }
            Some(ChannelMsg::ExitSignal {
                signal_name,
                core_dumped,
                error_message,
                lang_tag,
            }) => {
                let _ = guest
                    .exit_signal_request(
                        guest_channel,
                        signal_name,
                        core_dumped,
                        error_message,
                        lang_tag,
                    )
                    .await;
            }
            Some(ChannelMsg::Success) => {
                complete_pending(&state).await;
            }
            Some(ChannelMsg::Failure) => {
                fail_pending(&state).await;
            }
            Some(ChannelMsg::Close) | None => {
                let _ = guest.close(guest_channel).await;
                shared.channels.lock().await.remove(&guest_channel);
                break;
            }
            Some(_) => {}
        }
    }
}

/// Complete the oldest pending upstream request as successful.
async fn complete_pending(state: &UpstreamChannel) {
    if let Some(reply) = state.pending.lock().await.take() {
        let _ = reply.send(true);
    }
}

/// Complete the oldest pending upstream request as failed.
async fn fail_pending(state: &UpstreamChannel) {
    if let Some(reply) = state.pending.lock().await.take() {
        let _ = reply.send(false);
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use microsandbox_scan::ActionSet;

    /// A scan report reduced to one enforcement level.
    fn report_with(enforce: Option<Severity>) -> ScanReport {
        ScanReport {
            hits: Vec::new(),
            strictest_action: enforce.map(|enforce| ActionSet {
                enforce: Some(enforce),
                audit: true,
                count: true,
            }),
        }
    }

    /// A pin entry with a real (fixed test-only) Ed25519 key.
    fn pin_entry() -> BrokerUpstreamHost {
        use crate::keys::BrokerKey;
        use microsandbox_protocol::bootstrap::{BROKER_KEY_TYPE_ED25519, BrokerSshKey};

        let key = BrokerKey::from_bootstrap(BrokerSshKey {
            key_type: BROKER_KEY_TYPE_ED25519.to_string(),
            key_bytes: vec![0x42; 32],
        })
        .unwrap();
        BrokerUpstreamHost {
            host: "example.com".to_string(),
            port: 22,
            user: "deploy".to_string(),
            public_key: format!("{} broker-test-only", key.public_key_openssh()),
        }
    }

    #[test]
    fn upstream_username_match_is_exact_and_nonempty() {
        let mut pin = parse_upstream_pin(&pin_entry()).unwrap();
        assert!(pin.matches_user("deploy"));
        for requested in ["", "Deploy", "DEPLOY", "deploy ", " deploy", "root"] {
            assert!(!pin.matches_user(requested), "must refuse {requested:?}");
        }
        pin.user.clear();
        assert!(!pin.matches_user(""));
    }

    #[test]
    fn upstream_pin_parses_authorized_keys_lines() {
        use crate::keys::BrokerKey;
        use microsandbox_protocol::bootstrap::{BROKER_KEY_TYPE_ED25519, BrokerSshKey};

        // Fixed test-only seed: derive a real pin from custody so the
        // base64 is genuinely parseable.
        let key = BrokerKey::from_bootstrap(BrokerSshKey {
            key_type: BROKER_KEY_TYPE_ED25519.to_string(),
            key_bytes: vec![0x42; 32],
        })
        .unwrap();
        let mut entry = pin_entry();
        entry.public_key = format!("{} broker-test-only", key.public_key_openssh());
        // A well-formed Ed25519 pin parses; the trailing comment is ignored.
        let pin = parse_upstream_pin(&entry).unwrap();
        assert_eq!(pin.user(), "deploy");
        assert_eq!(pin.expected.algorithm(), Algorithm::Ed25519);
        assert_eq!(
            pin.expected.public_key_base64(),
            key.public_key_openssh().split_whitespace().nth(1).unwrap()
        );
    }

    #[test]
    fn upstream_pin_rejects_garbage_and_empty_users() {
        let mut entry = pin_entry();
        entry.public_key = "not-a-key".to_string();
        assert!(parse_upstream_pin(&entry).is_err());

        let mut entry = pin_entry();
        entry.public_key = "ssh-ed25519 not-base64!!".to_string();
        assert!(parse_upstream_pin(&entry).is_err());

        let mut entry = pin_entry();
        entry.user = String::new();
        assert!(parse_upstream_pin(&entry).is_err());
    }

    #[test]
    fn server_config_builds_with_ephemeral_host_key() {
        let first = build_server_config().unwrap();
        let second = build_server_config().unwrap();
        assert_eq!(first.keys.len(), 1);
        assert_eq!(second.keys.len(), 1);
        assert_ne!(
            first.keys[0].public_key().public_key_base64(),
            second.keys[0].public_key().public_key_base64(),
            "each boot must mint a fresh host key"
        );
    }

    #[test]
    fn enforcement_forwards_hits_without_enforcement() {
        assert_eq!(
            enforcement_for(&report_with(None)),
            ScanEnforcement::Forward
        );
        assert_eq!(
            enforcement_for(&ScanReport {
                hits: Vec::new(),
                strictest_action: None,
            }),
            ScanEnforcement::Forward
        );
    }

    #[test]
    fn enforcement_closes_the_channel_on_block() {
        assert_eq!(
            enforcement_for(&report_with(Some(Severity::BlockAndLog))),
            ScanEnforcement::CloseChannel
        );
        assert_eq!(
            enforcement_for(&report_with(Some(Severity::Block))),
            ScanEnforcement::CloseChannel
        );
    }

    #[test]
    fn enforcement_terminates_the_session_on_block_and_terminate() {
        assert_eq!(
            enforcement_for(&report_with(Some(Severity::BlockAndTerminate))),
            ScanEnforcement::TerminateSession
        );
    }

    #[test]
    fn response_leg_stays_audit_only_by_default() {
        // Compile-time pin: the response leg stays audit-only until
        // response-side enforcement is explicitly adopted.
        const { assert!(!UPSTREAM_RESPONSE_ENFORCEMENT) };
        // Under the default switch a block report still forwards on the
        // response leg, while the shared mapping shows what enabling the
        // switch would enforce — no SSH needed either way.
        for severity in [
            Severity::BlockAndLog,
            Severity::Block,
            Severity::BlockAndTerminate,
        ] {
            let report = report_with(Some(severity));
            assert_eq!(response_enforcement_for(&report), ScanEnforcement::Forward);
            assert_ne!(enforcement_for(&report), ScanEnforcement::Forward);
        }
        assert_eq!(
            response_enforcement_for(&report_with(None)),
            ScanEnforcement::Forward
        );
    }

    #[test]
    fn termination_handle_starts_untriggered() {
        assert!(!TerminationHandle::new().is_terminated());
        assert!(!TerminationHandle::default().is_terminated());
    }

    #[test]
    fn termination_marks_the_handle() {
        let handle = TerminationHandle::new();
        handle.terminate();
        assert!(handle.is_terminated());
        // Terminating twice stays terminated.
        handle.terminate();
        assert!(handle.is_terminated());
    }

    #[test]
    fn termination_is_shared_across_clones() {
        let handle = TerminationHandle::new();
        let relay = handle.clone();
        relay.terminate();
        assert!(handle.is_terminated());
        assert!(relay.is_terminated());
    }

    #[tokio::test]
    async fn terminated_resolves_once_triggered() {
        let handle = TerminationHandle::new();
        let waiter = handle.clone();
        let done = tokio::spawn(async move { waiter.terminated().await });
        handle.terminate();
        tokio::time::timeout(Duration::from_secs(5), done)
            .await
            .expect("termination wait must resolve")
            .unwrap();
        // Late waiters observe termination without blocking.
        tokio::time::timeout(Duration::from_secs(5), handle.terminated())
            .await
            .expect("late termination wait must resolve immediately");
    }

    #[tokio::test]
    async fn termination_wakes_every_registered_waiter_and_racing_first_poll() {
        use std::future::{Future, poll_fn};
        use std::task::Poll;
        for _ in 0..64 {
            let handle = TerminationHandle::new();
            let mut first = Box::pin(handle.terminated());
            let mut second = Box::pin(handle.terminated());
            poll_fn(|cx| {
                assert!(first.as_mut().poll(cx).is_pending());
                assert!(second.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            handle.terminate();
            tokio::time::timeout(Duration::from_secs(1), async {
                tokio::join!(first, second);
            })
            .await
            .unwrap();
            // Cancellation before registration must resolve on its first poll.
            let mut late = Box::pin(handle.terminated());
            poll_fn(|cx| {
                assert!(late.as_mut().poll(cx).is_ready());
                Poll::Ready(())
            })
            .await;
        }
    }

    #[tokio::test]
    async fn termination_between_registration_and_flag_check_cannot_be_lost() {
        let handle = TerminationHandle::new();
        tokio::time::timeout(
            Duration::from_secs(1),
            handle.terminated_registered(|| handle.terminate()),
        )
        .await
        .expect("notification in the former check/register window must complete");

        // Model the old ordering with an actual Notify: its prior false flag
        // observation followed by notify_waiters loses the notification when
        // the waiter has not yet registered. This negative fixes the schedule.
        let old = TerminationHandle::new();
        let stale_flag = old.is_terminated();
        old.terminate();
        let old_order = async {
            if !stale_flag {
                old.notify.notified().await;
            }
        };
        assert!(
            tokio::time::timeout(Duration::from_millis(1), old_order)
                .await
                .is_err()
        );
    }
}
