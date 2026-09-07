//! SSH termination toward the guest and reorigination toward upstream.
//!
//! brokerd acts as SSH server toward the guest (terminating the diverted
//! guest client session) and SSH client toward upstream (authenticating
//! with the sealed Ed25519 key). After both sessions establish, channels
//! relay guest↔upstream: session channels (shell, exec, pty, env, signal,
//! window-change) proxy transparently, while `direct-tcpip` and subsystem
//! (SFTP) requests are refused as out of scope for this broker.
//!
//! Guest authentication accepts any public key: authorization already
//! happened at the host divert decision, and the broker holds no guest
//! credential store to check against. The security boundary is the
//! upstream leg — sealed-key authentication plus strict pinned host-key
//! verification with no fallback to unverified.
//!
//! Upstream password or keyboard-interactive authentication has no path
//! through the broker (there is no password custody), so only upstream
//! public-key authentication is attempted.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use russh::keys::{Algorithm, PrivateKeyWithHashAlg, PublicKey, PublicKeyBase64};
use russh::server::{Auth, ChannelOpenHandle, Session};
use russh::{ChannelId, ChannelMsg, Sig};
use tokio::sync::{Mutex, oneshot};

use microsandbox_protocol::bootstrap::BrokerUpstreamHost;

use crate::error::{BrokerError, BrokerResult};
use crate::keys::BrokerKey;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Time allowed for one upstream channel-request reply.
const REPLY_TIMEOUT_SECS: u64 = 30;

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
    /// Authenticated upstream client connection.
    upstream: russh::client::Handle<UpstreamVerifier>,

    /// Upstream write halves keyed by guest channel id.
    channels: Mutex<HashMap<ChannelId, Arc<UpstreamChannel>>>,

    /// In-flight relay tasks, aborted when the guest session ends.
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

/// One relayed channel: the upstream write half plus its pending reply.
struct UpstreamChannel {
    /// Upstream write half for guest→upstream forwarding.
    tx: Mutex<russh::ChannelWriteHalf<russh::client::Msg>>,

    /// Completer for the oldest request awaiting an upstream reply.
    pending: Mutex<Option<oneshot::Sender<bool>>>,
}

/// Guest-facing SSH server handler: one per diverted connection.
struct GuestServer {
    /// Shared relay state for this diverted connection.
    shared: Arc<RelayShared>,
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
}

impl GuestServer {
    /// Run `f` against the upstream channel for `channel`, if still present.
    ///
    /// A channel that already closed resolves to `false` so the guest gets
    /// a clean failure instead of a stalled request.
    async fn with_channel<F, Fut>(&self, channel: ChannelId, f: F) -> bool
    where
        F: FnOnce(Arc<UpstreamChannel>) -> Fut,
        Fut: Future<Output = bool>,
    {
        let Some(state) = self.shared.channels.lock().await.get(&channel).cloned() else {
            return false;
        };
        f(state).await
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

impl russh::server::Handler for GuestServer {
    type Error = BrokerError;

    async fn auth_publickey_offered(
        &mut self,
        _user: &str,
        _public_key: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        // Authorization happened at the host divert decision; the broker
        // holds no guest credential store, so every offered key proceeds
        // to the proof-of-possession check, which is then accepted.
        Ok(Auth::Accept)
    }

    async fn auth_publickey(
        &mut self,
        _user: &str,
        _public_key: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: russh::Channel<russh::server::Msg>,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let guest_id = channel.id();
        let upstream = match self.shared.upstream.channel_open_session().await {
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
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(state) = self.shared.channels.lock().await.get(&channel).cloned() {
            let tx = state.tx.lock().await;
            let _ = tx.data_bytes(data.to_vec()).await;
        }
        Ok(())
    }

    async fn extended_data(
        &mut self,
        channel: ChannelId,
        code: u32,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(state) = self.shared.channels.lock().await.get(&channel).cloned() {
            let tx = state.tx.lock().await;
            let _ = tx.extended_data_bytes(code, data.to_vec()).await;
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

/// Reoriginate one diverted guest session toward its pinned upstream.
///
/// `guest` is the accepted divert stream (starting with the guest's first
/// flight); `upstream` is the egress-tunneled stream to the pinned
/// destination. brokerd runs the SSH server side on `guest` and the SSH
/// client side on `upstream`, relaying channels until the guest session
/// ends.
///
/// Double-banner fingerprint, stated as a technical fact: the guest
/// already saw the direct upstream banner (relayed pre-divert by the host
/// proxy while it buffered the first flight) and now sees a second banner
/// from this reoriginated handshake. The two banners frame the divert.
pub async fn reoriginate<G, U>(
    guest: G,
    upstream: U,
    key: &BrokerKey,
    pin: &UpstreamPin,
    server_config: Arc<russh::server::Config>,
) -> BrokerResult<()>
where
    G: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let verifier = UpstreamVerifier {
        expected: pin.expected.clone(),
    };
    let mut client = russh::client::connect_stream(
        Arc::new(russh::client::Config::default()),
        upstream,
        verifier,
    )
    .await
    .map_err(|e| BrokerError::Ssh(format!("upstream handshake: {e}")))?;
    let hash = client
        .best_supported_rsa_hash()
        .await
        .map_err(|e| BrokerError::Ssh(format!("upstream signature algorithms: {e}")))?
        .flatten();
    let auth = client
        .authenticate_publickey(
            pin.user.clone(),
            PrivateKeyWithHashAlg::new(Arc::new(key.private_key().clone()), hash),
        )
        .await
        .map_err(|e| BrokerError::Ssh(format!("upstream public-key authentication: {e}")))?;
    if !auth.success() {
        let _ = client
            .disconnect(russh::Disconnect::ByApplication, "", "")
            .await;
        return Err(BrokerError::Ssh(
            "upstream public-key authentication failed".to_string(),
        ));
    }

    let shared = Arc::new(RelayShared {
        upstream: client,
        channels: Mutex::new(HashMap::new()),
        tasks: Mutex::new(Vec::new()),
    });
    let session = russh::server::run_stream(
        server_config,
        guest,
        GuestServer {
            shared: Arc::clone(&shared),
        },
    )
    .await
    .map_err(|e| BrokerError::Ssh(format!("guest handshake: {e}")))?;
    session
        .await
        .map_err(|e| BrokerError::Ssh(format!("guest session failed: {e}")))?;

    for task in shared.tasks.lock().await.drain(..) {
        task.abort();
    }
    let _ = shared
        .upstream
        .disconnect(russh::Disconnect::ByApplication, "", "")
        .await;
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
                if guest.data(guest_channel, data).await.is_err() {
                    break;
                }
            }
            Some(ChannelMsg::ExtendedData { data, ext }) => {
                if guest.extended_data(guest_channel, ext, data).await.is_err() {
                    break;
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
}
