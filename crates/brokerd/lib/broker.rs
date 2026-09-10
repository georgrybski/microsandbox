//! Broker runtime: console epoch serving and divert session handling.
//!
//! The broker loop drives two inputs concurrently: the agent console
//! (epoch provisions, liveness, shutdown) and the divert vsock listener
//! (accepted host-diverted guest streams). Each accepted stream is read
//! for one prelude, validated against the console-bound epoch state, and
//! — only on success — tunneled through the egress port into a fresh SSH
//! reorigination.

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Duration;

use microsandbox_protocol::codec;
use microsandbox_protocol::core::{Ping, Pong};
use microsandbox_protocol::message::{Message, MessageType};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;
use tokio::time::timeout;

use crate::config::{BrokerConfig, MAX_PRELUDE_BYTES, PRELUDE_READ_TIMEOUT_SECS};
use crate::console::BootConsole;
use crate::egress::open_egress_tunnel;
use crate::epoch::{EpochState, apply_provision};
use crate::error::{BrokerError, BrokerResult};
use crate::keys::BrokerKey;
use crate::prelude::read_ssh_divert_prelude;
use crate::ssh::{build_server_config, parse_upstream_pin, reoriginate};
use crate::vsock::{VsockListener, VsockStream};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Serial read chunk size for the console loop.
const CONSOLE_READ_BUF_SIZE: usize = 64 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Shared broker runtime state.
pub struct Broker {
    /// Vsock ports and upstream pins.
    config: BrokerConfig,

    /// Sealed upstream authentication key.
    custody: Arc<BrokerKey>,

    /// Console-bound epoch state.
    epoch: Mutex<Option<EpochState>>,

    /// Guest-facing SSH server configuration (ephemeral host key).
    server_config: Arc<russh::server::Config>,
}

/// Outcome of handling one console frame.
#[derive(Debug, PartialEq, Eq)]
enum ConsoleOutcome {
    /// Frame handled; replies (if any) are queued in the output buffer.
    Handled,

    /// The host requested shutdown.
    Shutdown,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Broker {
    /// Build the broker runtime from its configuration and sealed key.
    ///
    /// Mints the ephemeral guest-facing SSH host key.
    pub fn new(config: BrokerConfig, key: BrokerKey) -> BrokerResult<Arc<Self>> {
        let server_config = build_server_config()?;
        Ok(Arc::new(Self {
            config,
            custody: Arc::new(key),
            epoch: Mutex::new(None),
            server_config,
        }))
    }

    /// Run the broker loop until shutdown or a fatal console error.
    pub async fn run(self: &Arc<Self>, port_file: File, console: BootConsole) -> BrokerResult<()> {
        let listener = VsockListener::bind(self.config.divert_port).map_err(|e| {
            BrokerError::Console(format!("bind divert port {}: {e}", self.config.divert_port))
        })?;
        eprintln!(
            "brokerd: listening for diverts on vsock port {}",
            self.config.divert_port
        );

        let async_port = AsyncFd::new(port_file)?;
        let mut serial_in_buf = console.input;
        let mut serial_out_buf = Vec::new();
        let mut read_buf = vec![0u8; CONSOLE_READ_BUF_SIZE];

        loop {
            tokio::select! {
                accept = listener.accept() => {
                    match accept {
                        Ok(stream) => {
                            let broker = Arc::clone(self);
                            tokio::spawn(async move {
                                broker.serve_connection(stream).await;
                            });
                        }
                        Err(e) => {
                            eprintln!("brokerd: divert accept failed: {e}");
                        }
                    }
                }
                readable = async_port.readable() => {
                    let mut guard = readable.map_err(|e| {
                        BrokerError::Console(format!("console readiness: {e}"))
                    })?;
                    loop {
                        match guard.try_io(|inner| {
                            read_from_fd(inner.get_ref().as_raw_fd(), &mut read_buf)
                        }) {
                            Ok(Ok(0)) => {
                                return Err(BrokerError::Console(
                                    "agent console closed".to_string(),
                                ));
                            }
                            Ok(Ok(n)) => {
                                serial_in_buf.extend_from_slice(&read_buf[..n]);
                                if serial_in_buf.len() > codec::MAX_FRAME_SIZE as usize + 4 {
                                    return Err(BrokerError::Console(
                                        "console input buffer exceeded maximum size".to_string(),
                                    ));
                                }
                            }
                            Ok(Err(e)) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                            Ok(Err(e)) => return Err(BrokerError::Console(e.to_string())),
                            Err(_would_block) => break,
                        }
                    }
                    drop(guard);
                    while let Some(frame) =
                        codec::try_decode_raw_from_buf(&mut serial_in_buf).map_err(|e| {
                            BrokerError::Console(format!("decode console frame: {e}"))
                        })?
                    {
                        let msg = codec::raw_frame_to_message(frame).map_err(|e| {
                            BrokerError::Console(format!("decode console message: {e}"))
                        })?;
                        match handle_console_message(msg, &mut *self.epoch.lock().await, &mut serial_out_buf)? {
                            ConsoleOutcome::Handled => {}
                            ConsoleOutcome::Shutdown => {
                                request_guest_poweroff()?;
                                return Ok(());
                            }
                        }
                    }
                    if !serial_out_buf.is_empty() {
                        flush_write_buf(&async_port, &mut serial_out_buf).await?;
                    }
                }
            }
        }
    }

    /// Serve one accepted divert stream through validation to reorigination.
    ///
    /// Every refusal is fail-closed with a log line: the stream is dropped
    /// without relaying a byte.
    async fn serve_connection(&self, mut stream: VsockStream) {
        let prelude = match timeout(
            Duration::from_secs(PRELUDE_READ_TIMEOUT_SECS),
            read_ssh_divert_prelude(&mut stream, MAX_PRELUDE_BYTES),
        )
        .await
        {
            Ok(Ok(prelude)) => prelude,
            Ok(Err(e)) => {
                eprintln!("brokerd: divert prelude unreadable: {e}");
                return;
            }
            Err(_) => {
                eprintln!("brokerd: divert prelude timed out");
                return;
            }
        };
        let epoch = self.epoch.lock().await;
        if let Err(reject) = prelude.validate_against(epoch.as_ref()) {
            eprintln!(
                "brokerd: divert to {}:{} refused: {reject}",
                prelude.dest_host, prelude.dest_port
            );
            return;
        }
        drop(epoch);
        let Some(entry) = self.config.pin_for(&prelude.dest_host, prelude.dest_port) else {
            eprintln!(
                "brokerd: divert to {}:{} refused: no upstream pin",
                prelude.dest_host, prelude.dest_port
            );
            return;
        };
        let pin = match parse_upstream_pin(entry) {
            Ok(pin) => pin,
            Err(e) => {
                eprintln!("brokerd: divert to {} refused: {e}", prelude.dest_host);
                return;
            }
        };
        let egress_port = self.config.egress_port;
        let destination = (prelude.dest_host.clone(), prelude.dest_port);
        // Keep the entire dial lazy: endpoint admission is not authorization
        // for the guest's requested SSH principal.
        let egress = async move {
            let mut stream = VsockStream::connect(egress_port).await?;
            open_egress_tunnel(&mut stream, &destination.0, destination.1).await?;
            Ok(stream)
        };
        eprintln!(
            "brokerd: reoriginating divert to {}:{} (cid {})",
            prelude.dest_host, prelude.dest_port, prelude.transport_cid
        );
        let identity = prelude.session_identity();
        if let Err(e) = reoriginate(
            stream,
            egress,
            &self.custody,
            &pin,
            Arc::clone(&self.server_config),
            identity,
            Arc::clone(&self.config.patterns),
        )
        .await
        {
            eprintln!(
                "brokerd: reorigination for {}:{} ended: {e}",
                prelude.dest_host, prelude.dest_port
            );
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Handle one console message, queueing replies into `out`.
///
/// Only epoch provisions, liveness, and shutdown are served: brokerd
/// implements no exec, filesystem, or TCP handlers by design.
fn handle_console_message(
    msg: Message,
    epoch: &mut Option<EpochState>,
    out: &mut Vec<u8>,
) -> BrokerResult<ConsoleOutcome> {
    if msg.flags != msg.t.flags() {
        eprintln!(
            "brokerd: ignoring {} with invalid flags {}",
            msg.t.as_str(),
            msg.flags
        );
        return Ok(ConsoleOutcome::Handled);
    }
    match msg.t {
        MessageType::SshEpochProvision => {
            match msg.payload::<microsandbox_protocol::core::SshEpochProvision>() {
                Ok(provision) => {
                    let ack = match apply_provision(epoch, &provision) {
                        Ok(ack) => ack,
                        Err(e) => {
                            eprintln!("brokerd: epoch provision refused: {e}");
                            microsandbox_protocol::core::SshEpochAck {
                                cid: provision.cid,
                                epoch: provision.epoch,
                                ok: false,
                            }
                        }
                    };
                    if ack.ok {
                        eprintln!(
                            "brokerd: bound epoch {} to cid {}",
                            provision.epoch, provision.cid
                        );
                    }
                    let reply = Message::with_payload(MessageType::SshEpochAck, msg.id, &ack)
                        .map_err(|e| BrokerError::Console(format!("encode epoch ack: {e}")))?;
                    codec::encode_to_buf(&reply, out)
                        .map_err(|e| BrokerError::Console(format!("frame epoch ack: {e}")))?;
                }
                Err(e) => {
                    eprintln!("brokerd: ignoring malformed epoch provision: {e}");
                }
            }
            Ok(ConsoleOutcome::Handled)
        }
        MessageType::Ping => {
            match msg.payload::<Ping>() {
                Ok(_) => {
                    let reply = Message::with_payload(MessageType::Pong, msg.id, &Pong {})
                        .map_err(|e| BrokerError::Console(format!("encode pong: {e}")))?;
                    codec::encode_to_buf(&reply, out)
                        .map_err(|e| BrokerError::Console(format!("frame pong: {e}")))?;
                }
                Err(e) => {
                    eprintln!("brokerd: ignoring malformed ping: {e}");
                }
            }
            Ok(ConsoleOutcome::Handled)
        }
        MessageType::Shutdown => Ok(ConsoleOutcome::Shutdown),
        _ => {
            eprintln!(
                "brokerd: ignoring unsupported console message {}",
                msg.t.as_str()
            );
            Ok(ConsoleOutcome::Handled)
        }
    }
}

/// Copy bytes bidirectionally between two streams until either side ends.
///
/// Used by the framing integration test to prove the shim↔brokerd byte
/// path; production divert sessions relay through the SSH layer instead.
pub async fn relay_bytes<A, B>(a: &mut A, b: &mut B) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    tokio::io::copy_bidirectional(a, b).await
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

fn read_from_fd(fd: i32, buf: &mut [u8]) -> std::io::Result<usize> {
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

fn write_to_fd(fd: i32, buf: &[u8]) -> std::io::Result<usize> {
    let n = unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

async fn flush_write_buf(fd: &AsyncFd<File>, buf: &mut Vec<u8>) -> BrokerResult<()> {
    while !buf.is_empty() {
        let mut guard = fd
            .writable()
            .await
            .map_err(|e| BrokerError::Console(format!("console writability: {e}")))?;
        match guard.try_io(|inner| write_to_fd(inner.get_ref().as_raw_fd(), buf)) {
            Ok(Ok(n)) => {
                buf.drain(..n);
            }
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Ok(Err(e)) => return Err(BrokerError::Console(e.to_string())),
            Err(_would_block) => continue,
        }
    }
    Ok(())
}

fn request_guest_poweroff() -> BrokerResult<()> {
    unsafe {
        libc::sync();
    }
    let ret = unsafe { libc::reboot(libc::RB_POWER_OFF) };
    if ret != 0 {
        return Err(BrokerError::Console(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use microsandbox_protocol::core::SshEpochProvision;

    fn provision(epoch: u64) -> Message {
        Message::with_payload(
            MessageType::SshEpochProvision,
            11,
            &SshEpochProvision {
                instance: "sandbox-1".to_string(),
                cid: 7,
                epoch,
                issued_at: 1_700_000_000,
                not_before: 1_700_000_000,
            },
        )
        .unwrap()
    }

    fn decode_ack(out: &[u8]) -> microsandbox_protocol::core::SshEpochAck {
        let mut buf = out.to_vec();
        let msg = codec::try_decode_from_buf(&mut buf).unwrap().unwrap();
        assert_eq!(msg.t, MessageType::SshEpochAck);
        assert_eq!(msg.id, 11);
        msg.payload().unwrap()
    }

    #[test]
    fn console_provision_binds_and_acks() {
        let mut epoch = None;
        let mut out = Vec::new();
        let outcome = handle_console_message(provision(1), &mut epoch, &mut out).unwrap();
        assert_eq!(outcome, ConsoleOutcome::Handled);
        assert!(decode_ack(&out).ok);
        assert_eq!(epoch.as_ref().unwrap().epoch, 1);
    }

    #[test]
    fn console_stale_provision_nacks_without_unbinding() {
        let mut epoch = None;
        let mut out = Vec::new();
        handle_console_message(provision(4), &mut epoch, &mut out).unwrap();
        out.clear();
        handle_console_message(provision(2), &mut epoch, &mut out).unwrap();
        assert!(!decode_ack(&out).ok);
        assert_eq!(epoch.as_ref().unwrap().epoch, 4);
    }

    #[test]
    fn console_ping_gets_pong_with_same_id() {
        let mut epoch = None;
        let mut out = Vec::new();
        let ping = Message::with_payload(MessageType::Ping, 9, &Ping {}).unwrap();
        let outcome = handle_console_message(ping, &mut epoch, &mut out).unwrap();
        assert_eq!(outcome, ConsoleOutcome::Handled);
        let mut buf = out;
        let msg = codec::try_decode_from_buf(&mut buf).unwrap().unwrap();
        assert_eq!(msg.t, MessageType::Pong);
        assert_eq!(msg.id, 9);
        let _: Pong = msg.payload().unwrap();
    }

    #[test]
    fn console_shutdown_requests_poweroff() {
        let mut epoch = None;
        let mut out = Vec::new();
        let shutdown = Message::new(MessageType::Shutdown, 0, Vec::new());
        let outcome = handle_console_message(shutdown, &mut epoch, &mut out).unwrap();
        assert_eq!(outcome, ConsoleOutcome::Shutdown);
    }

    #[test]
    fn console_ignores_foreign_message_types() {
        let mut epoch = None;
        let mut out = Vec::new();
        let exec = Message::new(MessageType::ExecRequest, 3, Vec::new());
        let outcome = handle_console_message(exec, &mut epoch, &mut out).unwrap();
        assert_eq!(outcome, ConsoleOutcome::Handled);
        assert!(out.is_empty(), "no reply for ignored types");
    }

    #[tokio::test]
    async fn relay_bytes_pumps_both_directions() {
        let (mut a1, mut a2) = tokio::net::UnixStream::pair().unwrap();
        let (mut b1, mut b2) = tokio::net::UnixStream::pair().unwrap();
        let pump = tokio::spawn(async move { relay_bytes(&mut a2, &mut b2).await.unwrap() });
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        a1.write_all(b"guest-hello").await.unwrap();
        let mut buf = [0u8; 11];
        b1.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"guest-hello");
        b1.write_all(b"upstream-hi").await.unwrap();
        let mut back = [0u8; 11];
        a1.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"upstream-hi");
        drop(a1);
        drop(b1);
        let _ = pump.await;
    }
}
