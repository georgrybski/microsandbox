//! Bounded per-exec I/O. A blocked child never owns the agent control loop.

use super::{RawActivity, RawSessionOutput, SessionOutput};
use crate::error::{AgentdError, AgentdResult};
use microsandbox_protocol::{
    codec,
    exec::ExecStdinError,
    message::{Message, MessageType},
};
use std::{
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

const INPUT_BYTES: usize = 256 * 1024;
const INPUT_CHUNK: usize = 64 * 1024;
const INPUT_MESSAGES: usize = 64;
const WRITE_DEADLINE: Duration = Duration::from_secs(2);
const OUTPUT_BYTES: usize = 1024 * 1024;
const OUTPUT_MESSAGES: usize = 64;

#[derive(Debug)]
pub(super) struct StdinQueue {
    tx: mpsc::Sender<Input>,
    bytes: Arc<Semaphore>,
    messages: Arc<Semaphore>,
    closed: bool,
    pty: bool,
}

struct Input {
    data: Vec<u8>,
    _bytes: Option<OwnedSemaphorePermit>,
    _message: Option<OwnedSemaphorePermit>,
}

impl StdinQueue {
    pub(super) fn new(fd: RawFd, pty: bool, id: u32, output: OutputSender) -> AgentdResult<Self> {
        let fd = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        if flags < 0
            || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        // One slot is reserved for EOF, which must follow all accepted data.
        let (tx, mut rx) = mpsc::channel::<Input>(INPUT_MESSAGES + 1);
        tokio::spawn(async move {
            let fd = Arc::new(fd);
            while let Some(input) = rx.recv().await {
                if input.data.is_empty() {
                    if pty {
                        continue;
                    }
                    break;
                }
                let owned_fd = fd.clone();
                let result = tokio::task::spawn_blocking(move || {
                    let _accounting = (&input._bytes, &input._message);
                    write_until(
                        owned_fd.as_raw_fd(),
                        &input.data,
                        Instant::now() + WRITE_DEADLINE,
                    )
                })
                .await;
                let error = match result {
                    Ok(Ok(())) => continue,
                    Ok(Err(error)) => error,
                    Err(error) => std::io::Error::other(format!("stdin writer ended: {error}")),
                };
                // One explicit error, never a fabricated exit. Subsequent
                // queued data is discarded only after this reported failure.
                let payload = ExecStdinError {
                    errno: error.raw_os_error(),
                    errno_name: error.raw_os_error().and_then(|n| match n {
                        libc::ETIMEDOUT => Some("ETIMEDOUT".into()),
                        libc::EPIPE => Some("EPIPE".into()),
                        _ => None,
                    }),
                    message: error.to_string(),
                };
                output.stdin_error(id, &payload);
                break;
            }
        });
        Ok(Self {
            tx,
            bytes: Arc::new(Semaphore::new(INPUT_BYTES)),
            messages: Arc::new(Semaphore::new(INPUT_MESSAGES)),
            closed: false,
            pty,
        })
    }

    pub(super) fn enqueue(&mut self, data: Vec<u8>) -> AgentdResult<()> {
        if data.is_empty() && self.pty {
            return Ok(());
        }
        if self.closed {
            return Err(std::io::Error::from_raw_os_error(libc::EPIPE).into());
        }
        if data.len() > INPUT_CHUNK {
            return Err(std::io::Error::from_raw_os_error(libc::E2BIG).into());
        }
        let empty = data.is_empty();
        let (bytes, message) = if empty {
            (None, None)
        } else {
            let bytes = self
                .bytes
                .clone()
                .try_acquire_many_owned(data.len() as u32)
                .map_err(|_| AgentdError::Io(std::io::Error::from_raw_os_error(libc::EAGAIN)))?;
            let message =
                self.messages.clone().try_acquire_owned().map_err(|_| {
                    AgentdError::Io(std::io::Error::from_raw_os_error(libc::EAGAIN))
                })?;
            (Some(bytes), Some(message))
        };
        self.tx
            .try_send(Input {
                data,
                _bytes: bytes,
                _message: message,
            })
            .map_err(|error| {
                AgentdError::Io(std::io::Error::from_raw_os_error(match error {
                    mpsc::error::TrySendError::Full(_) => libc::EAGAIN,
                    mpsc::error::TrySendError::Closed(_) => libc::EPIPE,
                }))
            })?;
        if empty {
            self.closed = true;
        }
        Ok(())
    }
}

/// Nonblocking writes use the owned FD for their entire finite deadline, so
/// cancellation cannot leave a task writing through a reused descriptor.
fn write_until(fd: RawFd, data: &[u8], deadline: Instant) -> std::io::Result<()> {
    let mut written = 0;
    while written < data.len() {
        if Instant::now() >= deadline {
            return Err(std::io::Error::from_raw_os_error(libc::ETIMEDOUT));
        }
        let result =
            unsafe { libc::write(fd, data[written..].as_ptr().cast(), data.len() - written) };
        if result > 0 {
            written += result as usize;
            continue;
        }
        if result < 0 {
            let error = std::io::Error::last_os_error();
            match error.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::EAGAIN) => {}
                _ => return Err(error),
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        let millis = remaining.as_millis().clamp(1, 50) as i32;
        let mut poll = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut poll, 1, millis) };
        if result < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Queue accounting follows the payload until the agent loop encodes it.
pub struct OutputChunk {
    data: Vec<u8>,
    _bytes: OwnedSemaphorePermit,
    _message: OwnedSemaphorePermit,
}

impl std::ops::Deref for OutputChunk {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.data
    }
}

impl OutputChunk {
    pub(crate) fn into_data(self) -> Vec<u8> {
        self.data
    }
}

#[derive(Clone)]
pub(super) struct OutputSender {
    tx: mpsc::UnboundedSender<(u32, SessionOutput)>,
    bytes: Arc<Semaphore>,
    messages: Arc<Semaphore>,
    terminal: Arc<std::sync::Mutex<bool>>,
}

impl OutputSender {
    pub(super) fn new(tx: mpsc::UnboundedSender<(u32, SessionOutput)>) -> Self {
        Self {
            tx,
            bytes: Arc::new(Semaphore::new(OUTPUT_BYTES)),
            messages: Arc::new(Semaphore::new(OUTPUT_MESSAGES)),
            terminal: Arc::new(std::sync::Mutex::new(false)),
        }
    }

    pub(super) async fn send(&self, id: u32, data: Vec<u8>, stderr: bool) -> Result<(), ()> {
        if data.len() > OUTPUT_BYTES {
            return Err(());
        }
        // Backpressure applies only to this reader, never to agent dispatch.
        let bytes = self
            .bytes
            .clone()
            .acquire_many_owned(data.len() as u32)
            .await
            .map_err(|_| ())?;
        let message = self
            .messages
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| ())?;
        let chunk = OutputChunk {
            data,
            _bytes: bytes,
            _message: message,
        };
        let terminal = self.terminal.lock().unwrap();
        if *terminal {
            return Err(());
        }
        self.tx
            .send((
                id,
                if stderr {
                    SessionOutput::Stderr(chunk)
                } else {
                    SessionOutput::Stdout(chunk)
                },
            ))
            .map_err(|_| ())
    }

    pub(super) fn exited(&self, id: u32, code: i32) {
        let mut terminal = self.terminal.lock().unwrap();
        if *terminal {
            return;
        }
        *terminal = true;
        let _ = self.tx.send((id, SessionOutput::Exited(code)));
    }

    fn stdin_error(&self, id: u32, payload: &ExecStdinError) {
        // Serialize publication with the terminal, so a late writer error can
        // never appear on a reused correlation ID after ExecExited.
        let terminal = self.terminal.lock().unwrap();
        if *terminal {
            return;
        }
        if let Ok(message) = Message::with_payload(MessageType::ExecStdinError, id, payload) {
            let mut frame = Vec::new();
            if codec::encode_to_buf(&message, &mut frame).is_ok() {
                let _ = self.tx.send((
                    id,
                    SessionOutput::Raw(RawSessionOutput::new(
                        frame,
                        RawActivity::guest_message(),
                        None,
                    )),
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests;
