//! One owner per native exec: bounded delivery, deadline, and cleanup.

use std::{fmt, sync::Arc, time::Duration};

use bytes::Bytes;
use microsandbox_agent_client::{AgentSession, AgentSessionEvents, SessionEvent};
use microsandbox_protocol::{
    codec::RawFrame,
    exec::{
        ExecExited, ExecFailed, ExecRequest, ExecResize, ExecSignal, ExecStarted, ExecStderr,
        ExecStdin, ExecStdinError, ExecStdout,
    },
    message::{FLAG_TERMINAL, Message, MessageType},
};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch},
    time::{Instant, timeout, timeout_at},
};

use super::{ExecControl, ExecEvent, ExecHandle, ExecSink, StdinMode};
use crate::{MicrosandboxError, MicrosandboxResult, agent::AgentClient};

const OUTPUT_BYTES: usize = 1024 * 1024;
const OUTPUT_EVENTS: usize = 64;
pub(super) const COLLECT_BYTES: usize = 8 * 1024 * 1024;
const INPUT_BYTES: usize = 8 * 1024 * 1024;
const INPUT_CHUNK: usize = 64 * 1024;
const SEND_TIMEOUT: Duration = Duration::from_secs(2);
const TERMINATION_TIMEOUT: Duration = Duration::from_secs(5);
const CANCEL_TIMEOUT: Duration = Duration::from_secs(8);

/// Why an exec operation could not complete normally.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ExecInterruptionReason {
    /// Its execution deadline elapsed, including request delivery.
    Timeout(Duration),
    /// A caller cancelled, or dropped the event owner before completion.
    Cancelled,
    /// A bounded output queue or buffered collection exceeded its limit.
    OutputLimit,
    /// The original transport closed without a valid terminal event.
    TransportClosed,
    /// An exec frame was malformed or inappropriate for this session.
    Protocol,
    /// A bounded request or stdin/control send could not complete.
    Delivery,
}

/// Process outcome reported on the original exec session, not inferred from a
/// signal request, host PID disappearance, or a transport disconnect.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ExecTermination {
    /// A valid agent terminal reported the process exit code.
    Exited(i32),
    /// A valid agent terminal reported that spawning failed.
    SpawnFailed(ExecFailed),
    /// No valid terminal was observed within the bounded cleanup interval.
    Unconfirmed,
}

/// An interrupted operation and its independent termination evidence.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ExecInterruption {
    /// The first reason the operation was interrupted.
    pub reason: ExecInterruptionReason,
    /// What was observed during bounded cleanup on the original connection.
    pub termination: ExecTermination,
}

impl fmt::Display for ExecInterruption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}; termination: {:?}", self.reason, self.termination)
    }
}

struct QueuedEvent {
    event: ExecEvent,
    _bytes: OwnedSemaphorePermit,
}

/// The terminal slot is independent of the bounded output queue.
pub(crate) struct ExecEvents {
    data: mpsc::Receiver<QueuedEvent>,
    completed: watch::Receiver<Option<ExecEvent>>,
    ended: bool,
}

impl ExecEvents {
    pub(crate) fn try_recv(&mut self) -> Result<ExecEvent, mpsc::error::TryRecvError> {
        if self.ended {
            return Err(mpsc::error::TryRecvError::Disconnected);
        }
        match self.data.try_recv() {
            Ok(queued) => Ok(queued.event),
            Err(state) => self.after_data_empty(state),
        }
    }

    fn after_data_empty(
        &mut self,
        state: mpsc::error::TryRecvError,
    ) -> Result<ExecEvent, mpsc::error::TryRecvError> {
        if let Some(terminal) = self.completed.borrow().clone() {
            // The producer enqueues all output before publishing completion.
            // Its final enqueue may race the first empty read; recheck after
            // observing completion so the independent terminal cannot overtake it.
            if let Ok(queued) = self.data.try_recv() {
                return Ok(queued.event);
            }
            self.ended = true;
            Ok(terminal)
        } else if state == mpsc::error::TryRecvError::Disconnected {
            self.ended = true;
            Ok(interrupted(
                ExecInterruptionReason::TransportClosed,
                ExecTermination::Unconfirmed,
            ))
        } else {
            Err(state)
        }
    }

    pub(crate) async fn recv(&mut self) -> Option<ExecEvent> {
        loop {
            match self.try_recv() {
                Ok(event) => return Some(event),
                Err(mpsc::error::TryRecvError::Disconnected) => return None,
                Err(mpsc::error::TryRecvError::Empty) => {}
            }
            tokio::select! {
                queued = self.data.recv() => {
                    if let Some(queued) = queued { return Some(queued.event); }
                }
                _ = self.completed.changed() => {}
            }
        }
    }
}

#[derive(Clone)]
pub(super) struct SessionControl {
    pub(super) session: AgentSession,
    cancel: watch::Sender<Option<ExecInterruptionReason>>,
    completed: watch::Receiver<Option<ExecEvent>>,
}

impl SessionControl {
    pub(super) async fn signal(&self, signal: i32) -> MicrosandboxResult<()> {
        bounded_send(
            &self.session,
            MessageType::ExecSignal,
            &ExecSignal { signal },
        )
        .await
    }

    pub(super) async fn resize(&self, rows: u16, cols: u16) -> MicrosandboxResult<()> {
        bounded_send(
            &self.session,
            MessageType::ExecResize,
            &ExecResize { rows, cols },
        )
        .await
    }

    pub(super) async fn cancel(&self, reason: ExecInterruptionReason) -> ExecInterruption {
        self.cancel.send_if_modified(|current| {
            if current.is_some() {
                false
            } else {
                *current = Some(reason.clone());
                true
            }
        });
        let mut completed = self.completed.clone();
        let observe = async {
            loop {
                if let Some(event) = completed.borrow().clone() {
                    return match event {
                        ExecEvent::Interrupted(value) => value,
                        other => ExecInterruption {
                            reason: reason.clone(),
                            termination: termination(&other)
                                .unwrap_or(ExecTermination::Unconfirmed),
                        },
                    };
                }
                if completed.changed().await.is_err() {
                    break;
                }
            }
            ExecInterruption {
                reason: reason.clone(),
                termination: ExecTermination::Unconfirmed,
            }
        };
        timeout(CANCEL_TIMEOUT, observe)
            .await
            .unwrap_or(ExecInterruption {
                reason,
                termination: ExecTermination::Unconfirmed,
            })
    }
}

async fn bounded_send<T: serde::Serialize>(
    session: &AgentSession,
    kind: MessageType,
    payload: &T,
) -> MicrosandboxResult<()> {
    timeout(SEND_TIMEOUT, session.send(kind, payload))
        .await
        .map_err(|_| {
            MicrosandboxError::ExecInterrupted(ExecInterruption {
                reason: ExecInterruptionReason::Delivery,
                termination: ExecTermination::Unconfirmed,
            })
        })??;
    Ok(())
}

pub(super) async fn write_stdin(
    session: &AgentSession,
    data: &[u8],
    close: bool,
) -> MicrosandboxResult<()> {
    // One deadline for the whole write. No full-input clone and no unbounded
    // background producer; cancelled queued writes retain the native lease.
    timeout(SEND_TIMEOUT, async {
        for chunk in data.chunks(INPUT_CHUNK) {
            session
                .send(
                    MessageType::ExecStdin,
                    &ExecStdin {
                        data: chunk.to_vec(),
                    },
                )
                .await?;
        }
        if close {
            session
                .send(MessageType::ExecStdin, &ExecStdin { data: Vec::new() })
                .await?;
        }
        Ok::<_, microsandbox_agent_client::AgentClientError>(())
    })
    .await
    .map_err(|_| {
        MicrosandboxError::ExecInterrupted(ExecInterruption {
            reason: ExecInterruptionReason::Delivery,
            termination: ExecTermination::Unconfirmed,
        })
    })??;
    Ok(())
}

pub(super) async fn open(
    client: Arc<AgentClient>,
    request: ExecRequest,
    stdin: StdinMode,
    duration: Option<Duration>,
) -> MicrosandboxResult<ExecHandle> {
    if matches!(&stdin, StdinMode::Bytes(bytes) if bytes.len() > INPUT_BYTES) {
        return Err(MicrosandboxError::InvalidConfig(
            "fixed stdin exceeds 8 MiB".into(),
        ));
    }
    if duration == Some(Duration::ZERO) {
        return Err(MicrosandboxError::ExecInterrupted(ExecInterruption {
            reason: ExecInterruptionReason::Timeout(Duration::ZERO),
            termination: ExecTermination::Unconfirmed,
        }));
    }
    let deadline = duration.and_then(|d| Instant::now().checked_add(d));
    if duration.is_some() && deadline.is_none() {
        return Err(MicrosandboxError::InvalidConfig(
            "exec timeout overflows clock".into(),
        ));
    }
    let (session, raw) = client.owned_session().await?;
    let (data_tx, data_rx) = mpsc::channel(OUTPUT_EVENTS);
    let (completed_tx, completed_rx) = watch::channel(None);
    let (cancel_tx, cancel_rx) = watch::channel(None);
    let control = ExecControl {
        inner: SessionControl {
            session: session.clone(),
            cancel: cancel_tx,
            completed: completed_rx.clone(),
        },
    };
    let sink = matches!(stdin, StdinMode::Pipe).then(|| ExecSink::new(session.clone()));
    let events = ExecEvents {
        data: data_rx,
        completed: completed_rx,
        ended: false,
    };
    let (opened_tx, opened_rx) = oneshot::channel();
    // The actor exists before the opening write can be queued. Dropping the
    // caller at any await drops its event receiver and triggers owned cleanup.
    tokio::spawn(run(
        session,
        raw,
        request,
        stdin,
        duration,
        deadline,
        data_tx,
        completed_tx,
        cancel_rx,
        opened_tx,
    ));
    match opened_rx.await {
        Ok(Ok(())) => Ok(ExecHandle::new(control, events, sink)),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(MicrosandboxError::Runtime(
            "exec owner ended before request delivery".into(),
        )),
    }
}

#[allow(clippy::too_many_arguments)]
async fn run(
    session: AgentSession,
    mut raw: AgentSessionEvents,
    request: ExecRequest,
    stdin: StdinMode,
    duration: Option<Duration>,
    deadline: Option<Instant>,
    data: mpsc::Sender<QueuedEvent>,
    completed: watch::Sender<Option<ExecEvent>>,
    mut cancel: watch::Receiver<Option<ExecInterruptionReason>>,
    opened: oneshot::Sender<MicrosandboxResult<()>>,
) {
    let opening = bounded_send(&session, MessageType::ExecRequest, &request);
    let opening_result = tokio::select! {
        result = opening => result.map_err(|_| ExecInterruptionReason::Delivery),
        _ = wait_deadline(deadline) => Err(ExecInterruptionReason::Timeout(duration.unwrap())),
        _ = data.closed() => Err(ExecInterruptionReason::Cancelled),
    };
    if let Err(reason) = opening_result {
        let outcome = cleanup(&session, &mut raw, reason).await;
        let _ = opened.send(Err(MicrosandboxError::ExecInterrupted(outcome.clone())));
        completed.send_replace(Some(ExecEvent::Interrupted(outcome)));
        return;
    }
    let _ = opened.send(Ok(()));
    let fixed_stdin = matches!(&stdin, StdinMode::Bytes(_));
    let bytes = Arc::new(Semaphore::new(OUTPUT_BYTES));
    let reason = {
        let input = async {
            match stdin {
                StdinMode::Bytes(bytes) => write_stdin(&session, &bytes, true).await,
                // Pipe EOF follows the opening request. For a PTY the agent
                // intentionally treats an empty stdin frame as a no-op.
                StdinMode::Null => write_stdin(&session, &[], true).await,
                StdinMode::Pipe => Ok(()),
            }
        };
        tokio::pin!(input);
        let mut input_done = false;
        loop {
            if let Some(reason) = cancel.borrow().clone() {
                break reason;
            }
            tokio::select! {
                biased;
                _ = wait_deadline(deadline) => break ExecInterruptionReason::Timeout(duration.unwrap()),
                _ = data.closed() => break ExecInterruptionReason::Cancelled,
                changed = cancel.changed() => {
                    if changed.is_err() { break ExecInterruptionReason::Cancelled; }
                }
                event = raw.recv() => {
                    match decode(event) {
                        Ok(event) => {
                            if termination(&event).is_some() {
                                completed.send_replace(Some(event));
                                return;
                            }
                            if fixed_stdin && matches!(&event, ExecEvent::StdinError(_)) {
                                // Fixed input is part of the operation, unlike an
                                // interactive Pipe write. A later exit, even zero,
                                // cannot turn refused input into successful delivery.
                                let _ = enqueue(&data, &bytes, event);
                                break ExecInterruptionReason::Delivery;
                            }
                            if !enqueue(&data, &bytes, event) { break ExecInterruptionReason::OutputLimit; }
                        }
                        Err(reason) => break reason,
                    }
                }
                result = &mut input, if !input_done => {
                    input_done = true;
                    if result.is_err() { break ExecInterruptionReason::Delivery; }
                }
            }
        }
    };
    // The fixed-input future is dropped before cleanup. Queued writes remain
    // leased, and the writer will refuse them after the terminal/close fence.
    let outcome = cleanup(&session, &mut raw, reason).await;
    completed.send_replace(Some(ExecEvent::Interrupted(outcome)));
}

async fn wait_deadline(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

fn enqueue(data: &mpsc::Sender<QueuedEvent>, bytes: &Arc<Semaphore>, event: ExecEvent) -> bool {
    let size = match &event {
        ExecEvent::Stdout(data) | ExecEvent::Stderr(data) => data.len(),
        ExecEvent::StdinError(error) => {
            error.message.len() + error.errno_name.as_ref().map_or(0, String::len)
        }
        _ => 0,
    };
    if size > OUTPUT_BYTES {
        return false;
    }
    let Ok(permit) = bytes.clone().try_acquire_many_owned(size as u32) else {
        return false;
    };
    data.try_send(QueuedEvent {
        event,
        _bytes: permit,
    })
    .is_ok()
}

fn decode(event: Option<SessionEvent>) -> Result<ExecEvent, ExecInterruptionReason> {
    let frame = match event {
        Some(SessionEvent::Frame(frame)) => frame,
        Some(SessionEvent::OutputOverflow) => return Err(ExecInterruptionReason::OutputLimit),
        Some(SessionEvent::TransportClosed) | None => {
            return Err(ExecInterruptionReason::TransportClosed);
        }
    };
    decode_frame(frame).ok_or(ExecInterruptionReason::Protocol)
}

fn decode_frame(frame: RawFrame) -> Option<ExecEvent> {
    let terminal = frame.flags & FLAG_TERMINAL != 0;
    // Terminal metadata has a separate fixed limit, including malformed peers.
    if terminal && frame.body.len() > 16 * 1024 {
        return None;
    }
    let message: Message = ciborium::from_reader(frame.body.as_slice()).ok()?;
    let event = match message.t {
        MessageType::ExecStarted => ExecEvent::Started {
            pid: message.payload::<ExecStarted>().ok()?.pid,
        },
        MessageType::ExecStdout => {
            ExecEvent::Stdout(Bytes::from(message.payload::<ExecStdout>().ok()?.data))
        }
        MessageType::ExecStderr => {
            ExecEvent::Stderr(Bytes::from(message.payload::<ExecStderr>().ok()?.data))
        }
        MessageType::ExecStdinError => {
            ExecEvent::StdinError(message.payload::<ExecStdinError>().ok()?)
        }
        MessageType::ExecExited => ExecEvent::Exited {
            code: message.payload::<ExecExited>().ok()?.code,
        },
        MessageType::ExecFailed => ExecEvent::Failed(message.payload::<ExecFailed>().ok()?),
        _ => return None,
    };
    (terminal == termination(&event).is_some()).then_some(event)
}

fn termination(event: &ExecEvent) -> Option<ExecTermination> {
    match event {
        ExecEvent::Exited { code } => Some(ExecTermination::Exited(*code)),
        ExecEvent::Failed(failure) => Some(ExecTermination::SpawnFailed(failure.clone())),
        _ => None,
    }
}

fn interrupted(reason: ExecInterruptionReason, termination: ExecTermination) -> ExecEvent {
    ExecEvent::Interrupted(ExecInterruption {
        reason,
        termination,
    })
}

async fn cleanup(
    session: &AgentSession,
    raw: &mut AgentSessionEvents,
    reason: ExecInterruptionReason,
) -> ExecInterruption {
    // First inspect already queued evidence. Never signal a completed session.
    let observe = async {
        while let Ok(event) = raw.try_recv() {
            if let Ok(event) = decode(Some(event))
                && let Some(termination) = termination(&event)
            {
                return termination;
            }
        }
        let _ = bounded_send(session, MessageType::ExecSignal, &ExecSignal { signal: 9 }).await;
        let end = Instant::now() + TERMINATION_TIMEOUT;
        loop {
            match timeout_at(end, raw.recv()).await {
                Ok(Some(event)) => {
                    if let Ok(event) = decode(Some(event))
                        && let Some(termination) = termination(&event)
                    {
                        return termination;
                    }
                }
                _ => return ExecTermination::Unconfirmed,
            }
        }
    };
    let termination = timeout(SEND_TIMEOUT + TERMINATION_TIMEOUT, observe)
        .await
        .unwrap_or(ExecTermination::Unconfirmed);
    session.close_sends();
    ExecInterruption {
        reason,
        termination,
    }
}

#[cfg(test)]
mod tests;
