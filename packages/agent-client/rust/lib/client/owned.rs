//! Correlation leases and nonblocking, bounded per-session delivery.

use std::collections::VecDeque;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

use microsandbox_protocol::{codec::RawFrame, message::FLAG_TERMINAL};
use serde::Serialize;
use tokio::sync::{Notify, mpsc::error::TryRecvError};

use super::{AgentClient, AgentClientError, AgentClientResult, MessageType};

/// Maximum queued wire bytes for one owned session, excluding its one terminal.
pub const SESSION_OUTPUT_BYTES: usize = 1024 * 1024;
/// Maximum queued nonterminal frames for one owned session.
pub const SESSION_OUTPUT_FRAMES: usize = 64;
/// Maximum encoded body accepted by an owned-session send.
pub const SESSION_SEND_BYTES: usize = 256 * 1024;
/// Maximum simultaneously retained owned-session leases on one connection.
pub(super) const SESSION_LEASES: usize = 64;

/// A frame or an explicit interruption in an owned session's output.
#[derive(Debug)]
pub enum SessionEvent {
    /// An intact protocol frame. A terminal frame retains its terminal flag.
    Frame(RawFrame),
    /// Output exceeded the byte/frame queue bound. Further data was discarded.
    /// A later terminal can still be observed; this is never lossless success.
    OutputOverflow,
    /// The transport ended without an observed terminal frame.
    TransportClosed,
}

/// A connection-bound correlation lease for follow-up messages.
///
/// The ID cannot be reused while this handle, its receiver, or any queued write
/// retains the lease, even after the peer sends a terminal frame. There is no
/// reconnect or lookup by sandbox name.
#[derive(Clone)]
pub struct AgentSession {
    pub(super) client: Arc<AgentClient>,
    pub(super) lease: Arc<SessionLease>,
}

/// Bounded output for one owned session, independent of all other receivers.
pub struct AgentSessionEvents {
    pub(super) lease: Arc<SessionLease>,
    overflow_reported: bool,
    transport_reported: bool,
}

pub(super) struct SessionLease {
    pub(super) id: u32,
    pub(super) active: AtomicBool,
    pub(super) sent: AtomicBool,
    changed: Notify,
    state: Mutex<Mailbox>,
}

#[derive(Default)]
struct Mailbox {
    queue: VecDeque<RawFrame>,
    bytes: usize,
    overflow: bool,
    transport_closed: bool,
    terminal: Option<RawFrame>,
    terminal_seen: bool,
    receiver_dropped: bool,
}

impl AgentSession {
    /// The protocol correlation ID, diagnostic only; sends require this lease.
    pub fn id(&self) -> u32 {
        self.lease.id
    }

    /// Whether this session still accepts follow-up sends.
    ///
    /// This is not proof that its guest process is running.
    pub fn is_active(&self) -> bool {
        self.lease.active.load(Ordering::Acquire)
    }

    /// Refuse future and not-yet-started queued writes without claiming remote
    /// termination. The ID remains reserved until its terminal or disconnect.
    pub fn close_sends(&self) {
        self.lease.active.store(false, Ordering::Release);
    }

    /// Send a bounded follow-up using this original connection and lease.
    /// Queued writes keep the lease even if the caller cancels this future.
    pub async fn send<T: Serialize>(
        &self,
        kind: MessageType,
        payload: &T,
    ) -> AgentClientResult<()> {
        self.client.ensure_version_compat(kind)?;
        if !self.is_active() {
            return Err(AgentClientError::SessionClosed(self.id()));
        }
        // Account for both the payload and envelope before allocating either.
        // A full queue fails promptly instead of retaining unbounded send tasks.
        let bytes = self
            .client
            .session_write_bytes
            .clone()
            .try_acquire_many_owned((2 * SESSION_SEND_BYTES + 9) as u32)
            .map_err(|_| AgentClientError::SessionWriteQueueFull)?;
        let body = encode(self.client.protocol.version(), kind, payload)?;
        self.client
            .write_session_frame(self.lease.clone(), kind.flags(), body, bytes)
            .await
    }
}

impl SessionLease {
    pub(super) fn new(id: u32) -> Arc<Self> {
        Arc::new(Self {
            id,
            active: AtomicBool::new(true),
            sent: AtomicBool::new(false),
            changed: Notify::new(),
            state: Mutex::new(Mailbox::default()),
        })
    }

    pub(super) fn receiver(self: &Arc<Self>) -> AgentSessionEvents {
        AgentSessionEvents {
            lease: self.clone(),
            overflow_reported: false,
            transport_reported: false,
        }
    }

    /// Never waits for a consumer. One separate terminal slot remains available
    /// after overflow so cancellation may still observe the remote outcome.
    pub(super) fn push(&self, frame: RawFrame) {
        let mut state = self.state.lock().unwrap();
        if state.terminal_seen || state.transport_closed {
            return;
        }
        if frame.flags & FLAG_TERMINAL != 0 {
            self.active.store(false, Ordering::Release);
            state.terminal_seen = true;
            if !state.receiver_dropped {
                state.terminal = Some(frame);
            }
        } else if !state.receiver_dropped && !state.overflow {
            let bytes = frame.body.len() + 4 + microsandbox_protocol::message::FRAME_HEADER_SIZE;
            if state.queue.len() >= SESSION_OUTPUT_FRAMES
                || bytes > SESSION_OUTPUT_BYTES - state.bytes
            {
                state.overflow = true;
            } else {
                state.bytes += bytes;
                state.queue.push_back(frame);
            }
        }
        drop(state);
        self.changed.notify_one();
    }

    pub(super) fn transport_closed(&self) {
        self.active.store(false, Ordering::Release);
        let mut state = self.state.lock().unwrap();
        state.transport_closed = true;
        drop(state);
        self.changed.notify_one();
    }
}

impl AgentSessionEvents {
    /// Receive without waiting or performing transport I/O.
    pub fn try_recv(&mut self) -> Result<SessionEvent, TryRecvError> {
        let mut state = self.lease.state.lock().unwrap();
        if let Some(frame) = state.queue.pop_front() {
            state.bytes -= frame.body.len() + 4 + microsandbox_protocol::message::FRAME_HEADER_SIZE;
            return Ok(SessionEvent::Frame(frame));
        }
        if state.overflow && !self.overflow_reported {
            self.overflow_reported = true;
            return Ok(SessionEvent::OutputOverflow);
        }
        if let Some(frame) = state.terminal.take() {
            return Ok(SessionEvent::Frame(frame));
        }
        if state.transport_closed && !state.terminal_seen && !self.transport_reported {
            self.transport_reported = true;
            return Ok(SessionEvent::TransportClosed);
        }
        if state.terminal_seen || state.transport_closed {
            Err(TryRecvError::Disconnected)
        } else {
            Err(TryRecvError::Empty)
        }
    }

    /// Wait for one event. Cancelling this future does not consume an event.
    pub async fn recv(&mut self) -> Option<SessionEvent> {
        loop {
            let lease = self.lease.clone();
            let notified = lease.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            match self.try_recv() {
                Ok(event) => return Some(event),
                Err(TryRecvError::Disconnected) => return None,
                Err(TryRecvError::Empty) => notified.await,
            }
        }
    }
}

impl Drop for AgentSessionEvents {
    fn drop(&mut self) {
        let mut state = self.lease.state.lock().unwrap();
        state.receiver_dropped = true;
        state.queue.clear();
        state.bytes = 0;
        state.terminal = None;
    }
}

fn encode<T: Serialize>(version: u8, kind: MessageType, payload: &T) -> AgentClientResult<Vec<u8>> {
    struct Limited(Vec<u8>);
    impl std::io::Write for Limited {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > SESSION_SEND_BYTES - self.0.len() {
                return Err(std::io::Error::other("session message byte limit exceeded"));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut payload_bytes = Limited(Vec::with_capacity(SESSION_SEND_BYTES));
    ciborium::into_writer(payload, &mut payload_bytes)
        .map_err(|_| AgentClientError::SessionSendTooLarge)?;
    let message = microsandbox_protocol::message::Message {
        v: version,
        t: kind,
        id: 0,
        flags: kind.flags(),
        p: payload_bytes.0,
    };
    let mut envelope = Limited(Vec::with_capacity(SESSION_SEND_BYTES));
    ciborium::into_writer(&message, &mut envelope)
        .map_err(|_| AgentClientError::SessionSendTooLarge)?;
    Ok(envelope.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(flags: u8, bytes: usize) -> RawFrame {
        RawFrame {
            id: 1,
            flags,
            body: vec![0; bytes],
        }
    }

    #[test]
    fn owned_session_byte_overflow_preserves_independent_terminal() {
        let lease = SessionLease::new(1);
        let mut events = lease.receiver();
        lease.push(frame(0, SESSION_OUTPUT_BYTES));
        assert!(matches!(
            events.try_recv(),
            Ok(SessionEvent::OutputOverflow)
        ));
        assert!(matches!(events.try_recv(), Err(TryRecvError::Empty)));
        lease.push(frame(FLAG_TERMINAL, 16));
        assert!(!lease.active.load(Ordering::Acquire));
        assert!(matches!(events.try_recv(), Ok(SessionEvent::Frame(_))));
        assert!(matches!(events.try_recv(), Err(TryRecvError::Disconnected)));
    }

    #[test]
    fn owned_session_frame_bound_does_not_silently_drop_success() {
        let lease = SessionLease::new(1);
        let mut events = lease.receiver();
        for _ in 0..SESSION_OUTPUT_FRAMES + 1 {
            lease.push(frame(0, 0));
        }
        lease.push(frame(FLAG_TERMINAL, 0));
        for _ in 0..SESSION_OUTPUT_FRAMES {
            assert!(matches!(events.try_recv(), Ok(SessionEvent::Frame(_))));
        }
        assert!(matches!(
            events.try_recv(),
            Ok(SessionEvent::OutputOverflow)
        ));
        assert!(matches!(events.try_recv(), Ok(SessionEvent::Frame(_))));
    }

    #[test]
    fn owned_session_transport_loss_is_not_terminal() {
        let lease = SessionLease::new(1);
        let mut events = lease.receiver();
        lease.transport_closed();
        assert!(matches!(
            events.try_recv(),
            Ok(SessionEvent::TransportClosed)
        ));
        assert!(matches!(events.try_recv(), Err(TryRecvError::Disconnected)));
    }

    #[test]
    fn owned_session_encoding_stops_at_send_bound() {
        assert!(matches!(
            encode(
                1,
                MessageType::ExecStdin,
                &vec![0_u8; SESSION_SEND_BYTES + 1]
            ),
            Err(AgentClientError::SessionSendTooLarge)
        ));
    }

    #[cfg(feature = "stream")]
    async fn connected(ids: u32) -> (Arc<AgentClient>, tokio::io::DuplexStream) {
        use microsandbox_protocol::{codec, core::Ready, message::Message};
        use tokio::io::AsyncWriteExt;
        let (client, mut peer) = tokio::io::duplex(1024);
        peer.write_all(&1_u32.to_be_bytes()).await.unwrap();
        peer.write_all(&(ids + 1).to_be_bytes()).await.unwrap();
        codec::write_message(
            &mut peer,
            &Message::with_payload(MessageType::Ready, 0, &Ready::default()).unwrap(),
        )
        .await
        .unwrap();
        (
            Arc::new(AgentClient::connect_stream(client).await.unwrap()),
            peer,
        )
    }

    #[cfg(feature = "stream")]
    #[tokio::test]
    async fn owned_session_terminal_retains_id_until_controls_and_receiver_drop() {
        use microsandbox_protocol::codec;
        let (client, mut peer) = connected(2).await;
        let (first, mut events) = client.owned_session().await.unwrap();
        let first_id = first.id();
        codec::write_raw_frame(&mut peer, &frame(FLAG_TERMINAL, 0))
            .await
            .unwrap();
        assert!(matches!(events.recv().await, Some(SessionEvent::Frame(_))));
        assert!(matches!(
            first.send(MessageType::ExecSignal, &()).await,
            Err(AgentClientError::SessionClosed(_))
        ));
        let (_second, _second_events) = client.owned_session().await.unwrap();
        assert!(matches!(
            client.owned_session().await,
            Err(AgentClientError::IdRangeExhausted)
        ));
        drop(events);
        assert!(matches!(
            client.owned_session().await,
            Err(AgentClientError::IdRangeExhausted)
        ));
        drop(first);
        let (replacement, _) = client.owned_session().await.unwrap();
        assert_eq!(replacement.id(), first_id);
    }

    #[cfg(feature = "stream")]
    #[tokio::test]
    async fn owned_session_slow_consumer_does_not_block_another_terminal() {
        use microsandbox_protocol::codec;
        let (client, mut peer) = connected(2).await;
        let (slow, mut slow_events) = client.owned_session().await.unwrap();
        let (fast, mut fast_events) = client.owned_session().await.unwrap();
        for _ in 0..SESSION_OUTPUT_FRAMES + 1 {
            let frame = RawFrame {
                id: slow.id(),
                flags: 0,
                body: vec![0; 64],
            };
            codec::write_raw_frame(&mut peer, &frame).await.unwrap();
        }
        codec::write_raw_frame(
            &mut peer,
            &RawFrame {
                id: fast.id(),
                flags: FLAG_TERMINAL,
                body: vec![],
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            tokio::time::timeout(std::time::Duration::from_secs(1), fast_events.recv())
                .await
                .unwrap(),
            Some(SessionEvent::Frame(_))
        ));
        for _ in 0..SESSION_OUTPUT_FRAMES {
            assert!(matches!(
                slow_events.recv().await,
                Some(SessionEvent::Frame(_))
            ));
        }
        assert!(matches!(
            slow_events.recv().await,
            Some(SessionEvent::OutputOverflow)
        ));
    }

    #[cfg(feature = "stream")]
    #[tokio::test]
    async fn owned_session_queued_writes_hold_id_after_sender_cancellation() {
        use microsandbox_protocol::{codec, exec::ExecStdin};
        use std::time::Duration;
        let (client, mut peer) = connected(1).await;
        let (session, mut events) = client.owned_session().await.unwrap();
        let first = session.clone();
        let sending = tokio::spawn(async move {
            first
                .send(
                    MessageType::ExecStdin,
                    &ExecStdin {
                        data: vec![0; 128 * 1024],
                    },
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while !session.lease.sent.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        // The writer is blocked in this frame. A second write is queued behind
        // it and must become stale without ever reaching the peer.
        let second = session.clone();
        let queued = tokio::spawn(async move { second.send(MessageType::ExecSignal, &()).await });
        tokio::task::yield_now().await;
        codec::write_raw_frame(&mut peer, &frame(FLAG_TERMINAL, 0))
            .await
            .unwrap();
        assert!(matches!(events.recv().await, Some(SessionEvent::Frame(_))));
        sending.abort();
        queued.abort();
        let _ = sending.await;
        let _ = queued.await;
        drop((session, events));
        assert!(matches!(
            client.owned_session().await,
            Err(AgentClientError::IdRangeExhausted)
        ));
        codec::read_raw_frame(&mut peer).await.unwrap();
        let replacement = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                match client.owned_session().await {
                    Ok(session) => break session,
                    Err(AgentClientError::IdRangeExhausted) => tokio::task::yield_now().await,
                    Err(error) => panic!("unexpected error: {error}"),
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(replacement.0.id(), 1);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), codec::read_raw_frame(&mut peer))
                .await
                .is_err()
        );
    }

    #[cfg(feature = "stream")]
    #[tokio::test]
    async fn owned_session_unused_reservation_can_be_released_without_sending() {
        let (client, _peer) = connected(1).await;
        let unused = client.owned_session().await.unwrap();
        drop(unused);
        assert!(client.owned_session().await.is_ok());
    }
}
