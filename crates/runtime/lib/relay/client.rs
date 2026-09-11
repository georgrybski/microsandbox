//! Bounded delivery and retained correlation ownership for one relay client.

use std::collections::HashSet;
use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const QUEUED_FRAMES: usize = 64;
// Include the prefix so any one valid protocol frame remains admissible. The
// permit stays attached while a socket write is in flight, not just queued.
const QUEUED_BYTES: usize = microsandbox_protocol::codec::MAX_FRAME_SIZE as usize + 4;
const ACTIVE_EXECS: usize = 64;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub(super) struct QueuedFrame {
    pub(super) bytes: Bytes,
    _permit: OwnedSemaphorePermit,
}

pub(super) struct ClientOutput {
    sender: mpsc::Sender<QueuedFrame>,
    budget: Arc<Semaphore>,
    closed: watch::Sender<bool>,
}

pub(super) struct ClientState {
    pub(super) active_sessions: HashSet<u32>,
    pub(super) output: ClientOutput,
    pub(super) writer_finished: bool,
    pub(super) cleanup_finished: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ClientOutput {
    pub(super) fn new() -> (Self, mpsc::Receiver<QueuedFrame>, watch::Receiver<bool>) {
        let (sender, receiver) = mpsc::channel(QUEUED_FRAMES);
        let (closed, cancellation) = watch::channel(false);
        (
            Self {
                sender,
                budget: Arc::new(Semaphore::new(QUEUED_BYTES)),
                closed,
            },
            receiver,
            cancellation,
        )
    }

    pub(super) fn is_closed(&self) -> bool {
        *self.closed.borrow()
    }

    pub(super) fn close(&self) {
        self.closed.send_replace(true);
    }

    pub(super) fn subscribe(&self) -> watch::Receiver<bool> {
        self.closed.subscribe()
    }

    /// No shared reader awaits a consumer. Any admission/delivery failure
    /// explicitly closes this transport, so dropped output is never lossless.
    pub(super) fn try_send(&self, bytes: Bytes) -> bool {
        if self.is_closed() {
            return false;
        }
        let permit = u32::try_from(bytes.len())
            .ok()
            .and_then(|size| self.budget.clone().try_acquire_many_owned(size).ok());
        if let Some(permit) = permit
            && self
                .sender
                .try_send(QueuedFrame {
                    // A small Bytes slice could otherwise retain an entire
                    // large decoder allocation outside its accounted length.
                    bytes: Bytes::copy_from_slice(&bytes),
                    _permit: permit,
                })
                .is_ok()
        {
            return true;
        }
        self.close();
        false
    }
}

impl ClientState {
    pub(super) fn new(output: ClientOutput) -> Self {
        Self {
            active_sessions: HashSet::new(),
            output,
            writer_finished: false,
            cleanup_finished: false,
        }
    }

    pub(super) fn start_exec(&mut self, id: u32) -> bool {
        if self.output.is_closed()
            || self.active_sessions.len() >= ACTIVE_EXECS
            || !self.active_sessions.insert(id)
        {
            self.output.close();
            return false;
        }
        true
    }

    pub(super) fn can_release(&self) -> bool {
        self.output.is_closed()
            && self.writer_finished
            && self.cleanup_finished
            && self.active_sessions.is_empty()
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bounded_relay_slow_client_does_not_block_another_client() {
        let (slow, _unread, mut closed) = ClientOutput::new();
        let (fast, mut output, _) = ClientOutput::new();
        for _ in 0..QUEUED_FRAMES {
            assert!(slow.try_send(Bytes::from_static(b"x")));
        }
        assert!(!slow.try_send(Bytes::from_static(b"overflow")));
        closed.changed().await.unwrap();
        assert!(*closed.borrow());
        assert!(fast.try_send(Bytes::from_static(b"unaffected")));
        assert_eq!(output.recv().await.unwrap().bytes, b"unaffected"[..]);
    }

    #[tokio::test]
    async fn bounded_relay_inflight_frame_retains_byte_budget() {
        let (output, mut receiver, _) = ClientOutput::new();
        assert!(output.try_send(Bytes::from(vec![0; QUEUED_BYTES])));
        let in_flight = receiver.recv().await.unwrap();
        assert_eq!(output.budget.available_permits(), 0);
        assert!(!output.try_send(Bytes::from_static(b"overflow")));
        drop(in_flight);
        assert_eq!(output.budget.available_permits(), QUEUED_BYTES);
        assert!(
            output.is_closed(),
            "overflow remains sticky after capacity recovers"
        );
    }

    #[test]
    fn bounded_relay_closed_receiver_is_explicit_transport_failure() {
        let (output, receiver, _) = ClientOutput::new();
        drop(receiver);
        assert!(!output.try_send(Bytes::from_static(b"x")));
        assert!(output.is_closed());
    }

    #[test]
    fn bounded_relay_tombstone_needs_terminal_and_owned_cleanup() {
        let (output, _receiver, _) = ClientOutput::new();
        let mut state = ClientState::new(output);
        assert!(state.start_exec(7));
        state.output.close();
        assert!(!state.can_release());
        state.writer_finished = true;
        state.cleanup_finished = true;
        assert!(
            !state.can_release(),
            "a kill request is not a terminal event"
        );
        state.active_sessions.remove(&8);
        assert!(
            !state.can_release(),
            "a different exec cannot release the lease"
        );
        state.active_sessions.remove(&7);
        assert!(state.can_release());
    }

    #[test]
    fn bounded_relay_duplicate_or_exhausted_exec_ownership_refuses() {
        for duplicate in [true, false] {
            let (output, _receiver, _) = ClientOutput::new();
            let mut state = ClientState::new(output);
            let count = if duplicate { 1 } else { ACTIVE_EXECS as u32 };
            for id in 1..=count {
                assert!(state.start_exec(id));
            }
            assert!(!state.start_exec(if duplicate {
                1
            } else {
                ACTIVE_EXECS as u32 + 1
            }));
            assert!(state.output.is_closed());
            assert_eq!(state.active_sessions.len(), count as usize);
        }
    }
}
