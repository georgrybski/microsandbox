//! In-process relay fixtures; no VM or guest process is implied.

use super::*;
use microsandbox_protocol::{codec, core::Ready};
use tokio::io::{AsyncWriteExt, DuplexStream};

async fn connected() -> (Arc<AgentClient>, DuplexStream) {
    let (stream, mut peer) = tokio::io::duplex(4096);
    peer.write_all(&1_u32.to_be_bytes()).await.unwrap();
    peer.write_all(&20_u32.to_be_bytes()).await.unwrap();
    codec::write_message(
        &mut peer,
        &Message::with_payload(MessageType::Ready, 0, &Ready::default()).unwrap(),
    )
    .await
    .unwrap();
    let client = AgentClient::connect_stream_with_timeout(stream, Duration::from_secs(1))
        .await
        .unwrap();
    (Arc::new(client), peer)
}

#[test]
fn native_exec_completion_racing_empty_read_cannot_overtake_output() {
    let (tx, data) = mpsc::channel(OUTPUT_EVENTS);
    let (finished, completed) = watch::channel(None);
    let mut events = ExecEvents {
        data,
        completed,
        ended: false,
    };
    let bytes = Arc::new(Semaphore::new(OUTPUT_BYTES));
    // Freeze the exact interleaving: the first queue read sees empty; then
    // the producer publishes its last data and completion before the watch read.
    let state = events.data.try_recv().err().unwrap();
    assert_eq!(state, mpsc::error::TryRecvError::Empty);
    assert!(enqueue(
        &tx,
        &bytes,
        ExecEvent::Stdout(Bytes::from_static(b"last"))
    ));
    finished.send_replace(Some(ExecEvent::Exited { code: 0 }));
    assert!(
        matches!(events.after_data_empty(state), Ok(ExecEvent::Stdout(data)) if data == b"last"[..])
    );
    assert!(matches!(
        events.try_recv(),
        Ok(ExecEvent::Exited { code: 0 })
    ));
    assert!(matches!(
        events.try_recv(),
        Err(mpsc::error::TryRecvError::Disconnected)
    ));
    assert_eq!(bytes.available_permits(), OUTPUT_BYTES);
}

fn request() -> ExecRequest {
    serde_json::from_value(serde_json::json!({"cmd":"fixture-command"})).unwrap()
}

async fn exited(peer: &mut DuplexStream, id: u32, code: i32) {
    codec::write_message(
        peer,
        &Message::with_payload(MessageType::ExecExited, id, &ExecExited { code }).unwrap(),
    )
    .await
    .unwrap();
}

async fn null_request(peer: &mut DuplexStream) -> Message {
    let opening = codec::read_message(peer).await.unwrap();
    assert_eq!(opening.t, MessageType::ExecRequest);
    let eof = timeout(Duration::from_secs(1), codec::read_message(peer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!((eof.id, eof.t), (opening.id, MessageType::ExecStdin));
    assert!(eof.payload::<ExecStdin>().unwrap().data.is_empty());
    opening
}

async fn stdin_error(peer: &mut DuplexStream, id: u32) {
    codec::write_message(
        peer,
        &Message::with_payload(
            MessageType::ExecStdinError,
            id,
            &ExecStdinError {
                errno: Some(32),
                errno_name: Some("EPIPE".into()),
                message: "child closed stdin".into(),
            },
        )
        .unwrap(),
    )
    .await
    .unwrap();
}

async fn terminal(handle: &mut ExecHandle) -> ExecEvent {
    timeout(Duration::from_secs(9), async {
        while let Some(event) = handle.recv().await {
            if matches!(
                event,
                ExecEvent::Exited { .. } | ExecEvent::Failed(_) | ExecEvent::Interrupted(_)
            ) {
                return event;
            }
        }
        panic!("missing terminal event");
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn native_exec_streaming_deadline_preserves_reason_and_observed_exit() {
    let (client, mut peer) = connected().await;
    let mut handle = open(
        client,
        request(),
        StdinMode::Null,
        Some(Duration::from_millis(30)),
    )
    .await
    .unwrap();
    let opening = null_request(&mut peer).await;
    let kill = timeout(Duration::from_secs(1), codec::read_message(&mut peer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(kill.id, opening.id);
    assert_eq!(kill.t, MessageType::ExecSignal);
    assert_eq!(kill.payload::<ExecSignal>().unwrap().signal, 9);
    exited(&mut peer, opening.id, 137).await;
    assert!(matches!(
        terminal(&mut handle).await,
        ExecEvent::Interrupted(ExecInterruption {
            reason: ExecInterruptionReason::Timeout(_),
            termination: ExecTermination::Exited(137),
        })
    ));
    assert!(matches!(
        handle.try_recv(),
        Err(mpsc::error::TryRecvError::Disconnected)
    ));
}

#[tokio::test]
async fn native_exec_transport_loss_is_not_a_successful_exit() {
    let (client, peer) = connected().await;
    let mut handle = open(client, request(), StdinMode::Null, None)
        .await
        .unwrap();
    drop(peer);
    assert!(matches!(
        terminal(&mut handle).await,
        ExecEvent::Interrupted(ExecInterruption {
            reason: ExecInterruptionReason::TransportClosed,
            termination: ExecTermination::Unconfirmed,
        })
    ));
}

#[tokio::test]
async fn native_exec_zero_deadline_refuses_before_request() {
    let (client, mut peer) = connected().await;
    assert!(matches!(
        open(
            client.clone(),
            request(),
            StdinMode::Null,
            Some(Duration::ZERO)
        )
        .await,
        Err(MicrosandboxError::ExecInterrupted(_))
    ));
    assert!(
        timeout(Duration::from_millis(20), codec::read_message(&mut peer))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn native_exec_fixed_stdin_bound_refuses_before_request() {
    let (client, mut peer) = connected().await;
    assert!(matches!(
        open(
            client.clone(),
            request(),
            StdinMode::Bytes(vec![0; INPUT_BYTES + 1]),
            None
        )
        .await,
        Err(MicrosandboxError::InvalidConfig(_))
    ));
    assert!(
        timeout(Duration::from_millis(20), codec::read_message(&mut peer))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn native_exec_slow_consumer_preserves_explicit_overflow_and_other_session() {
    let (client, mut peer) = connected().await;
    let mut slow = open(client.clone(), request(), StdinMode::Null, None)
        .await
        .unwrap();
    let first = null_request(&mut peer).await;
    let mut fast = open(client, request(), StdinMode::Null, None)
        .await
        .unwrap();
    let second = null_request(&mut peer).await;
    for _ in 0..OUTPUT_EVENTS + 1 {
        codec::write_message(
            &mut peer,
            &Message::with_payload(
                MessageType::ExecStdout,
                first.id,
                &ExecStdout { data: vec![1; 64] },
            )
            .unwrap(),
        )
        .await
        .unwrap();
        tokio::task::yield_now().await;
    }
    exited(&mut peer, second.id, 0).await;
    exited(&mut peer, first.id, 137).await;
    assert!(matches!(
        terminal(&mut fast).await,
        ExecEvent::Exited { code: 0 }
    ));
    assert!(matches!(
        terminal(&mut slow).await,
        ExecEvent::Interrupted(ExecInterruption {
            reason: ExecInterruptionReason::OutputLimit,
            termination: ExecTermination::Exited(137),
        })
    ));
}

#[tokio::test]
async fn native_exec_cancel_and_retained_control_do_not_retarget() {
    let (client, mut peer) = connected().await;
    let mut handle = open(client, request(), StdinMode::Pipe, None)
        .await
        .unwrap();
    let opening = codec::read_message(&mut peer).await.unwrap();
    let control = handle.control();
    let retained = control.clone();
    let cancellation = tokio::spawn(async move { control.cancel().await });
    let signal = codec::read_message(&mut peer).await.unwrap();
    assert_eq!((signal.id, signal.t), (opening.id, MessageType::ExecSignal));
    exited(&mut peer, opening.id, 137).await;
    let outcome = cancellation.await.unwrap();
    assert_eq!(outcome.reason, ExecInterruptionReason::Cancelled);
    assert!(matches!(outcome.termination, ExecTermination::Exited(137)));
    assert!(matches!(
        terminal(&mut handle).await,
        ExecEvent::Interrupted(_)
    ));
    assert!(retained.signal(15).await.is_err());
    assert!(handle.take_stdin().unwrap().write(b"stale").await.is_err());
}

#[tokio::test]
async fn native_exec_dropped_receiver_requests_cleanup_without_polling() {
    let (client, mut peer) = connected().await;
    let handle = open(client, request(), StdinMode::Null, None)
        .await
        .unwrap();
    let opening = null_request(&mut peer).await;
    let control = handle.control();
    drop(handle);
    let signal = timeout(Duration::from_secs(1), codec::read_message(&mut peer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(signal.id, opening.id);
    assert_eq!(signal.t, MessageType::ExecSignal);
    exited(&mut peer, opening.id, 137).await;
    assert!(matches!(
        control.cancel().await.termination,
        ExecTermination::Exited(137)
    ));
}

#[tokio::test]
async fn native_exec_cancel_without_terminal_stays_unconfirmed_and_fences_sends() {
    let (client, mut peer) = connected().await;
    let mut handle = open(client, request(), StdinMode::Null, None)
        .await
        .unwrap();
    null_request(&mut peer).await;
    let control = handle.control();
    let retained = control.clone();
    let cancellation = tokio::spawn(async move { control.cancel().await });
    assert_eq!(
        codec::read_message(&mut peer).await.unwrap().t,
        MessageType::ExecSignal
    );
    let result = timeout(CANCEL_TIMEOUT, cancellation)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result.reason, ExecInterruptionReason::Cancelled);
    assert!(matches!(result.termination, ExecTermination::Unconfirmed));
    assert!(retained.signal(15).await.is_err());
    assert!(matches!(
        terminal(&mut handle).await,
        ExecEvent::Interrupted(ExecInterruption {
            reason: ExecInterruptionReason::Cancelled,
            termination: ExecTermination::Unconfirmed,
        })
    ));
}

#[tokio::test]
async fn native_exec_cancellation_during_opening_keeps_owned_cleanup() {
    use tokio::io::AsyncReadExt;
    let (client, mut peer) = connected().await;
    let mut request = request();
    request.args = vec!["x".repeat(128 * 1024)];
    let opening = tokio::spawn(open(client.clone(), request, StdinMode::Null, None));
    let mut header = [0; 9];
    peer.read_exact(&mut header).await.unwrap();
    let length = u32::from_be_bytes(header[..4].try_into().unwrap()) as usize;
    let id = u32::from_be_bytes(header[4..8].try_into().unwrap());
    // The opening frame is larger than the duplex buffer, so this caller is
    // cancelled after enqueue but before write acknowledgement.
    assert!(!opening.is_finished());
    opening.abort();
    let _ = opening.await;
    peer.read_exact(&mut vec![0; length - 5]).await.unwrap();
    let kill = timeout(Duration::from_secs(1), codec::read_message(&mut peer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!((kill.id, kill.t), (id, MessageType::ExecSignal));
    exited(&mut peer, id, 137).await;
}

#[test]
fn native_exec_serialization_keeps_deadline_and_termination_separate() {
    let outcome = ExecInterruption {
        reason: ExecInterruptionReason::Timeout(Duration::from_millis(1500)),
        termination: ExecTermination::Unconfirmed,
    };
    let value = serde_json::to_value(outcome).unwrap();
    assert_eq!(value["reason"]["kind"], "timeout");
    assert_eq!(value["reason"]["value"]["secs"], 1);
    assert_eq!(value["reason"]["value"]["nanos"], 500_000_000);
    assert_eq!(
        value["termination"],
        serde_json::json!({"kind":"unconfirmed"})
    );
}

#[tokio::test]
async fn native_exec_nonblocking_empty_is_not_termination() {
    let (client, mut peer) = connected().await;
    let mut handle = open(client, request(), StdinMode::Null, None)
        .await
        .unwrap();
    let opening = null_request(&mut peer).await;
    assert!(matches!(
        handle.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    exited(&mut peer, opening.id, 3).await;
    assert!(matches!(
        terminal(&mut handle).await,
        ExecEvent::Exited { code: 3 }
    ));
}

#[tokio::test]
async fn native_exec_null_stdin_delivers_eof_before_waiting_for_exit() {
    let (client, mut peer) = connected().await;
    let mut handle = open(client, request(), StdinMode::Null, None)
        .await
        .unwrap();
    assert!(handle.take_stdin().is_none());
    let opening = null_request(&mut peer).await;
    exited(&mut peer, opening.id, 0).await;
    assert!(matches!(
        terminal(&mut handle).await,
        ExecEvent::Exited { code: 0 }
    ));
}

#[tokio::test]
async fn native_exec_fixed_stdin_error_cannot_be_success_even_with_exit_zero() {
    let (client, mut peer) = connected().await;
    let mut handle = open(client, request(), StdinMode::Bytes(b"input".to_vec()), None)
        .await
        .unwrap();
    let opening = codec::read_message(&mut peer).await.unwrap();
    let input = codec::read_message(&mut peer).await.unwrap();
    assert_eq!((input.id, input.t), (opening.id, MessageType::ExecStdin));
    assert_eq!(input.payload::<ExecStdin>().unwrap().data, b"input");
    let eof = codec::read_message(&mut peer).await.unwrap();
    assert_eq!((eof.id, eof.t), (opening.id, MessageType::ExecStdin));
    assert!(eof.payload::<ExecStdin>().unwrap().data.is_empty());
    stdin_error(&mut peer, opening.id).await;
    exited(&mut peer, opening.id, 0).await;
    assert!(matches!(
        terminal(&mut handle).await,
        ExecEvent::Interrupted(ExecInterruption {
            reason: ExecInterruptionReason::Delivery,
            termination: ExecTermination::Exited(0),
        })
    ));
}

#[tokio::test]
async fn native_exec_pipe_stdin_error_remains_nonterminal_and_does_not_send_eof() {
    let (client, mut peer) = connected().await;
    let mut handle = open(client, request(), StdinMode::Pipe, None)
        .await
        .unwrap();
    let opening = codec::read_message(&mut peer).await.unwrap();
    assert!(
        timeout(Duration::from_millis(20), codec::read_message(&mut peer))
            .await
            .is_err()
    );
    stdin_error(&mut peer, opening.id).await;
    assert!(matches!(
        handle.recv().await,
        Some(ExecEvent::StdinError(_))
    ));
    assert!(matches!(
        handle.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    exited(&mut peer, opening.id, 0).await;
    assert!(matches!(
        terminal(&mut handle).await,
        ExecEvent::Exited { code: 0 }
    ));
}

#[test]
fn native_exec_malformed_or_nonterminal_exit_cannot_report_success() {
    assert!(
        decode_frame(RawFrame {
            id: 1,
            flags: FLAG_TERMINAL,
            body: vec![255]
        })
        .is_none()
    );
    let message =
        Message::with_payload(MessageType::ExecExited, 1, &ExecExited { code: 0 }).unwrap();
    let mut body = Vec::new();
    ciborium::into_writer(&message, &mut body).unwrap();
    assert!(
        decode_frame(RawFrame {
            id: 1,
            flags: 0,
            body
        })
        .is_none()
    );
}

#[tokio::test]
async fn native_exec_output_bytes_are_bounded_independently_of_frame_count() {
    let (tx, mut rx) = mpsc::channel(OUTPUT_EVENTS);
    let bytes = Arc::new(Semaphore::new(OUTPUT_BYTES));
    assert!(enqueue(
        &tx,
        &bytes,
        ExecEvent::Stdout(Bytes::from(vec![0; OUTPUT_BYTES]))
    ));
    assert!(!enqueue(
        &tx,
        &bytes,
        ExecEvent::Stdout(Bytes::from_static(b"x"))
    ));
    drop(rx.recv().await.unwrap());
    assert!(enqueue(
        &tx,
        &bytes,
        ExecEvent::Stderr(Bytes::from_static(b"x"))
    ));
}
