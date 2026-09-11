//! In-process transport/routing controls; no guest or host child process.

use super::*;
use microsandbox_protocol::core::Ready;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

fn frame(message: Message) -> RawFrame {
    let mut bytes = Vec::new();
    codec::encode_to_buf(&message, &mut bytes).unwrap();
    try_extract_frame(&mut BytesMut::from(bytes.as_slice())).unwrap()
}

fn exited(id: u32) -> RawFrame {
    frame(Message::with_payload(MessageType::ExecExited, id, &ExecExited { code: 0 }).unwrap())
}

#[tokio::test]
async fn bounded_relay_terminal_requires_exact_exec_type_and_id() {
    let (output, mut receiver, _) = ClientOutput::new();
    let mut client = ClientState::new(output);
    assert!(client.start_exec(7));
    client.output.close();
    client.writer_finished = true;
    client.cleanup_finished = true;
    let clients = Mutex::new(HashMap::from([(0, client)]));
    let slots = Mutex::new(HashSet::from([0]));
    let registry = std::sync::Mutex::new(HashMap::new());
    let mut unrelated = Message::with_payload(MessageType::Ready, 7, &Ready::default()).unwrap();
    unrelated.flags |= FLAG_TERMINAL;
    let malformed = Message::with_payload(MessageType::ExecExited, 7, &()).unwrap();
    for refused in [exited(8), frame(unrelated), frame(malformed)] {
        route_client_frame(refused, &clients, &slots, &registry).await;
        assert!(slots.lock().await.contains(&0));
        assert!(clients.lock().await[&0].active_sessions.contains(&7));
    }
    assert!(
        receiver.try_recv().is_err(),
        "closed transport must not receive late output"
    );
    route_client_frame(exited(7), &clients, &slots, &registry).await;
    assert!(slots.lock().await.is_empty());
    assert!(clients.lock().await.is_empty());
}

#[tokio::test]
async fn bounded_relay_terminal_does_not_bypass_unfinished_local_cleanup() {
    let (output, _receiver, _) = ClientOutput::new();
    let mut client = ClientState::new(output);
    assert!(client.start_exec(7));
    client.output.close();
    let clients = Mutex::new(HashMap::from([(0, client)]));
    let slots = Mutex::new(HashSet::from([0]));
    let registry = std::sync::Mutex::new(HashMap::new());
    route_client_frame(exited(7), &clients, &slots, &registry).await;
    assert!(slots.lock().await.contains(&0));
    clients.lock().await.get_mut(&0).unwrap().cleanup_finished = true;
    release_finished_slot(0, &clients, &slots).await;
    assert!(slots.lock().await.contains(&0));
    clients.lock().await.get_mut(&0).unwrap().writer_finished = true;
    release_finished_slot(0, &clients, &slots).await;
    assert!(slots.lock().await.is_empty());
}

#[tokio::test]
async fn bounded_relay_confirmed_cleanup_allows_more_than_lifetime_slot_count() {
    let clients = Mutex::new(HashMap::new());
    let slots = Mutex::new(HashSet::new());
    for _ in 0..AGENT_RELAY_MAX_CLIENTS + 2 {
        let (output, _receiver, _) = ClientOutput::new();
        let mut client = ClientState::new(output);
        client.output.close();
        client.cleanup_finished = true;
        client.writer_finished = true;
        clients.lock().await.insert(0, client);
        slots.lock().await.insert(0);
        release_finished_slot(0, &clients, &slots).await;
        assert!(clients.lock().await.is_empty());
        assert!(slots.lock().await.is_empty());
    }
}

#[tokio::test]
async fn bounded_relay_stalled_socket_closes_without_stalling_other_route() {
    let (slow, receiver, cancelled) = ClientOutput::new();
    let (fast, mut fast_receiver, _) = ClientOutput::new();
    let clients = Arc::new(Mutex::new(HashMap::from([
        (0, ClientState::new(slow)),
        (1, ClientState::new(fast)),
    ])));
    let slots = Arc::new(Mutex::new(HashSet::from([0, 1])));
    let registry = std::sync::Mutex::new(HashMap::new());
    let (writer, _unread_peer) = tokio::io::duplex(8);
    let mut task = tokio::spawn(client_writer_task(
        0,
        writer,
        receiver,
        cancelled,
        clients.clone(),
        slots.clone(),
    ));
    for _ in 0..66 {
        if !clients.lock().await[&0]
            .output
            .try_send(Bytes::from(vec![0; 64 * 1024]))
        {
            break;
        }
    }
    assert!(clients.lock().await[&0].output.is_closed());
    let expected = exited(AGENT_RELAY_ID_RANGE_STEP + 1);
    let bytes = expected.data.clone();
    tokio::time::timeout(
        Duration::from_secs(1),
        route_client_frame(expected, &clients, &slots, &registry),
    )
    .await
    .unwrap();
    assert_eq!(fast_receiver.recv().await.unwrap().bytes, bytes);
    tokio::time::timeout(Duration::from_secs(1), &mut task)
        .await
        .unwrap()
        .unwrap();
    assert!(clients.lock().await[&0].writer_finished);
    assert!(
        slots.lock().await.contains(&0),
        "reader cleanup has not been established"
    );
}

#[tokio::test]
async fn bounded_relay_large_frame_spans_turns_without_corruption_or_loss() {
    let shared = ConsoleSharedState::with_capacity(1);
    let (output, mut receiver, _) = ClientOutput::new();
    let clients = Mutex::new(HashMap::from([(0, ClientState::new(output))]));
    let slots = Mutex::new(HashSet::from([0]));
    let registry = std::sync::Mutex::new(HashMap::new());
    let expected = frame(
        Message::with_payload(
            MessageType::ExecStdout,
            7,
            &ExecStdout {
                data: vec![b'x'; MAX_FRAME_SIZE as usize - 128].into(),
            },
        )
        .unwrap(),
    );
    shared.tx_ring.push(expected.data.to_vec()).unwrap();
    let (mut buf, mut pending) = (BytesMut::new(), Bytes::new());
    let mut total = 0;
    loop {
        let read = drain_guest_turn(
            &shared,
            &mut buf,
            &mut pending,
            &clients,
            &slots,
            None,
            &registry,
        )
        .await;
        assert!(read <= GUEST_TURN_BYTES);
        assert!(buf.len() <= MAX_FRAME_SIZE as usize + LEN_PREFIX_SIZE);
        total += read;
        if let Ok(actual) = receiver.try_recv() {
            assert_eq!(actual.bytes, expected.data);
            break;
        }
        assert!(read > 0);
    }
    assert_eq!(total, expected.data.len());
    assert!(buf.is_empty() && pending.is_empty() && shared.tx_ring.is_empty());
}

struct Producer {
    stopped: Arc<AtomicBool>,
    task: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Producer {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        self.task.take().unwrap().join().unwrap();
    }
}

#[tokio::test]
async fn bounded_relay_continuous_producer_cannot_extend_one_turn() {
    let shared = Arc::new(ConsoleSharedState::with_capacity(64));
    let encoded =
        frame(Message::with_payload(MessageType::Ready, 1, &Ready::default()).unwrap()).data;
    let chunk = encoded.repeat(GUEST_DECODE_SLICE / encoded.len());
    for _ in 0..64 {
        shared.tx_ring.push(chunk.clone()).unwrap();
    }
    let stopped = Arc::new(AtomicBool::new(false));
    let producer = Producer {
        stopped: stopped.clone(),
        task: Some(std::thread::spawn({
            let shared = shared.clone();
            move || {
                while !stopped.load(Ordering::Acquire) {
                    let _ = shared.tx_ring.push(chunk.clone());
                    std::thread::yield_now();
                }
            }
        })),
    };
    let clients = Mutex::new(HashMap::new());
    let slots = Mutex::new(HashSet::new());
    let registry = std::sync::Mutex::new(HashMap::new());
    let (mut buf, mut pending) = (BytesMut::new(), Bytes::new());
    let read = tokio::time::timeout(
        Duration::from_secs(1),
        drain_guest_turn(
            &shared,
            &mut buf,
            &mut pending,
            &clients,
            &slots,
            None,
            &registry,
        ),
    )
    .await
    .unwrap();
    drop(producer);
    assert_eq!(read, GUEST_TURN_BYTES);
    assert!(!shared.tx_ring.is_empty());
    assert!(buf.len() <= MAX_FRAME_SIZE as usize + LEN_PREFIX_SIZE);
}

#[tokio::test]
async fn bounded_relay_cleanup_submission_preserves_exact_ids_and_order() {
    let (sender, mut receiver) = mpsc::channel(4);
    submit_disconnect_cleanup(&sender, &HashSet::from([7]), 1, 9)
        .await
        .unwrap();
    let kill = decode_frame(&receiver.recv().await.unwrap()).unwrap();
    assert_eq!((kill.id, kill.t), (7, MessageType::ExecSignal));
    assert_eq!(kill.payload::<ExecSignal>().unwrap().signal, 9);
    let disconnected = decode_frame(&receiver.recv().await.unwrap()).unwrap();
    assert_eq!(disconnected.t, MessageType::RelayClientDisconnected);
    let range = disconnected.payload::<RelayClientDisconnected>().unwrap();
    assert_eq!((range.id_start, range.id_end_exclusive), (1, 9));
    drop(receiver);
    assert!(
        submit_disconnect_cleanup(&sender, &HashSet::new(), 1, 9)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn bounded_relay_disconnect_keeps_range_until_exact_terminal_after_both_tasks() {
    let (output, receiver, writer_cancelled) = ClientOutput::new();
    let reader_cancelled = output.subscribe();
    let clients = Arc::new(Mutex::new(HashMap::from([(0, ClientState::new(output))])));
    let slots = Arc::new(Mutex::new(HashSet::from([0])));
    let (stream, mut peer) = tokio::io::duplex(4096);
    let (reader, writer) = tokio::io::split(stream);
    let (sender, mut commands) = mpsc::channel(4);
    let (drain, _drain_rx) = mpsc::channel(1);
    let registry = Arc::new(std::sync::Mutex::new(HashMap::new()));
    let mut output_task = tokio::spawn(client_writer_task(
        0,
        writer,
        receiver,
        writer_cancelled,
        clients.clone(),
        slots.clone(),
    ));
    let mut input_task = tokio::spawn(client_reader_task(
        0,
        reader,
        sender,
        clients.clone(),
        slots.clone(),
        drain,
        registry.clone(),
        Arc::new(AtomicU64::new(1)),
        1,
        10,
        reader_cancelled,
    ));
    let request: ExecRequest =
        serde_json::from_value(serde_json::json!({"cmd":"not-executed"})).unwrap();
    codec::write_message(
        &mut peer,
        &Message::with_payload(MessageType::ExecRequest, 7, &request).unwrap(),
    )
    .await
    .unwrap();
    let opening = decode_frame(&commands.recv().await.unwrap()).unwrap();
    assert_eq!((opening.id, opening.t), (7, MessageType::ExecRequest));
    drop(peer);
    tokio::time::timeout(Duration::from_secs(1), &mut input_task)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), &mut output_task)
        .await
        .unwrap()
        .unwrap();
    let kill = decode_frame(&commands.recv().await.unwrap()).unwrap();
    assert_eq!((kill.id, kill.t), (7, MessageType::ExecSignal));
    assert_eq!(kill.payload::<ExecSignal>().unwrap().signal, 9);
    assert_eq!(
        decode_frame(&commands.recv().await.unwrap()).unwrap().t,
        MessageType::RelayClientDisconnected
    );
    assert!(slots.lock().await.contains(&0));
    assert!(clients.lock().await[&0].active_sessions.contains(&7));
    route_client_frame(exited(7), &clients, &slots, &registry).await;
    assert!(slots.lock().await.is_empty());
    assert!(clients.lock().await.is_empty());
}

#[tokio::test]
async fn bounded_relay_no_log_retires_only_matching_exec_registry_entries() {
    let shared = ConsoleSharedState::with_capacity(1);
    let (output, mut receiver, _) = ClientOutput::new();
    let clients = Mutex::new(HashMap::from([(0, ClientState::new(output))]));
    let slots = Mutex::new(HashSet::from([0]));
    let registry = std::sync::Mutex::new(HashMap::new());
    let (mut buf, mut pending) = (BytesMut::new(), Bytes::new());
    // More completed sessions than the concurrent cap must not accumulate
    // log metadata when this relay has no log writer.
    for id in 1..=130 {
        assert!(clients.lock().await.get_mut(&0).unwrap().start_exec(id));
        registry.lock().unwrap().insert(
            id,
            SessionInfo {
                session_id: u64::from(id),
                is_pty: false,
            },
        );
        let mut unrelated =
            Message::with_payload(MessageType::Ready, id, &Ready::default()).unwrap();
        unrelated.flags |= FLAG_TERMINAL;
        let malformed = Message::with_payload(MessageType::ExecExited, id, &()).unwrap();
        for refused in [frame(unrelated), frame(malformed), exited(id + 1)] {
            shared.tx_ring.push(refused.data.to_vec()).unwrap();
            drain_guest_turn(
                &shared,
                &mut buf,
                &mut pending,
                &clients,
                &slots,
                None,
                &registry,
            )
            .await;
            drop(receiver.try_recv().unwrap());
            assert_eq!(registry.lock().unwrap().len(), 1);
            assert!(registry.lock().unwrap().contains_key(&id));
            assert!(clients.lock().await[&0].active_sessions.contains(&id));
        }
        let terminal = if id % 2 == 0 {
            let failed: ExecFailed = serde_json::from_value(serde_json::json!({
                "kind": "other", "message": "fixture spawn failure"
            }))
            .unwrap();
            frame(Message::with_payload(MessageType::ExecFailed, id, &failed).unwrap())
        } else {
            exited(id)
        };
        shared.tx_ring.push(terminal.data.to_vec()).unwrap();
        drain_guest_turn(
            &shared,
            &mut buf,
            &mut pending,
            &clients,
            &slots,
            None,
            &registry,
        )
        .await;
        drop(receiver.try_recv().unwrap());
        assert!(registry.lock().unwrap().is_empty());
        assert!(clients.lock().await[&0].active_sessions.is_empty());
        assert!(slots.lock().await.contains(&0));
        assert!(buf.is_empty() && pending.is_empty() && shared.tx_ring.is_empty());
    }
}
