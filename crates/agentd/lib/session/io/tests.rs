use super::*;
use std::io::Read;

fn pipe() -> (OwnedFd, OwnedFd) {
    let mut fds = [0; 2];
    assert_eq!(
        unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) },
        0
    );
    unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
}

#[test]
fn bounded_exec_refusing_stdin_has_a_real_write_deadline() {
    let (_read, write) = pipe();
    let start = Instant::now();
    let error = write_until(
        write.as_raw_fd(),
        &vec![0; 256 * 1024],
        start + Duration::from_millis(25),
    )
    .unwrap_err();
    assert_eq!(error.raw_os_error(), Some(libc::ETIMEDOUT));
    assert!(start.elapsed() < Duration::from_secs(1));
}

#[tokio::test]
async fn bounded_exec_input_queue_refuses_overflow_and_reserves_ordered_eof() {
    let (_read, write) = pipe();
    let (tx, _rx) = mpsc::unbounded_channel();
    let mut queue = StdinQueue::new(write.as_raw_fd(), false, 1, OutputSender::new(tx)).unwrap();
    for _ in 0..INPUT_BYTES / INPUT_CHUNK {
        queue.enqueue(vec![0; INPUT_CHUNK]).unwrap();
    }
    assert!(queue.enqueue(vec![1]).is_err());
    queue.enqueue(Vec::new()).unwrap();
    assert!(queue.enqueue(vec![1]).is_err());
}

#[tokio::test]
async fn bounded_exec_pipe_eof_follows_accepted_data() {
    let (read, write) = pipe();
    let (tx, _rx) = mpsc::unbounded_channel();
    let mut queue = StdinQueue::new(write.as_raw_fd(), false, 1, OutputSender::new(tx)).unwrap();
    drop(write);
    queue.enqueue(b"first".to_vec()).unwrap();
    queue.enqueue(b"second".to_vec()).unwrap();
    queue.enqueue(Vec::new()).unwrap();
    let result = tokio::task::spawn_blocking(move || {
        let mut file = std::fs::File::from(read);
        let mut result = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let mut bytes = [0; 64];
            match file.read(&mut bytes) {
                Ok(0) => return result,
                Ok(n) => result.extend_from_slice(&bytes[..n]),
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(1))
                }
                Err(e) => panic!("pipe did not close correctly: {e}"),
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(result, b"firstsecond");
}

#[tokio::test]
async fn bounded_exec_pty_eof_remains_noop() {
    let (_read, write) = pipe();
    let (tx, _rx) = mpsc::unbounded_channel();
    let mut queue = StdinQueue::new(write.as_raw_fd(), true, 1, OutputSender::new(tx)).unwrap();
    queue.enqueue(Vec::new()).unwrap();
    queue.enqueue(b"still open".to_vec()).unwrap();
}

#[tokio::test]
async fn bounded_exec_stdin_timeout_is_error_not_exit_and_other_tasks_progress() {
    let (_read, write) = pipe();
    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut queue = StdinQueue::new(write.as_raw_fd(), false, 1, OutputSender::new(tx)).unwrap();
    for _ in 0..INPUT_BYTES / INPUT_CHUNK {
        queue.enqueue(vec![0; INPUT_CHUNK]).unwrap();
    }
    // Dispatch can immediately continue while this child's write is blocked.
    tokio::time::timeout(Duration::from_millis(100), async {
        tokio::task::yield_now().await
    })
    .await
    .unwrap();
    let (_, output) = tokio::time::timeout(Duration::from_secs(3), rx.recv())
        .await
        .unwrap()
        .unwrap();
    let SessionOutput::Raw(output) = output else {
        panic!("write failure is not an exit");
    };
    let message = codec::decode_message_frame(&output.frame).unwrap();
    assert_eq!(message.t, MessageType::ExecStdinError);
    assert_eq!(
        message.payload::<ExecStdinError>().unwrap().errno,
        Some(libc::ETIMEDOUT)
    );
}

#[tokio::test]
async fn bounded_exec_output_backpressure_is_per_session_and_terminal_independent() {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let slow = OutputSender::new(tx.clone());
    let fast = OutputSender::new(tx);
    slow.send(1, vec![0; OUTPUT_BYTES], false).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(20), slow.send(1, vec![1], false))
            .await
            .is_err()
    );
    fast.send(2, vec![2], false).await.unwrap();
    fast.exited(2, 0);
    slow.exited(1, 137);
    let mut ids = Vec::new();
    for _ in 0..4 {
        ids.push(rx.recv().await.unwrap().0);
    }
    assert_eq!(ids, [1, 2, 2, 1]);
    assert!(slow.send(1, vec![3], false).await.is_err());
}

#[tokio::test]
async fn bounded_exec_output_frame_count_is_also_bounded() {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let sender = OutputSender::new(tx);
    for _ in 0..OUTPUT_MESSAGES {
        sender.send(1, vec![1], false).await.unwrap();
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(20), sender.send(1, vec![1], false))
            .await
            .is_err()
    );
    drop(rx.recv().await.unwrap());
    sender.send(1, vec![1], false).await.unwrap();
}

#[tokio::test]
async fn bounded_exec_late_stdin_error_cannot_follow_terminal_or_reused_id() {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let sender = OutputSender::new(tx);
    sender.exited(7, 0);
    sender.stdin_error(
        7,
        &ExecStdinError {
            errno: Some(libc::EPIPE),
            errno_name: None,
            message: "late".into(),
        },
    );
    assert!(matches!(
        rx.recv().await.unwrap(),
        (7, SessionOutput::Exited(0))
    ));
    assert!(matches!(
        rx.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
}
