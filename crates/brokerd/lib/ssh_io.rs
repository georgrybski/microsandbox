//! Cancellation-aware I/O for owned SSH sessions, including native key exchange.
//!
//! Returning an I/O error wakes the protocol driver; it does not prove that its
//! task has joined. The relay owner must still await the native session handle.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::ssh::TerminationHandle;

type Cancellation = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Each half retains its own wake registration so concurrent reads/writes do
/// not overwrite one another's waker when the SSH library splits this stream.
pub(crate) struct CancellableIo<S> {
    inner: S,
    termination: TerminationHandle,
    read_cancel: Cancellation,
    write_cancel: Cancellation,
}

impl<S> CancellableIo<S> {
    pub(crate) fn new(inner: S, termination: TerminationHandle) -> Self {
        let read = termination.clone();
        Self {
            inner,
            termination: termination.clone(),
            read_cancel: Box::pin(async move { read.terminated().await }),
            write_cancel: Box::pin(async move { termination.terminated().await }),
        }
    }
}

fn cancelled(future: &mut Cancellation, cx: &mut Context<'_>) -> bool {
    future.as_mut().poll(cx).is_ready()
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "SSH relay was cancelled")
}

impl<S: AsyncRead + Unpin> AsyncRead for CancellableIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.termination.is_terminated() || cancelled(&mut self.read_cancel, cx) {
            return Poll::Ready(Err(closed()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CancellableIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.termination.is_terminated() || cancelled(&mut self.write_cancel, cx) {
            return Poll::Ready(Err(closed()));
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.termination.is_terminated() || cancelled(&mut self.write_cancel, cx) {
            return Poll::Ready(Err(closed()));
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.termination.is_terminated() || cancelled(&mut self.write_cancel, cx) {
            return Poll::Ready(Err(closed()));
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn bytes_remain_unchanged_before_cancellation() {
        let (client, mut peer) = tokio::io::duplex(16);
        let mut io = CancellableIo::new(client, TerminationHandle::new());
        io.write_all(b"\x00\xffhello").await.unwrap();
        let mut bytes = [0; 7];
        peer.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"\x00\xffhello");
        peer.write_all(b"back").await.unwrap();
        let mut back = [0; 4];
        io.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"back");
    }

    #[tokio::test]
    async fn cancellation_wakes_both_pending_halves() {
        let (client, _peer) = tokio::io::duplex(1);
        let stop = TerminationHandle::new();
        let (mut read, mut write) = tokio::io::split(CancellableIo::new(client, stop.clone()));
        write.write_all(b"x").await.unwrap();
        let reader = tokio::spawn(async move {
            let mut byte = [0];
            read.read(&mut byte).await
        });
        let writer = tokio::spawn(async move { write.write_all(b"blocked").await });
        tokio::task::yield_now().await;
        stop.terminate();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), reader)
                .await
                .unwrap()
                .unwrap()
                .unwrap_err()
                .kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), writer)
                .await
                .unwrap()
                .unwrap()
                .unwrap_err()
                .kind(),
            io::ErrorKind::ConnectionAborted
        );
    }

    #[tokio::test]
    async fn prior_cancellation_refuses_before_any_write() {
        let (client, mut peer) = tokio::io::duplex(16);
        let stop = TerminationHandle::new();
        stop.terminate();
        let mut io = CancellableIo::new(client, stop);
        assert_eq!(
            io.write_all(b"secret").await.unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert_eq!(
            io.flush().await.unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert_eq!(
            io.shutdown().await.unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        drop(io);
        let mut bytes = Vec::new();
        peer.read_to_end(&mut bytes).await.unwrap();
        assert!(bytes.is_empty());
    }
}
