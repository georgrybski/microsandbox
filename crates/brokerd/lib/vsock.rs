//! Guest-side vsock stream transport.
//!
//! brokerd speaks vsock directly through `AF_VSOCK` sockets: it LISTENs on
//! the divert port for host-injected streams and dials the egress port on
//! `VMADDR_CID_HOST` for upstream tunnels. The host-side route backends in
//! `crates/vsock` cannot be reused here — they implement the host end of
//! libkrun routes, while this module is the guest end over raw sockets.
//!
//! Socket creation is synchronous and blocking; accepted and connected
//! streams are wrapped in [`tokio::io::unix::AsyncFd`] so the async broker
//! loop can drive them. vsock availability itself is environment-gated
//! (no vsock device exists outside a VM), so this module is compile-checked
//! everywhere and exercised only where vsock exists.

use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::ReadBuf;
use tokio::io::unix::AsyncFd;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Well-known host CID for guest-to-host dials.
pub const VMADDR_CID_HOST: u32 = 2;

/// Listen backlog for the divert port.
const LISTEN_BACKLOG: i32 = 64;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A bound vsock listener on one guest port.
pub struct VsockListener {
    /// Nonblocking listen socket wrapped for async accept readiness.
    inner: AsyncFd<OwnedFd>,
}

/// One connected vsock byte stream.
pub struct VsockStream {
    /// Nonblocking connected socket wrapped for async readiness.
    inner: AsyncFd<OwnedFd>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl VsockListener {
    /// Bind `CID_ANY` on `port` and start listening for host-injected streams.
    pub fn bind(port: u32) -> io::Result<Self> {
        let fd = vsock_socket()?;
        let addr = sockaddr_vm(libc::VMADDR_CID_ANY, port);
        let ret = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &addr as *const libc::sockaddr_vm as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
            )
        };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { libc::listen(fd.as_raw_fd(), LISTEN_BACKLOG) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            inner: AsyncFd::new(fd)?,
        })
    }

    /// Accept the next divert stream only when its kernel-reported peer is
    /// `VMADDR_CID_HOST`. A prelude cannot assert authority for this hop.
    pub async fn accept(&self) -> io::Result<VsockStream> {
        loop {
            let mut guard = self.inner.readable().await?;
            match guard.try_io(|inner| accept_one(inner.as_raw_fd())) {
                Ok(Ok(fd)) => {
                    return Ok(VsockStream {
                        inner: AsyncFd::new(fd)?,
                    });
                }
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => continue,
            }
        }
    }
}

impl VsockStream {
    /// Dial `port` on the host (`VMADDR_CID_HOST`).
    pub async fn connect(port: u32) -> io::Result<Self> {
        let fd = vsock_socket()?;
        let addr = sockaddr_vm(VMADDR_CID_HOST, port);
        let ret = unsafe {
            libc::connect(
                fd.as_raw_fd(),
                &addr as *const libc::sockaddr_vm as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
            )
        };
        if ret == 0 {
            return Ok(Self {
                inner: AsyncFd::new(fd)?,
            });
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(err);
        }
        let stream = Self {
            inner: AsyncFd::new(fd)?,
        };
        stream.inner.writable().await?.clear_ready();
        if connect_completed(stream.inner.as_raw_fd())? {
            Ok(stream)
        } else {
            // The writable readiness was spurious; keep waiting for the
            // connection to complete or fail.
            loop {
                let mut guard = stream.inner.writable().await?;
                match guard.try_io(|_| connect_completed(stream.inner.as_raw_fd())) {
                    Ok(Ok(true)) => return Ok(stream),
                    Ok(Ok(false)) => continue,
                    Ok(Err(e)) => return Err(e),
                    Err(_would_block) => continue,
                }
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl tokio::io::AsyncRead for VsockStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut guard = std::task::ready!(self.inner.poll_read_ready(cx))?;
            let unfilled = buf.initialize_unfilled();
            match guard
                .try_io(|inner| recv_one(inner.as_raw_fd(), unfilled.as_mut_ptr(), unfilled.len()))
            {
                Ok(Ok(0)) => return Poll::Ready(Ok(())),
                Ok(Ok(n)) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                Err(_would_block) => continue,
            }
        }
    }
}

impl tokio::io::AsyncWrite for VsockStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = std::task::ready!(self.inner.poll_write_ready(cx))?;
            match guard.try_io(|inner| send_one(inner.as_raw_fd(), buf)) {
                Ok(Ok(n)) => return Poll::Ready(Ok(n)),
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let ret = unsafe { libc::shutdown(self.inner.as_raw_fd(), libc::SHUT_RDWR) };
        if ret != 0 {
            return Poll::Ready(Err(io::Error::last_os_error()));
        }
        Poll::Ready(Ok(()))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Create one nonblocking `AF_VSOCK` stream socket.
fn vsock_socket() -> io::Result<OwnedFd> {
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a freshly created socket owned by this function.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    set_nonblocking(&owned)?;
    Ok(owned)
}

/// Build a vsock socket address for `cid` and `port`.
fn sockaddr_vm(cid: u32, port: u32) -> libc::sockaddr_vm {
    let mut addr: libc::sockaddr_vm = unsafe { mem::zeroed() };
    addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
    addr.svm_cid = cid;
    addr.svm_port = port;
    addr
}

/// Accept one pending connection and verify host origin before reading bytes.
fn accept_one(listen_fd: i32) -> io::Result<OwnedFd> {
    let mut peer: libc::sockaddr_vm = unsafe { mem::zeroed() };
    let mut peer_len = mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t;
    // SAFETY: both output pointers refer to writable storage of the supplied
    // length. The returned address comes from the kernel, not the peer payload.
    let fd = unsafe {
        libc::accept(
            listen_fd,
            &mut peer as *mut libc::sockaddr_vm as *mut libc::sockaddr,
            &mut peer_len,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a freshly accepted socket owned by this function.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    validate_host_peer(&peer, peer_len)?;
    set_nonblocking(&owned)?;
    Ok(owned)
}

/// Authorize the immediate transport peer, not the original workload identity.
/// The latter must still be verified against host-installed instance policy.
fn validate_host_peer(peer: &libc::sockaddr_vm, len: libc::socklen_t) -> io::Result<()> {
    if len as usize != mem::size_of::<libc::sockaddr_vm>()
        || peer.svm_family != libc::AF_VSOCK as libc::sa_family_t
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "broker divert peer is not a complete vsock address",
        ));
    }
    if peer.svm_cid != VMADDR_CID_HOST {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("broker divert requires host CID, received {}", peer.svm_cid),
        ));
    }
    Ok(())
}

/// Check a nonblocking connect for completion via `SO_ERROR`.
fn connect_completed(fd: i32) -> io::Result<bool> {
    let mut err: libc::c_int = 0;
    let mut len = mem::size_of::<libc::c_int>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            &mut err as *mut libc::c_int as *mut libc::c_void,
            &mut len,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    if err == 0 {
        Ok(true)
    } else if err == libc::EINPROGRESS {
        Ok(false)
    } else {
        Err(io::Error::from_raw_os_error(err))
    }
}

/// Read up to `len` bytes from a nonblocking socket.
fn recv_one(fd: i32, buf: *mut u8, len: usize) -> io::Result<usize> {
    let n = unsafe { libc::recv(fd, buf as *mut libc::c_void, len, libc::MSG_DONTWAIT) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

/// Write bytes to a nonblocking socket without raising `SIGPIPE`.
fn send_one(fd: i32, buf: &[u8]) -> io::Result<usize> {
    let n = unsafe {
        libc::send(
            fd,
            buf.as_ptr() as *const libc::c_void,
            buf.len(),
            libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
        )
    };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

/// Put a socket into nonblocking mode.
fn set_nonblocking(fd: &OwnedFd) -> io::Result<()> {
    let raw = fd.as_raw_fd();
    let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::os::unix::net::{UnixListener, UnixStream};

    use super::*;

    #[test]
    fn only_complete_kernel_host_addresses_are_accepted() {
        let size = mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t;
        for cid in [0, 1, VMADDR_CID_HOST, 3, 65_536, u32::MAX] {
            for len in [0, size - 1, size, size + 1] {
                for family in [libc::AF_UNSPEC, libc::AF_UNIX, libc::AF_VSOCK] {
                    let mut peer = sockaddr_vm(cid, 4000);
                    peer.svm_family = family as libc::sa_family_t;
                    assert_eq!(
                        validate_host_peer(&peer, len).is_ok(),
                        cid == VMADDR_CID_HOST && len == size && family == libc::AF_VSOCK,
                        "cid={cid}, len={len}, family={family}"
                    );
                }
            }
        }
    }

    #[test]
    fn non_host_peer_is_a_permission_denial() {
        let peer = sockaddr_vm(65_536, 4000);
        let error = validate_host_peer(
            &peer,
            mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn accept_rejects_wrong_transport_before_returning_a_stream() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wrong-transport.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let mut client = UnixStream::connect(&path).unwrap();
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        assert_eq!(
            accept_one(listener.as_raw_fd()).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let mut byte = [0];
        assert_eq!(std::io::Read::read(&mut client, &mut byte).unwrap(), 0);
    }
}
