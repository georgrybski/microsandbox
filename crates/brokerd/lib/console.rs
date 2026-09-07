//! Agent console access: bootstrap receipt over virtio-serial.
//!
//! brokerd follows agentd's early-boot pattern: mount only what console
//! discovery needs, open the `agent` virtio-serial port once, and receive
//! the typed bootstrap frame the host queued before entering the VM. The
//! same descriptor is later handed to the async broker loop, which keeps
//! serving epoch provisions on it.

use std::fs::{self, File, OpenOptions};
use std::path::PathBuf;
use std::time::Instant;

use microsandbox_protocol::bootstrap::GuestBootstrap;
use microsandbox_protocol::codec::MAX_FRAME_SIZE;
use microsandbox_protocol::message::{Message, MessageType};

use crate::error::{BrokerError, BrokerResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Sysfs directory listing virtio-serial ports.
const VIRTIO_PORTS_PATH: &str = "/sys/class/virtio-ports";

/// Maximum time to wait for the bootstrap frame.
const BOOTSTRAP_TIMEOUT_SECS: u64 = 60;

/// Read chunk size for the blocking boot handshake.
const BOOT_READ_BUF_SIZE: usize = 4096;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Buffered console input retained across the bootstrap handshake.
///
/// A single device read may contain multiple frames, so later phases must
/// share this buffer instead of dropping bytes after the bootstrap frame.
#[derive(Default)]
pub struct BootConsole {
    /// Bytes read from the console but not yet decoded.
    pub input: Vec<u8>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Discover the device path for a virtio-serial port by name.
pub fn find_console_port(name: &str) -> BrokerResult<PathBuf> {
    let entries = fs::read_dir(VIRTIO_PORTS_PATH)
        .map_err(|e| BrokerError::Console(format!("cannot read {VIRTIO_PORTS_PATH}: {e}")))?;
    for entry in entries {
        let entry = entry.map_err(|e| BrokerError::Console(format!("read port entry: {e}")))?;
        let name_file = entry.path().join("name");
        if let Ok(port_name) = fs::read_to_string(&name_file)
            && port_name.trim() == name
        {
            return Ok(PathBuf::from("/dev").join(entry.file_name()));
        }
    }
    Err(BrokerError::Console(format!(
        "no virtio port with name '{name}' found"
    )))
}

/// Open the agent virtio-serial port once for boot and the broker loop.
///
/// Virtio-console multiport devices only allow a single open; a second
/// open returns `EBUSY`, so this descriptor is shared by every phase.
pub fn open_agent_port() -> BrokerResult<File> {
    let port_path = find_console_port(microsandbox_protocol::AGENT_PORT_NAME)?;
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(&port_path)
        .map_err(|e| BrokerError::Console(format!("open {}: {e}", port_path.display())))
}

/// Receive and validate the first host-to-guest bootstrap frame.
pub fn receive_bootstrap(port_file: &File) -> BrokerResult<(GuestBootstrap, BootConsole)> {
    let fd = std::os::fd::AsRawFd::as_raw_fd(port_file);
    set_nonblocking(fd)?;
    let deadline = Instant::now() + std::time::Duration::from_secs(BOOTSTRAP_TIMEOUT_SECS);
    let mut console = BootConsole::default();
    let msg = read_boot_message(fd, &mut console, deadline)?;
    if msg.id != 0 || msg.flags != 0 {
        return Err(BrokerError::Bootstrap(format!(
            "guest bootstrap requires id=0 and flags=0, got id={} flags={}",
            msg.id, msg.flags
        )));
    }
    if msg.t != MessageType::Bootstrap {
        return Err(BrokerError::Bootstrap(format!(
            "expected core.bootstrap as first console frame, got {}",
            msg.t.as_str()
        )));
    }
    let min_version = MessageType::Bootstrap.min_protocol_version();
    if msg.v < min_version {
        return Err(BrokerError::Bootstrap(format!(
            "guest bootstrap requires protocol generation {min_version} or newer, got {}",
            msg.v
        )));
    }
    let bootstrap = msg
        .payload::<GuestBootstrap>()
        .map_err(|e| BrokerError::Bootstrap(format!("decode guest bootstrap payload: {e}")))?;
    Ok((bootstrap, console))
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

fn read_boot_message(
    fd: i32,
    console: &mut BootConsole,
    deadline: Instant,
) -> BrokerResult<Message> {
    use microsandbox_protocol::codec;
    let mut read_buf = [0u8; BOOT_READ_BUF_SIZE];
    loop {
        if let Some(msg) = codec::try_decode_from_buf(&mut console.input)
            .map_err(|e| BrokerError::Bootstrap(format!("decode guest bootstrap: {e}")))?
        {
            return Ok(msg);
        }
        if console.input.len() > MAX_FRAME_SIZE as usize + 4 {
            return Err(BrokerError::Bootstrap(
                "serial input buffer exceeded maximum size while waiting for bootstrap".to_string(),
            ));
        }
        if !poll_fd_until(fd, libc::POLLIN, deadline)? {
            return Err(BrokerError::Bootstrap(
                "timed out waiting for guest bootstrap".to_string(),
            ));
        }
        match read_from_fd(fd, &mut read_buf) {
            Ok(0) => {
                return Err(BrokerError::Bootstrap(
                    "serial port closed while waiting for guest bootstrap".to_string(),
                ));
            }
            Ok(n) => console.input.extend_from_slice(&read_buf[..n]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                ) => {}
            Err(error) => return Err(BrokerError::Console(error.to_string())),
        }
    }
}

fn set_nonblocking(fd: i32) -> BrokerResult<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(BrokerError::Console(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(BrokerError::Console(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    Ok(())
}

fn poll_fd_until(fd: i32, events: i16, deadline: Instant) -> BrokerResult<bool> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(false);
        }
        let timeout_ms = remaining.as_millis().min(i32::MAX as u128) as i32;
        let timeout_ms = timeout_ms.max(1);
        let mut pfd = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let ret = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if ret > 0 {
            return Ok(true);
        }
        if ret == 0 {
            return Ok(false);
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return Err(BrokerError::Console(err.to_string()));
    }
}

fn read_from_fd(fd: i32, buf: &mut [u8]) -> std::io::Result<usize> {
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}
