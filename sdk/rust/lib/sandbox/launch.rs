//! Host-owned identity of one local runtime incarnation.

use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One runtime incarnation, scoped to the backend that issued it.
///
/// Unlike [`super::SandboxId`], this changes on stop/start. It is an observation
/// of host-owned state, not a credential or a guest-provided assertion. Keep the
/// originating backend with it; database row numbers are not globally unique.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SandboxLaunchId([u8; 32]);

/// Backend-private run metadata with optional platform-specific binding proof.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalLaunch {
    pub(crate) sandbox_id: i32,
    pub(crate) run_id: i32,
    pub(crate) pid: i32,
    pub(crate) identity: Option<SandboxLaunchId>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SandboxLaunchId {
    /// Canonical, version-domain-separated SHA-256 projection of host evidence.
    ///
    /// Suitable for comparison or a backend-scoped reference, not authorization.
    /// Contains no socket address or guest-supplied data.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl LocalLaunch {
    pub(crate) fn capture(
        backend: &crate::backend::LocalBackend,
        sandbox_id: i32,
        run_id: i32,
        pid: i32,
    ) -> Self {
        Self {
            sandbox_id,
            run_id,
            pid,
            identity: capture_identity(backend, sandbox_id, run_id, pid).ok(),
        }
    }

    pub(crate) fn ensure_current(
        self,
        name: &str,
        current: Option<Self>,
    ) -> MicrosandboxResult<()> {
        self.identity
            .ok_or(MicrosandboxError::LaunchBindingUnsupported)?;
        if current == Some(self) {
            return Ok(());
        }
        Err(MicrosandboxError::SandboxLaunchChanged {
            name: name.to_owned(),
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn capture_identity(
    backend: &crate::backend::LocalBackend,
    sandbox_id: i32,
    run_id: i32,
    pid: i32,
) -> MicrosandboxResult<SandboxLaunchId> {
    use std::io::Read;

    fn bounded(path: &str) -> MicrosandboxResult<String> {
        let mut text = String::new();
        std::fs::File::open(path)?
            .take(4097)
            .read_to_string(&mut text)?;
        if text.len() > 4096 {
            return Err(MicrosandboxError::LaunchBindingUnsupported);
        }
        Ok(text)
    }

    let (device, inode) = backend.launch_database_identity()?;
    let boot = bounded("/proc/sys/kernel/random/boot_id")?;
    let boot = boot.trim();
    if boot.len() != 36
        || !boot.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
    {
        return Err(MicrosandboxError::LaunchBindingUnsupported);
    }
    let start = process_start(&bounded(&format!("/proc/{pid}/stat"))?, pid)?;
    Ok(project_identity(
        device, inode, sandbox_id, run_id, pid, boot, start,
    ))
}

#[cfg(target_os = "linux")]
fn project_identity(
    device: u64,
    inode: u64,
    sandbox_id: i32,
    run_id: i32,
    pid: i32,
    boot: &str,
    start: u64,
) -> SandboxLaunchId {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"microsandbox-local-launch-v1\0");
    hash.update(device.to_be_bytes());
    hash.update(inode.to_be_bytes());
    hash.update(sandbox_id.to_be_bytes());
    hash.update(run_id.to_be_bytes());
    hash.update(pid.to_be_bytes());
    hash.update(boot.to_ascii_lowercase().as_bytes());
    hash.update(start.to_be_bytes());
    SandboxLaunchId(hash.finalize().into())
}

#[cfg(target_os = "linux")]
fn process_start(stat: &str, expected_pid: i32) -> MicrosandboxResult<u64> {
    let (prefix, fields) = stat
        .rsplit_once(')')
        .ok_or(MicrosandboxError::LaunchBindingUnsupported)?;
    let pid = prefix
        .split_once(' ')
        .and_then(|(pid, _)| pid.parse::<i32>().ok());
    let fields: Vec<_> = fields.split_whitespace().collect();
    if pid != Some(expected_pid)
        || !matches!(
            fields.first().copied(),
            Some("R" | "S" | "D" | "T" | "t" | "I" | "K" | "P")
        )
    {
        return Err(MicrosandboxError::LaunchBindingUnsupported);
    }
    fields
        .get(19)
        .and_then(|start| start.parse().ok())
        .ok_or(MicrosandboxError::LaunchBindingUnsupported)
}

#[cfg(not(target_os = "linux"))]
fn capture_identity(
    _backend: &crate::backend::LocalBackend,
    _sandbox_id: i32,
    _run_id: i32,
    _pid: i32,
) -> MicrosandboxResult<SandboxLaunchId> {
    Err(MicrosandboxError::LaunchBindingUnsupported)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::{process_start, project_identity};

    #[test]
    fn launch_identity_projection_distinguishes_all_host_fields() {
        let base = project_identity(1, 2, 3, 4, 5, "boot-a", 6);
        for other in [
            project_identity(2, 2, 3, 4, 5, "boot-a", 6),
            project_identity(1, 3, 3, 4, 5, "boot-a", 6),
            project_identity(1, 2, 4, 4, 5, "boot-a", 6),
            project_identity(1, 2, 3, 5, 5, "boot-a", 6),
            project_identity(1, 2, 3, 4, 6, "boot-a", 6),
            project_identity(1, 2, 3, 4, 5, "boot-b", 6),
            project_identity(1, 2, 3, 4, 5, "boot-a", 7),
        ] {
            assert_ne!(base.as_bytes(), other.as_bytes());
        }
        assert_eq!(
            base.as_bytes(),
            project_identity(1, 2, 3, 4, 5, "BOOT-A", 6).as_bytes()
        );
    }

    #[test]
    fn launch_identity_process_parser_handles_command_spaces_and_parentheses() {
        let stat = format!("123 (a process ) name) S {} 987 0", vec!["0"; 18].join(" "));
        assert_eq!(process_start(&stat, 123).unwrap(), 987);
        assert!(process_start(&stat, 124).is_err());
        assert!(process_start(&stat.replace(") S ", ") Z "), 123).is_err());
        assert!(process_start(&stat.replace(") S ", ") ??? "), 123).is_err());
        assert!(process_start("123 (short) S 0", 123).is_err());
    }
}
