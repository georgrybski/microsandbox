//! Retained process-exit proof and explicit administrative cleanup.
//!
//! A terminal database row can precede actual runtime exit and disk writeback.
//! Linux bound receivers retain a pidfd for exact signaling and exit observation;
//! they do not reload or signal a numeric PID after the original launch.
//! Windows name-addressed administrative cleanup retains its separate checked
//! image/start-time verification for older runtimes that outlive terminal rows.

use std::time::{Duration, Instant};

#[cfg(windows)]
use microsandbox_db::entity::run as run_entity;
#[cfg(windows)]
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};

use crate::MicrosandboxResult;
#[cfg(windows)]
use crate::runtime::reap;

/// A retained Linux process capability, never reopened by numeric PID for
/// signalling or exit observation. Other hosts cannot supply this proof yet.
#[derive(Debug)]
pub(crate) struct PinnedRuntime {
    #[cfg(target_os = "linux")]
    fd: std::os::fd::OwnedFd,
    pub(crate) launch: super::LocalLaunch,
}

impl PinnedRuntime {
    pub(crate) fn ensure_live(
        &self,
        backend: &crate::backend::LocalBackend,
    ) -> MicrosandboxResult<()> {
        let current = super::LocalLaunch::capture(
            backend,
            self.launch.sandbox_id,
            self.launch.run_id,
            self.launch.pid,
        );
        self.launch.ensure_current("runtime", Some(current))?;
        if self.has_exited()? {
            return Err(crate::MicrosandboxError::SandboxLaunchChanged {
                name: "runtime".into(),
            });
        }
        Ok(())
    }
    pub(crate) fn open(
        backend: &crate::backend::LocalBackend,
        launch: super::LocalLaunch,
    ) -> MicrosandboxResult<Self> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::FromRawFd;
            launch
                .identity
                .ok_or(crate::MicrosandboxError::LaunchBindingUnsupported)?;
            let fd = unsafe { nix::libc::syscall(nix::libc::SYS_pidfd_open, launch.pid, 0) };
            if fd < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd as i32) };
            // Opening a pidfd and then checking kernel start-time closes PID
            // reuse between the original snapshot and acquiring the capability.
            let current =
                super::LocalLaunch::capture(backend, launch.sandbox_id, launch.run_id, launch.pid);
            launch.ensure_current("runtime", Some(current))?;
            Ok(Self { fd, launch })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (backend, launch);
            Err(crate::MicrosandboxError::LaunchBindingUnsupported)
        }
    }

    pub(crate) fn has_exited(&self) -> MicrosandboxResult<bool> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            let mut poll = nix::libc::pollfd {
                fd: self.fd.as_raw_fd(),
                events: nix::libc::POLLIN,
                revents: 0,
            };
            let result = unsafe { nix::libc::poll(&mut poll, 1, 0) };
            if result < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            if poll.revents & (nix::libc::POLLNVAL | nix::libc::POLLERR) != 0 {
                return Err(crate::MicrosandboxError::LaunchBindingUnsupported);
            }
            Ok(poll.revents & nix::libc::POLLIN != 0)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(crate::MicrosandboxError::LaunchBindingUnsupported)
        }
    }

    pub(crate) fn signal(&self, signal: i32) -> MicrosandboxResult<()> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            let result = unsafe {
                nix::libc::syscall(
                    nix::libc::SYS_pidfd_send_signal,
                    self.fd.as_raw_fd(),
                    signal,
                    std::ptr::null::<nix::libc::siginfo_t>(),
                    0,
                )
            };
            if result < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = signal;
            Err(crate::MicrosandboxError::LaunchBindingUnsupported)
        }
    }

    pub(crate) async fn wait(&self, duration: Duration) -> MicrosandboxResult<()> {
        let started = Instant::now();
        loop {
            if self.has_exited()? {
                return Ok(());
            }
            if started.elapsed() >= duration {
                return Err(crate::MicrosandboxError::Runtime(
                    "selected runtime has not exited before deadline".into(),
                ));
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    pub(crate) fn drain(&self) -> MicrosandboxResult<()> {
        #[cfg(target_os = "linux")]
        {
            self.signal(nix::libc::SIGUSR1)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(crate::MicrosandboxError::LaunchBindingUnsupported)
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Grace window for the recorded runtime process to finish exiting after the
/// sandbox row is observed terminal, before `stop`/`kill` escalate to
/// signalling it.
///
/// Sized well above the guest shutdown flush fallbacks in
/// `microsandbox-protocol` (`NORMAL_SHUTDOWN_FLUSH_TIMEOUT` = 2s,
/// `HANDOFF_SHUTDOWN_FLUSH_TIMEOUT` = 8s): the row goes `Stopped` before the
/// host-side writeback flush of block-backed roots completes, and a multi-GB
/// `upper.ext4` has been observed to need tens of seconds to flush.
pub(crate) const RUNTIME_EXIT_GRACE: Duration = Duration::from_secs(30);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// What [`reap_leaked_runtime_process`] established about the recorded run PID.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LeakedReapVerdict {
    /// No live runtime process remains (already dead, or terminated here).
    NoProcess,

    /// A live process holds the PID but is provably not the runtime; it was left alone.
    RecycledPid,

    /// The live process could not be queried, so its ownership is unknown and it was left alone.
    Unverifiable,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Terminate a leftover VM process only when its identity matches the sandbox's latest run.
///
/// A stopped database row can still have a Windows VM process serving the sandbox's named pipes.
/// Checking the recorded start time and image before termination prevents a recycled PID from
/// causing an unrelated process to be killed.
#[cfg(windows)]
pub(crate) async fn reap_leaked_runtime_process(
    local_backend: &crate::backend::LocalBackend,
    sandbox_id: i32,
    name: &str,
) -> MicrosandboxResult<LeakedReapVerdict> {
    let pools = local_backend.db().await?;
    let run = run_entity::Entity::find()
        .filter(run_entity::Column::SandboxId.eq(sandbox_id))
        .order_by_desc(run_entity::Column::Id)
        .one(pools.read())
        .await?;
    let Some(run) = run else {
        return Ok(LeakedReapVerdict::NoProcess);
    };
    let (Some(pid), Some(started_at)) = (run.pid, run.started_at) else {
        return Ok(LeakedReapVerdict::NoProcess);
    };
    let Ok(pid_u32) = u32::try_from(pid) else {
        return Ok(LeakedReapVerdict::NoProcess);
    };
    if !pid_is_alive(pid) {
        return Ok(LeakedReapVerdict::NoProcess);
    }

    let outcome =
        reap::terminate_runtime_process_checked(pid_u32, started_at.and_utc().timestamp_micros());
    match outcome {
        Ok(reap::ReapOutcome::AlreadyDead) => return Ok(LeakedReapVerdict::NoProcess),
        Ok(reap::ReapOutcome::IdentityMismatch) => {
            tracing::warn!(
                pid,
                sandbox = %name,
                "recorded runtime PID is now a different process (recycled); leaving it alone"
            );
            return Ok(LeakedReapVerdict::RecycledPid);
        }
        Ok(reap::ReapOutcome::Unverifiable) => {
            tracing::warn!(
                pid,
                sandbox = %name,
                "recorded runtime PID cannot be queried (likely recycled); leaving it alone"
            );
            return Ok(LeakedReapVerdict::Unverifiable);
        }
        Ok(reap::ReapOutcome::Terminated) => {
            tracing::warn!(pid, sandbox = %name, "terminated leftover sandbox VM process");
        }
        // Termination can fail while a verified process is already exiting. The liveness check
        // below is authoritative, so wait before deciding whether cleanup failed.
        Err(err) => {
            tracing::warn!(
                pid,
                sandbox = %name,
                error = %err,
                "failed to terminate leftover sandbox VM process; waiting for exit"
            );
        }
    }

    wait_for_pids_to_exit(&[pid], reap::REAP_EXIT_WAIT).await;
    if pid_is_alive(pid) {
        return Err(crate::MicrosandboxError::Runtime(format!(
            "sandbox process {pid} for '{name}' is still running after termination"
        )));
    }

    Ok(LeakedReapVerdict::NoProcess)
}

#[cfg(windows)]
fn pid_is_alive(pid: i32) -> bool {
    microsandbox_utils::process::pid_is_alive(pid)
}

#[cfg(windows)]
async fn wait_for_pids_to_exit(pids: &[i32], timeout: Duration) {
    let start = Instant::now();
    let poll_interval = Duration::from_millis(50);

    loop {
        if pids.iter().all(|pid| !pid_is_alive(*pid)) || start.elapsed() >= timeout {
            return;
        }

        tokio::time::sleep(poll_interval).await;
    }
}
