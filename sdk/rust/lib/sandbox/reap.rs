//! Process-exit proof for sandbox runtimes whose database row already went
//! terminal, plus identity-checked cleanup for leaked Windows runtime
//! processes.
//!
//! The local runtime marks the sandbox row `Stopped` on the VMM thread before
//! `_exit()`, so a terminal row does not prove the recorded runtime process is
//! gone: host-side teardown (including the writeback flush of block-backed
//! roots) can still be in flight. [`await_recorded_runtime_exit`] closes that
//! window for `stop`/`kill` on all platforms.
//! [`reap_leaked_runtime_process`] additionally covers the Windows case where
//! the VM process never exits at all and keeps serving the sandbox's named
//! pipes; it terminates such a process only after proving the PID still names
//! the recorded runtime.

use std::time::{Duration, Instant};

use microsandbox_db::entity::run as run_entity;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};

use crate::{MicrosandboxResult, runtime::reap};

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

/// Wait for the sandbox's recorded runtime process to exit after its database
/// row went terminal, escalating to a kill when it outlives `exit_grace`.
///
/// The local runtime marks the sandbox row `Stopped` on the VMM thread before
/// `_exit()`, so a terminal row does not prove the process is gone: teardown
/// (including the writeback flush of block-backed roots) can still be in
/// flight. `stop`/`kill` only count as successful once no process remains;
/// otherwise an immediate remove/replace hits the fail-closed "recorded
/// runtime process is still alive" guard.
///
/// Escalation signals the recorded PID directly: the backend kill path
/// (`kill_sandbox`, and with it `SandboxHandle::request_kill`) no-ops once
/// the row is terminal, which is exactly the state that reaches this
/// function. On Windows termination is identity-checked so a recycled PID is
/// left alone, matching [`reap_leaked_runtime_process`] semantics.
pub(crate) async fn await_recorded_runtime_exit(
    local_backend: &crate::backend::LocalBackend,
    sandbox_id: i32,
    name: &str,
    exit_grace: Duration,
) -> MicrosandboxResult<()> {
    let pools = local_backend.db().await?;
    let run = run_entity::Entity::find()
        .filter(run_entity::Column::SandboxId.eq(sandbox_id))
        .order_by_desc(run_entity::Column::Id)
        .one(pools.read())
        .await?;
    let Some(run) = run else {
        return Ok(());
    };
    let Some(pid) = run.pid else {
        return Ok(());
    };
    if !pid_is_alive(pid) {
        return Ok(());
    }

    // Grace phase: the runtime may still be flushing guest writes to disk.
    tracing::debug!(pid, sandbox = %name, "waiting for recorded runtime process to exit");
    wait_for_pids_to_exit(&[pid], exit_grace).await;
    if !pid_is_alive(pid) {
        return Ok(());
    }

    #[cfg(unix)]
    let termination_requested = terminate_recorded_runtime(pid, name);
    #[cfg(windows)]
    let termination_requested = terminate_recorded_runtime(pid, run.started_at, name);

    if termination_requested {
        wait_for_pids_to_exit(&[pid], reap::REAP_EXIT_WAIT).await;
        if pid_is_alive(pid) {
            return Err(crate::MicrosandboxError::Runtime(format!(
                "sandbox '{name}': recorded runtime process {pid} is still alive after stop escalation"
            )));
        }
    }

    Ok(())
}

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

/// Signal the recorded runtime process after it outlived the exit grace.
///
/// Sends SIGKILL, matching the backend `kill_sandbox` path. Returns `true`
/// when the caller should wait for the PID to disappear; `false` when the
/// process was already gone (ESRCH) and nothing was signalled. Signalling
/// can race a concurrent exit, so the liveness check after the wait is
/// authoritative either way.
#[cfg(unix)]
fn terminate_recorded_runtime(pid: i32, name: &str) -> bool {
    match nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(pid),
        nix::sys::signal::Signal::SIGKILL,
    ) {
        Ok(()) => {
            tracing::warn!(
                pid,
                sandbox = %name,
                "recorded runtime process outlived stop; sent SIGKILL"
            );
            true
        }
        Err(nix::errno::Errno::ESRCH) => false,
        Err(error) => {
            tracing::warn!(
                pid,
                sandbox = %name,
                %error,
                "failed to SIGKILL recorded runtime process; waiting for exit"
            );
            true
        }
    }
}

/// Terminate the recorded runtime process after it outlived the exit grace.
///
/// Goes through the identity-checked terminator so a recycled PID is never
/// killed. Returns `true` when termination was requested (or attempted) and
/// the caller should wait for the PID to disappear; `false` when the PID
/// provably no longer names the recorded runtime (already dead, recycled, or
/// unverifiable), in which case the process was left alone.
#[cfg(windows)]
fn terminate_recorded_runtime(
    pid: i32,
    started_at: Option<chrono::NaiveDateTime>,
    name: &str,
) -> bool {
    let (Ok(pid_u32), Some(started_at)) = (u32::try_from(pid), started_at) else {
        // Without a recorded start time the runtime's identity is unprovable;
        // leave the process alone rather than risk killing a recycled PID.
        return false;
    };
    match reap::terminate_runtime_process_checked(pid_u32, started_at.and_utc().timestamp_micros())
    {
        Ok(reap::ReapOutcome::Terminated) => {
            tracing::warn!(
                pid,
                sandbox = %name,
                "recorded runtime process outlived stop; terminated"
            );
            true
        }
        Ok(reap::ReapOutcome::AlreadyDead) => false,
        Ok(reap::ReapOutcome::IdentityMismatch) | Ok(reap::ReapOutcome::Unverifiable) => {
            tracing::warn!(
                pid,
                sandbox = %name,
                "recorded runtime PID no longer names the runtime; leaving it alone"
            );
            false
        }
        Err(error) => {
            tracing::warn!(
                pid,
                sandbox = %name,
                %error,
                "failed to terminate recorded runtime process; waiting for exit"
            );
            true
        }
    }
}

fn pid_is_alive(pid: i32) -> bool {
    microsandbox_utils::process::pid_is_alive(pid)
}

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

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use microsandbox_db::entity::sandbox as sandbox_entity;
    use sea_orm::{EntityTrait, Set};
    use tempfile::{TempDir, tempdir};

    use super::*;
    use crate::backend::LocalBackend;
    use crate::sandbox::{SandboxConfig, SandboxStatus};

    /// Build a local backend rooted at a temp home, with the DB migrated.
    async fn test_backend() -> (TempDir, LocalBackend) {
        let temp = tempdir().unwrap();
        let backend = LocalBackend::builder()
            .home(temp.path())
            .build()
            .await
            .unwrap();
        // Force the pool (and migrations) open before seeding rows.
        backend.db().await.unwrap();
        (temp, backend)
    }

    /// Seed a stopped sandbox row and return its database id.
    async fn seed_stopped_sandbox(backend: &LocalBackend, name: &str) -> i32 {
        let pools = backend.db().await.unwrap();
        let config = SandboxConfig {
            spec: microsandbox_types::SandboxSpec {
                name: name.to_string(),
                ..Default::default()
            },
            ..Default::default()
        };
        let now = chrono::Utc::now().naive_utc();
        sandbox_entity::Entity::insert(sandbox_entity::ActiveModel {
            name: Set(name.to_string()),
            config: Set(serde_json::to_string(&config).unwrap()),
            status: Set(SandboxStatus::Stopped),
            ephemeral: Set(false),
            created_at: Set(Some(now)),
            updated_at: Set(Some(now)),
            ..Default::default()
        })
        .exec(pools.write())
        .await
        .unwrap()
        .last_insert_id
    }

    /// Seed a terminated run row carrying `pid` for `sandbox_id`.
    async fn seed_run(backend: &LocalBackend, sandbox_id: i32, pid: Option<i32>) {
        let pools = backend.db().await.unwrap();
        run_entity::Entity::insert(run_entity::ActiveModel {
            sandbox_id: Set(sandbox_id),
            pid: Set(pid),
            status: Set(run_entity::RunStatus::Terminated),
            started_at: Set(Some(chrono::Utc::now().naive_utc())),
            ..Default::default()
        })
        .exec(pools.write())
        .await
        .unwrap();
    }

    fn dead_pid() -> i32 {
        let mut pid = 900_000;
        while pid_is_alive(pid) {
            pid += 1;
        }
        pid
    }

    #[tokio::test]
    async fn await_recorded_runtime_exit_returns_ok_without_run() {
        let (_temp, backend) = test_backend().await;
        let sandbox_id = seed_stopped_sandbox(&backend, "no-run").await;

        await_recorded_runtime_exit(&backend, sandbox_id, "no-run", Duration::from_millis(10))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn await_recorded_runtime_exit_returns_ok_for_dead_pid() {
        let (_temp, backend) = test_backend().await;
        let sandbox_id = seed_stopped_sandbox(&backend, "dead-pid").await;
        seed_run(&backend, sandbox_id, Some(dead_pid())).await;

        await_recorded_runtime_exit(&backend, sandbox_id, "dead-pid", Duration::from_millis(10))
            .await
            .unwrap();
    }

    /// A terminal row whose recorded PID is still exiting must block the wait
    /// until the process is actually gone, then return Ok.
    #[cfg(unix)]
    #[tokio::test]
    async fn await_recorded_runtime_exit_waits_until_pid_exits() {
        let (_temp, backend) = test_backend().await;
        let sandbox_id = seed_stopped_sandbox(&backend, "slow-exit").await;

        let mut child = std::process::Command::new("sh")
            .arg("-c")
            .arg("sleep 0.5")
            .spawn()
            .unwrap();
        let pid = child.id() as i32;
        seed_run(&backend, sandbox_id, Some(pid)).await;

        let start = Instant::now();
        await_recorded_runtime_exit(&backend, sandbox_id, "slow-exit", Duration::from_secs(10))
            .await
            .unwrap();

        // The child sleeps 500ms and the poll interval is 50ms, so the wait
        // cannot have returned before the child actually exited.
        assert!(start.elapsed() >= Duration::from_millis(400));
        assert!(!pid_is_alive(pid));
        child.wait().unwrap();
    }

    /// A recorded PID that outlives the grace window is escalated (SIGKILL on
    /// Unix) and the wait only returns once the process is gone.
    #[cfg(unix)]
    #[tokio::test]
    async fn await_recorded_runtime_exit_escalates_after_grace() {
        let (_temp, backend) = test_backend().await;
        let sandbox_id = seed_stopped_sandbox(&backend, "stuck-exit").await;

        let mut child = std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .unwrap();
        let pid = child.id() as i32;
        seed_run(&backend, sandbox_id, Some(pid)).await;

        let start = Instant::now();
        await_recorded_runtime_exit(
            &backend,
            sandbox_id,
            "stuck-exit",
            Duration::from_millis(50),
        )
        .await
        .unwrap();

        // Grace (50ms) elapsed, escalation killed the child, and the bounded
        // post-kill wait (REAP_EXIT_WAIT) returned as soon as it died.
        assert!(start.elapsed() < reap::REAP_EXIT_WAIT + Duration::from_secs(5));
        assert!(!pid_is_alive(pid));
        child.wait().unwrap();
    }
}
