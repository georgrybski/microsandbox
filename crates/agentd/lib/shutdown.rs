//! Receiver-owned poweroff for systemd handoff guests.

use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use tokio::time::{Instant, sleep_until, timeout_at};

use crate::error::{AgentdError, AgentdResult};
use crate::process::{ProcessExitWatcher, ProcessIdentity, ProcessManager};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const HELPER_TIMEOUT: Duration = Duration::from_secs(2);
const POWEROFF_ARGS: &[&str] = &[
    "--system",
    "--no-block",
    "--no-ask-password",
    "--job-mode=replace-irreversibly",
    "start",
    "poweroff.target",
];

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

// Child-status ownership stays with ProcessManager. In particular, neither
// std::Child::wait nor tokio::process may compete with its process-wide reaper.
struct OwnedHelper {
    manager: Arc<ProcessManager>,
    identity: ProcessIdentity,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for OwnedHelper {
    fn drop(&mut self) {
        // Also covers cancellation and descendants remaining after helper exit.
        let _ = self
            .manager
            .signal_process_group(self.identity, libc::SIGKILL);
        self.manager.release(self.identity);
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Locate the helper belonging to the running PID 1, not the caller's PATH.
/// Non-systemd receivers retain their existing shutdown path.
pub(crate) fn systemd_poweroff_helper() -> AgentdResult<Option<PathBuf>> {
    let executable = std::fs::read_link("/proc/1/exe")?;
    let Some(helper) = helper_for_executable(&executable)? else {
        return Ok(None);
    };
    validate_helper(&helper)?;
    Ok(Some(helper))
}

/// Queue the receiver's named target and wait within the existing handoff grace.
/// A successful helper only acknowledges submission, not completed poweroff.
pub(crate) async fn poweroff_systemd(helper: &Path, deadline: Instant) -> AgentdResult<()> {
    await_poweroff(poweroff_command(helper), deadline).await
}

fn helper_for_executable(executable: &Path) -> AgentdResult<Option<PathBuf>> {
    if !executable.is_absolute()
        || executable.file_name().is_none()
        || executable
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
        || executable
            .as_os_str()
            .as_encoded_bytes()
            .ends_with(b" (deleted)")
    {
        return Err(AgentdError::Init(format!(
            "cannot identify handoff receiver executable: {}",
            executable.display()
        )));
    }
    if executable
        .file_name()
        .is_some_and(|name| name == "systemd-shutdown")
    {
        return Err(AgentdError::Init(
            "systemd is already executing its shutdown stage; refusing a fallback signal".into(),
        ));
    }
    if executable.file_name().is_none_or(|name| name != "systemd") {
        return Ok(None);
    }

    // Both NixOS and conventional distributions install these two binaries
    // relative to the same prefix. Do not guess for an unexpected layout.
    let systemd_dir = executable.parent().expect("absolute executable has parent");
    let lib_dir = systemd_dir.parent();
    if systemd_dir.file_name().is_none_or(|name| name != "systemd")
        || lib_dir
            .and_then(Path::file_name)
            .is_none_or(|name| name != "lib")
    {
        return Err(AgentdError::Init(format!(
            "unsupported systemd executable layout: {}",
            executable.display()
        )));
    }
    let prefix = lib_dir
        .and_then(Path::parent)
        .ok_or_else(|| AgentdError::Init("systemd executable has no installation prefix".into()))?;
    Ok(Some(prefix.join("bin/systemctl")))
}

fn validate_helper(helper: &Path) -> AgentdResult<()> {
    // The resolved helper must remain in this installation. A PATH lookup or
    // an unrelated symlink target could select a different systemd version.
    let resolved = std::fs::canonicalize(helper).map_err(|error| {
        AgentdError::Init(format!(
            "systemd poweroff helper {}: {error}",
            helper.display()
        ))
    })?;
    if resolved != helper {
        return Err(AgentdError::Init(format!(
            "systemd poweroff helper is not its canonical installation path: {}",
            helper.display()
        )));
    }
    let metadata = std::fs::metadata(helper)?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err(AgentdError::Init(format!(
            "systemd poweroff helper is not an executable file: {}",
            helper.display()
        )));
    }
    Ok(())
}

fn poweroff_command(helper: &Path) -> Command {
    let mut command = Command::new(helper);
    command
        .args(POWEROFF_ARGS)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);
    command
}

async fn await_poweroff(command: Command, deadline: Instant) -> AgentdResult<()> {
    run_helper(command, deadline).await?;
    sleep_until(deadline).await;
    Err(AgentdError::Init(
        "systemd accepted poweroff.target but the guest did not power off within the handoff grace; host fallback remains separate".into(),
    ))
}

fn spawn_helper(mut command: Command) -> AgentdResult<(OwnedHelper, ProcessExitWatcher)> {
    let manager = ProcessManager::get()?;
    let guard = manager.spawn_guard()?;
    let child = command
        .spawn()
        .map_err(|error| AgentdError::Init(format!("spawn systemd poweroff helper: {error}")))?;
    let exit = guard.track(child.id() as i32)?;
    let owned = OwnedHelper {
        manager,
        identity: exit.identity(),
    };
    drop(child);
    Ok((owned, exit))
}

async fn run_helper(command: Command, deadline: Instant) -> AgentdResult<()> {
    if Instant::now() >= deadline {
        return Err(AgentdError::Init(
            "systemd poweroff deadline already expired".into(),
        ));
    }
    let (owned, mut exit) = spawn_helper(command)?;
    let command_deadline = deadline.min(Instant::now() + HELPER_TIMEOUT);
    match timeout_at(command_deadline, &mut exit).await {
        Ok(0) => Ok(()),
        Ok(code) => Err(AgentdError::Init(format!(
            "systemd poweroff helper failed with exit code {code}"
        ))),
        Err(_) => {
            owned
                .manager
                .signal_process_group(owned.identity, libc::SIGKILL)?;
            let reaped = timeout_at(deadline, &mut exit).await.is_ok();
            Err(AgentdError::Init(format!(
                "systemd poweroff helper timed out; owned helper exit observed: {reaped}"
            )))
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_ENV: &str = "MSB_SYSTEMD_POWEROFF_TEST_HELPER";

    #[test]
    fn helper_resolution_uses_receiver_installation() {
        for (receiver, expected) in [
            (
                "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-systemd-260.1/lib/systemd/systemd",
                "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-systemd-260.1/bin/systemctl",
            ),
            ("/usr/lib/systemd/systemd", "/usr/bin/systemctl"),
            ("/lib/systemd/systemd", "/bin/systemctl"),
        ] {
            assert_eq!(
                helper_for_executable(Path::new(receiver)).unwrap(),
                Some(PathBuf::from(expected))
            );
        }
        assert_eq!(
            helper_for_executable(Path::new("/sbin/openrc-init")).unwrap(),
            None
        );
    }

    #[test]
    fn ambiguous_receiver_paths_are_errors_not_signal_fallbacks() {
        for receiver in [
            "/",
            "lib/systemd/systemd",
            "/usr/lib/systemd/systemd (deleted)",
            "/sbin/init (deleted)",
            "/usr/bin/systemd",
            "/usr/lib/../lib/systemd/systemd",
            "/usr/lib/systemd/systemd-shutdown",
        ] {
            assert!(
                helper_for_executable(Path::new(receiver)).is_err(),
                "{receiver}"
            );
        }
        assert!(validate_helper(Path::new("/nonexistent-msb-systemd-test/bin/systemctl")).is_err());
    }

    #[test]
    fn helper_must_be_regular_executable_and_not_an_alias() {
        use std::os::unix::fs::symlink;
        let root = std::env::temp_dir().join(format!(
            "msb-poweroff-helper-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir(&root).unwrap();
        let helper = root.join("systemctl");
        std::fs::write(&helper, b"synthetic fixture, never executed").unwrap();
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(validate_helper(&helper).is_err());
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
        validate_helper(&helper).unwrap();
        let alias = root.join("alias");
        symlink(&helper, &alias).unwrap();
        assert!(validate_helper(&alias).is_err());
        assert!(validate_helper(&root).is_err());
        std::fs::remove_file(alias).unwrap();
        std::fs::remove_file(helper).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn named_poweroff_is_independent_of_sender_realtime_signal_offsets() {
        // musl SIGRTMIN=35: +4 equals glibc SIGRTMIN=34 +5 (reboot).
        // The command names the receiver's target instead of translating RT signals.
        assert_eq!(35 + 4, 34 + 5);
        let helper = Path::new("/usr/bin/systemctl");
        let command = poweroff_command(helper);
        assert_eq!(command.get_program(), helper);
        assert_eq!(command.get_args().collect::<Vec<_>>(), POWEROFF_ARGS);
        assert_eq!(command.get_current_dir(), Some(Path::new("/")));
        assert_eq!(command.get_envs().count(), 0);
        assert!(!POWEROFF_ARGS.iter().any(|arg| arg.contains("force")));
    }

    fn fixture_command(mode: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "shutdown::tests::helper_process_fixture",
                "--nocapture",
            ])
            .env_clear()
            .env(FIXTURE_ENV, mode)
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
    }

    #[test]
    fn helper_process_fixture() {
        match std::env::var(FIXTURE_ENV).as_deref() {
            Ok("success") => std::process::exit(0),
            Ok("failure") => std::process::exit(7),
            Ok("timeout") => std::thread::sleep(Duration::from_secs(60)),
            _ => {}
        }
    }

    #[test]
    fn dropping_helper_ownership_terminates_the_exact_child() {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

        let (owned, _exit) = spawn_helper(fixture_command("timeout")).unwrap();
        // Pin this fixture's identity before cancellation. Polling its pidfd
        // observes actual kernel exit, not merely a dropped status channel.
        let raw_fd = unsafe { libc::syscall(libc::SYS_pidfd_open, owned.identity.pid(), 0) };
        assert!(
            raw_fd >= 0,
            "pidfd_open: {}",
            std::io::Error::last_os_error()
        );
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd as i32) };
        drop(owned);
        let mut event = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut event, 1, 2000) }, 1);
        assert_ne!(event.revents & libc::POLLIN, 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn helper_exit_status_is_tracked_and_failure_is_not_success() {
        run_helper(
            fixture_command("success"),
            Instant::now() + Duration::from_secs(5),
        )
        .await
        .unwrap();
        let error = run_helper(
            fixture_command("failure"),
            Instant::now() + Duration::from_secs(5),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("exit code 7"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn timed_out_helper_is_killed_and_reaped_within_total_budget() {
        let start = Instant::now();
        let error = run_helper(fixture_command("timeout"), start + Duration::from_secs(4))
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("timed out; owned helper exit observed: true"),
            "{error}"
        );
        assert!(start.elapsed() < Duration::from_secs(4));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn accepted_request_is_not_completed_poweroff() {
        let error = await_poweroff(
            fixture_command("success"),
            Instant::now() + Duration::from_secs(3),
        )
        .await
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("accepted poweroff.target but the guest did not power off"),
            "{error}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn expired_deadline_does_not_spawn_helper() {
        let error = run_helper(
            Command::new("/nonexistent-msb-must-not-spawn"),
            Instant::now(),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("deadline already expired"));
    }
}
