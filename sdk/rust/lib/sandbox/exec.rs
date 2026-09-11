//! Execution types for running commands inside sandboxes.

use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc;

use crate::MicrosandboxResult;
use microsandbox_types::EnvVar;

mod session;
use session::{ExecEvents, SessionControl};
pub use session::{ExecInterruption, ExecInterruptionReason, ExecTermination};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Options for command execution (everything except the command itself).
#[derive(Debug, Clone, Default)]
pub struct ExecOptions {
    /// Arguments.
    pub args: Vec<String>,

    /// Working directory (overrides sandbox default).
    pub cwd: Option<String>,

    /// Guest user override for this command.
    pub user: Option<String>,

    /// Environment variables (merged with sandbox env).
    pub env: Vec<EnvVar>,

    /// Execution deadline, including request delivery. On expiry a bounded
    /// SIGKILL request and termination observation run on the original session.
    /// An interruption is not a successful exit, even if termination is observed.
    pub timeout: Option<Duration>,

    /// Stdin mode.
    pub stdin: StdinMode,

    /// Allocate a PTY (pseudo-terminal).
    pub tty: bool,

    /// Resource limits applied before exec via `setrlimit()`.
    pub rlimits: Vec<Rlimit>,
}

/// Builder for [`ExecOptions`].
#[derive(Default)]
pub struct ExecOptionsBuilder {
    options: ExecOptions,
}

/// How stdin is provided to the command.
#[derive(Debug, Clone, Default)]
pub enum StdinMode {
    /// No stdin (`/dev/null`).
    #[default]
    Null,

    /// Pipe stdin via [`ExecSink`].
    Pipe,

    /// Provide fixed bytes as stdin.
    Bytes(Vec<u8>),
}

/// Output of a completed command execution.
#[derive(Debug)]
pub struct ExecOutput {
    /// Exit status.
    status: ExitStatus,

    /// Captured stdout.
    stdout: Bytes,

    /// Captured stderr.
    stderr: Bytes,
}

/// Process exit status.
#[derive(Debug, Clone, Copy)]
pub struct ExitStatus {
    /// Exit code.
    pub code: i32,

    /// Whether the process exited successfully (code == 0).
    pub success: bool,
}

/// Handle to a streaming exec session.
pub struct ExecHandle {
    /// Correlation ID for this session (protocol-level u32, exposed as String).
    id: u32,

    /// Event receiver.
    events: ExecEvents,

    /// Stdin sink (only if `StdinMode::Pipe` was used).
    stdin: Option<ExecSink>,

    control: ExecControl,
}

/// Cloneable control handle for a streaming exec session.
#[derive(Clone)]
pub struct ExecControl {
    inner: SessionControl,
}

/// Events emitted by a streaming exec session.
#[derive(Debug, Clone)]
pub enum ExecEvent {
    /// Process started.
    Started {
        /// Guest PID.
        pid: u32,
    },

    /// Stdout data.
    Stdout(Bytes),

    /// Stderr data.
    Stderr(Bytes),

    /// Process exited.
    Exited {
        /// Exit code.
        code: i32,
    },

    /// Process failed to spawn (binary not found, permission
    /// denied, etc.). Distinct from `Exited` — `Failed` means the
    /// user code never ran. Terminal: no further events follow.
    Failed(microsandbox_protocol::exec::ExecFailed),

    /// A stdin write to the child failed (e.g. broken pipe). Non-terminal:
    /// the session keeps running and may still emit further output and
    /// an `Exited` event.
    StdinError(microsandbox_protocol::exec::ExecStdinError),

    /// The operation was interrupted. The reason and any observed process
    /// termination are separate; transport loss never implies successful exit.
    Interrupted(ExecInterruption),
}

/// Sink for writing to a running process's stdin.
pub struct ExecSink {
    session: microsandbox_agent_client::AgentSession,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ExecOptionsBuilder {
    /// Prepend arguments resolved by a higher-level execution helper.
    pub(crate) fn prepend_args(mut self, args: impl IntoIterator<Item = String>) -> Self {
        self.options.args.splice(0..0, args);
        self
    }

    /// Append a command-line argument (e.g., `"-la"` or `"/tmp"`).
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.options.args.push(arg.into());
        self
    }

    /// Append multiple command-line arguments.
    pub fn args(mut self, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.options.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Override the working directory for this command (overrides the
    /// sandbox default set via the builder's `workdir` method).
    pub fn cwd(mut self, cwd: impl Into<String>) -> Self {
        self.options.cwd = Some(cwd.into());
        self
    }

    /// Override the guest user for this command.
    pub fn user(mut self, user: impl Into<String>) -> Self {
        self.options.user = Some(user.into());
        self
    }

    /// Set an environment variable for this command. Merged on top of
    /// the sandbox-level env vars.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.options.env.push(EnvVar::new(key, value));
        self
    }

    /// Set multiple environment variables for this command.
    pub fn envs(
        mut self,
        vars: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> Self {
        self.options
            .env
            .extend(vars.into_iter().map(|(key, value)| EnvVar::new(key, value)));
        self
    }

    /// Interrupt the operation after this duration, then request SIGKILL and
    /// observe termination for a bounded interval. Applies to streaming too.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.options.timeout = Some(timeout);
        self
    }

    /// Set stdin mode to null (`/dev/null`).
    pub fn stdin_null(mut self) -> Self {
        self.options.stdin = StdinMode::Null;
        self
    }

    /// Set stdin mode to pipe (use `ExecHandle::stdin()`).
    pub fn stdin_pipe(mut self) -> Self {
        self.options.stdin = StdinMode::Pipe;
        self
    }

    /// Set stdin to fixed bytes.
    pub fn stdin_bytes(mut self, data: impl Into<Vec<u8>>) -> Self {
        self.options.stdin = StdinMode::Bytes(data.into());
        self
    }

    /// Allocate a pseudo-terminal. Enable for interactive programs (shells,
    /// editors, `top`); disable for scripts and batch jobs (default: false).
    pub fn tty(mut self, enabled: bool) -> Self {
        self.options.tty = enabled;
        self
    }

    /// Set a resource limit (soft = hard).
    pub fn rlimit(mut self, resource: RlimitResource, limit: u64) -> Self {
        self.options.rlimits.push(Rlimit {
            resource,
            soft: limit,
            hard: limit,
        });
        self
    }

    /// Set a resource limit with different soft/hard values.
    pub fn rlimit_range(mut self, resource: RlimitResource, soft: u64, hard: u64) -> Self {
        self.options.rlimits.push(Rlimit {
            resource,
            soft,
            hard,
        });
        self
    }

    /// Finalize the options. Called automatically when using the closure form.
    ///
    /// Returns an error if any rlimit entry has `soft > hard`.
    pub fn build(self) -> MicrosandboxResult<ExecOptions> {
        validate_rlimits(&self.options.rlimits)?;
        Ok(self.options)
    }
}

/// Validates that every rlimit has `soft <= hard`.
pub(crate) fn validate_rlimits(rlimits: &[Rlimit]) -> MicrosandboxResult<()> {
    for rlimit in rlimits {
        if rlimit.soft > rlimit.hard {
            return Err(crate::MicrosandboxError::InvalidConfig(format!(
                "rlimit {}: soft ({}) must not exceed hard ({})",
                rlimit.resource.as_str(),
                rlimit.soft,
                rlimit.hard
            )));
        }
    }
    Ok(())
}

impl ExecOutput {
    /// Exit code and success flag of the completed process.
    pub fn status(&self) -> ExitStatus {
        self.status
    }

    /// Get stdout as a UTF-8 string.
    pub fn stdout(&self) -> Result<String, std::string::FromUtf8Error> {
        String::from_utf8(self.stdout.to_vec())
    }

    /// Get stderr as a UTF-8 string.
    pub fn stderr(&self) -> Result<String, std::string::FromUtf8Error> {
        String::from_utf8(self.stderr.to_vec())
    }

    /// Get stdout as raw bytes.
    pub fn stdout_bytes(&self) -> &Bytes {
        &self.stdout
    }

    /// Get stderr as raw bytes.
    pub fn stderr_bytes(&self) -> &Bytes {
        &self.stderr
    }
}

impl ExecHandle {
    /// Create a new exec handle.
    pub(crate) fn new(control: ExecControl, events: ExecEvents, stdin: Option<ExecSink>) -> Self {
        Self {
            id: control.inner.session.id(),
            events,
            stdin,
            control,
        }
    }

    /// Get the execution session ID.
    pub fn id(&self) -> String {
        self.id.to_string()
    }

    /// Get a cloneable control handle for this session.
    pub fn control(&self) -> ExecControl {
        self.control.clone()
    }

    /// Consume this handle into separately owned control, stdin, and event parts.
    #[cfg(feature = "ssh")]
    pub(crate) fn into_parts(self) -> (ExecControl, Option<ExecSink>, ExecEvents) {
        (self.control, self.stdin, self.events)
    }

    /// Receive the next exec event.
    ///
    /// Returns `None` when the session has ended.
    pub async fn recv(&mut self) -> Option<ExecEvent> {
        self.events.recv().await
    }

    /// Receive one queued event without waiting or transport I/O. Empty is
    /// distinct from disconnected; neither is evidence of process termination.
    pub fn try_recv(&mut self) -> Result<ExecEvent, mpsc::error::TryRecvError> {
        self.events.try_recv()
    }

    /// Take the stdin sink (if `StdinMode::Pipe` was used).
    ///
    /// Returns `None` if stdin was not piped or was already taken.
    pub fn take_stdin(&mut self) -> Option<ExecSink> {
        self.stdin.take()
    }

    /// Wait for the command to complete and return the exit status.
    pub async fn wait(&mut self) -> MicrosandboxResult<ExitStatus> {
        while let Some(event) = self.events.recv().await {
            match event {
                ExecEvent::Exited { code } => {
                    return Ok(ExitStatus {
                        code,
                        success: code == 0,
                    });
                }
                ExecEvent::Failed(payload) => {
                    return Err(crate::MicrosandboxError::ExecFailed(payload));
                }
                ExecEvent::Interrupted(interruption) => {
                    return Err(crate::MicrosandboxError::ExecInterrupted(interruption));
                }
                _ => {}
            }
        }

        Err(crate::MicrosandboxError::Runtime(
            "exec session ended without exit event".into(),
        ))
    }

    /// Wait for completion and collect at most 8 MiB of combined stdout/stderr.
    /// Exceeding the bound interrupts the operation rather than truncating it.
    pub async fn collect(&mut self) -> MicrosandboxResult<ExecOutput> {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit_code: Option<i32> = None;

        while let Some(event) = self.events.recv().await {
            match event {
                ExecEvent::Started { pid: _ } => {}
                ExecEvent::Stdout(data) => {
                    if data.len() > session::COLLECT_BYTES - stdout.len() - stderr.len() {
                        let outcome = self
                            .control
                            .inner
                            .cancel(ExecInterruptionReason::OutputLimit)
                            .await;
                        return Err(crate::MicrosandboxError::ExecInterrupted(outcome));
                    }
                    stdout.extend_from_slice(&data);
                }
                ExecEvent::Stderr(data) => {
                    if data.len() > session::COLLECT_BYTES - stdout.len() - stderr.len() {
                        let outcome = self
                            .control
                            .inner
                            .cancel(ExecInterruptionReason::OutputLimit)
                            .await;
                        return Err(crate::MicrosandboxError::ExecInterrupted(outcome));
                    }
                    stderr.extend_from_slice(&data);
                }
                ExecEvent::Exited { code } => {
                    exit_code = Some(code);
                    break;
                }
                ExecEvent::Failed(payload) => {
                    return Err(crate::MicrosandboxError::ExecFailed(payload));
                }
                ExecEvent::StdinError(_) => {}
                ExecEvent::Interrupted(interruption) => {
                    return Err(crate::MicrosandboxError::ExecInterrupted(interruption));
                }
            }
        }

        let code = exit_code.ok_or_else(|| {
            crate::MicrosandboxError::Runtime("exec session ended without exit event".into())
        })?;

        Ok(ExecOutput {
            status: ExitStatus {
                code,
                success: code == 0,
            },
            stdout: Bytes::from(stdout),
            stderr: Bytes::from(stderr),
        })
    }

    /// Send a Unix signal (e.g., `libc::SIGTERM`, `libc::SIGINT`) to the
    /// running process inside the guest.
    pub async fn signal(&self, signal: i32) -> MicrosandboxResult<()> {
        self.control().signal(signal).await
    }

    /// Send SIGKILL to the running process.
    pub async fn kill(&self) -> MicrosandboxResult<()> {
        self.control().kill().await
    }

    /// Resize the PTY for this session.
    pub async fn resize(&self, rows: u16, cols: u16) -> MicrosandboxResult<()> {
        self.control().resize(rows, cols).await
    }

    /// Request cancellation and wait a bounded interval for termination evidence.
    pub async fn cancel(&self) -> ExecInterruption {
        self.control.cancel().await
    }
}

impl ExecControl {
    /// Get the execution session ID.
    pub fn id(&self) -> String {
        self.inner.session.id().to_string()
    }

    /// Send a Unix signal (e.g., `libc::SIGTERM`, `libc::SIGINT`) to the
    /// running process inside the guest.
    pub async fn signal(&self, signal: i32) -> MicrosandboxResult<()> {
        self.inner.signal(signal).await
    }

    /// Send SIGKILL to the running process.
    pub async fn kill(&self) -> MicrosandboxResult<()> {
        self.signal(9).await
    }

    /// Resize the PTY for this session.
    pub async fn resize(&self, rows: u16, cols: u16) -> MicrosandboxResult<()> {
        self.inner.resize(rows, cols).await
    }

    /// Request SIGKILL on this original session and observe termination for a
    /// bounded interval. This is process-group cleanup, not containment of
    /// descendants that escaped the group. Unconfirmed is never an exit code.
    pub async fn cancel(&self) -> ExecInterruption {
        self.inner.cancel(ExecInterruptionReason::Cancelled).await
    }
}

impl ExecSink {
    /// Create a new stdin sink.
    pub(crate) fn new(session: microsandbox_agent_client::AgentSession) -> Self {
        Self { session }
    }

    /// Write data to the process's stdin.
    pub async fn write(&self, data: impl AsRef<[u8]>) -> MicrosandboxResult<()> {
        session::write_stdin(&self.session, data.as_ref(), false).await
    }

    /// Close pipe stdin. PTY EOF remains a no-op in agentd so output can drain.
    pub async fn close(&self) -> MicrosandboxResult<()> {
        session::write_stdin(&self.session, &[], true).await
    }
}

//--------------------------------------------------------------------------------------------------
// Module: agent (backend-agnostic ops driven over an agent connection)
//--------------------------------------------------------------------------------------------------

pub(crate) mod agent {
    //! Native exec dispatch over an existing connection. Name-addressed helpers
    //! remain for backends without a host-owned launch binding.

    use super::{ExecHandle, ExecOptions, ExecOutput};
    use crate::{
        MicrosandboxResult,
        sandbox::{SandboxConfig, build_exec_request},
    };
    use std::sync::Arc;

    pub(crate) async fn exec_stream(
        backend: &dyn crate::backend::Backend,
        name: &str,
        config: &SandboxConfig,
        cmd: String,
        opts: ExecOptions,
    ) -> MicrosandboxResult<ExecHandle> {
        exec_stream_with_pty_size(backend, name, config, cmd, opts, 24, 80).await
    }

    pub(crate) async fn exec_stream_with_pty_size(
        backend: &dyn crate::backend::Backend,
        name: &str,
        config: &SandboxConfig,
        cmd: String,
        opts: ExecOptions,
        rows: u16,
        cols: u16,
    ) -> MicrosandboxResult<ExecHandle> {
        let client = Arc::new(super::super::fs::agent::connect_agent(backend, name).await?);
        exec_stream_connected(client, config, cmd, opts, rows, cols).await
    }

    pub(crate) async fn exec_stream_connected(
        client: Arc<crate::agent::AgentClient>,
        config: &SandboxConfig,
        cmd: String,
        opts: ExecOptions,
        rows: u16,
        cols: u16,
    ) -> MicrosandboxResult<ExecHandle> {
        super::validate_rlimits(&opts.rlimits)?;
        let ExecOptions {
            args,
            cwd,
            user,
            env,
            rlimits,
            tty,
            stdin,
            timeout,
        } = opts;
        let request = build_exec_request(
            config, cmd, args, cwd, user, &env, &rlimits, tty, rows, cols,
        );
        super::session::open(client, request, stdin, timeout).await
    }

    pub(crate) async fn exec(
        backend: &dyn crate::backend::Backend,
        name: &str,
        config: &SandboxConfig,
        cmd: String,
        opts: ExecOptions,
    ) -> MicrosandboxResult<ExecOutput> {
        let client = Arc::new(super::super::fs::agent::connect_agent(backend, name).await?);
        exec_connected(client, config, cmd, opts).await
    }

    pub(crate) async fn exec_connected(
        client: Arc<crate::agent::AgentClient>,
        config: &SandboxConfig,
        cmd: String,
        opts: ExecOptions,
    ) -> MicrosandboxResult<ExecOutput> {
        exec_stream_connected(client, config, cmd, opts, 24, 80)
            .await?
            .collect()
            .await
    }
}

//--------------------------------------------------------------------------------------------------
//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use microsandbox_types::{Rlimit, RlimitResource};
