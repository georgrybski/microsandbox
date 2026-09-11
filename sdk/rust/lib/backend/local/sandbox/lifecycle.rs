//! Generation-bound receiver lifecycle, distinct from explicit name selection.

use super::*;
use crate::MicrosandboxError;
use crate::sandbox::BoundAction;

impl LocalBackend {
    pub(crate) async fn refresh_bound(
        &self,
        backend: Arc<dyn Backend>,
        name: &str,
        expected: &LocalObservation,
    ) -> MicrosandboxResult<SandboxHandle> {
        let _transition =
            Self::acquire_sandbox_transition_guard(&self.config().run_dir(), name).await?;
        let mut model = self.validate_observation(name, expected).await?;
        // Reconciliation is itself a mutation. Validate the selected run before
        // it, and use retained exit evidence rather than a recycled numeric PID.
        if matches!(
            model.status,
            SandboxStatus::Starting | SandboxStatus::Running | SandboxStatus::Draining
        ) && expected
            .process
            .as_ref()
            .map(|p| p.has_exited())
            .transpose()?
            .unwrap_or(false)
            && let Some(_runtime) = microsandbox_runtime::ipc::try_acquire_lifecycle_guard(
                &self.config().run_dir(),
                name,
            )?
        {
            model = self.validate_observation(name, expected).await?;
            let (status, reason) = Self::stale_runtime_terminal_state(model.status);
            Self::mark_sandbox_runtime_stale(
                self.db().await?.write(),
                model.id,
                expected.run_id,
                status,
                reason,
            )
            .await?;
            crate::runtime::remove_sandbox_socket_artifacts_for(self, name)?;
            model = self.validate_observation(name, expected).await?;
        }
        let launch = match expected.process.as_ref() {
            Some(process)
                if !process.has_exited()?
                    && matches!(
                        model.status,
                        SandboxStatus::Running | SandboxStatus::Draining
                    ) =>
            {
                Some(process.launch)
            }
            _ => None,
        };
        Ok(SandboxHandle::from_local_model(
            backend,
            model,
            launch,
            expected.clone(),
        ))
    }

    pub(crate) async fn start_bound(
        &self,
        backend: Arc<dyn Backend>,
        name: &str,
        expected: &LocalObservation,
        mode: SpawnMode,
    ) -> MicrosandboxResult<Sandbox> {
        self.start_sandbox_observed(
            backend,
            name,
            Some(expected.sandbox_id),
            Some(expected),
            mode,
        )
        .await
    }
    /// Read-only selection validation. Callers hold the transition guard when
    /// using the result to change state or dispatch a lifecycle command.
    pub(crate) async fn validate_observation(
        &self,
        name: &str,
        expected: &LocalObservation,
    ) -> MicrosandboxResult<sandbox_entity::Model> {
        let pools = self.db().await?;
        let model = load_sandbox_record(pools.read(), name).await?;
        ensure_local_identity(name, Some(expected.sandbox_id), model.id)?;
        let run = Self::load_latest_run(pools.read(), model.id).await?;
        let current = LocalObservation::capture(self, model.id, run.map(|r| r.id), None);
        expected.ensure_current(name, &current)?;
        Ok(model)
    }

    pub(crate) async fn request_bound_action(
        &self,
        name: &str,
        expected: &LocalObservation,
        action: BoundAction,
        retained: Option<Arc<crate::agent::AgentClient>>,
    ) -> MicrosandboxResult<()> {
        let _transition =
            Self::acquire_sandbox_transition_guard(&self.config().run_dir(), name).await?;
        let model = self.validate_observation(name, expected).await?;
        if matches!(
            model.status,
            SandboxStatus::Created | SandboxStatus::Stopped | SandboxStatus::Crashed
        ) {
            return Ok(());
        }
        let process = expected
            .process
            .as_ref()
            .ok_or(MicrosandboxError::LaunchBindingUnsupported)?;
        if process.has_exited()? {
            return Ok(());
        }
        process.ensure_live(self)?;
        if matches!(action, BoundAction::Kill | BoundAction::Drain) {
            if matches!(action, BoundAction::Drain) {
                Self::mark_sandbox_draining_if_running(self.db().await?.write(), model.id).await?;
            }
            return if matches!(action, BoundAction::Kill) {
                process.signal(9)
            } else {
                process.drain()
            };
        }

        let client = match retained {
            Some(client) => Ok(client),
            None => crate::sandbox::fs::agent::connect_agent_with_timeout(
                self,
                name,
                AGENT_SHUTDOWN_CONNECT_TIMEOUT,
            )
            .await
            .map(Arc::new),
        };
        self.validate_observation(name, expected).await?;
        if let Ok(client) = client {
            if client.peer_pid() != Some(process.launch.pid as u32) {
                return Err(MicrosandboxError::LaunchBindingUnsupported);
            }
            process.ensure_live(self)?;
            Self::mark_sandbox_draining_if_running(self.db().await?.write(), model.id).await?;
            if matches!(
                tokio::time::timeout(
                    AGENT_SHUTDOWN_CONNECT_TIMEOUT,
                    client.send(0, MessageType::Shutdown, &())
                )
                .await,
                Ok(Ok(()))
            ) {
                return Ok(());
            }
        }
        // The fallback can only address the retained kernel process object.
        // It never reloads a PID or reconnects to a new launch.
        if process.has_exited()? {
            return Ok(());
        }
        process.signal(15)
    }

    pub(crate) async fn await_bound_runtime_exit(
        &self,
        name: &str,
        expected: &LocalObservation,
        allow_removed: bool,
    ) -> MicrosandboxResult<()> {
        self.await_bound_runtime_exit_with_grace(
            name,
            expected,
            allow_removed,
            crate::sandbox::reap::RUNTIME_EXIT_GRACE,
        )
        .await
    }

    pub(super) async fn await_bound_runtime_exit_with_grace(
        &self,
        name: &str,
        expected: &LocalObservation,
        allow_removed: bool,
        grace: Duration,
    ) -> MicrosandboxResult<()> {
        self.validate_exit_selection(name, expected, allow_removed)
            .await?;
        let Some(process) = expected.process.as_ref() else {
            if expected.run_id.is_none() {
                return Ok(());
            }
            return Err(MicrosandboxError::LaunchBindingUnsupported);
        };
        if process.wait(grace).await.is_ok() {
            return Ok(());
        }
        self.escalate_bound_runtime_exit(name, expected, allow_removed)
            .await
    }

    pub(super) async fn escalate_bound_runtime_exit(
        &self,
        name: &str,
        expected: &LocalObservation,
        allow_removed: bool,
    ) -> MicrosandboxResult<()> {
        let _transition =
            Self::acquire_sandbox_transition_guard(&self.config().run_dir(), name).await?;
        self.validate_exit_selection(name, expected, allow_removed)
            .await?;
        let process = expected
            .process
            .as_ref()
            .ok_or(MicrosandboxError::LaunchBindingUnsupported)?;
        if !process.has_exited()? {
            process.signal(9)?;
        }
        process.wait(crate::runtime::reap::REAP_EXIT_WAIT).await
    }

    /// Passive evidence for the exceptional ephemeral row-removal path.
    /// Missing rows alone must never manufacture a terminal process result.
    pub(crate) async fn removed_runtime_has_exited(
        &self,
        name: &str,
        expected: &LocalObservation,
    ) -> MicrosandboxResult<bool> {
        self.validate_exit_selection(name, expected, true).await?;
        expected
            .process
            .as_ref()
            .ok_or(MicrosandboxError::LaunchBindingUnsupported)?
            .has_exited()
    }

    async fn validate_exit_selection(
        &self,
        name: &str,
        expected: &LocalObservation,
        allow_removed: bool,
    ) -> MicrosandboxResult<()> {
        match self.validate_observation(name, expected).await {
            Ok(_) => Ok(()),
            Err(error)
                if allow_removed && crate::sandbox::sandbox_not_found_for_name(&error, name) =>
            {
                // Ephemeral deletion removes the row, not the process proof.
                // Only the retained pidfd can complete the following wait.
                expected.ensure_current(
                    name,
                    &LocalObservation::capture(self, expected.sandbox_id, expected.run_id, None),
                )
            }
            Err(error) => Err(error),
        }
    }
}
