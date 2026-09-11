//! Immutable local database generation selected by a lifecycle receiver.

use crate::{MicrosandboxError, MicrosandboxResult, backend::LocalBackend};

#[derive(Clone, Copy)]
pub(crate) enum BoundAction {
    Stop,
    Kill,
    Drain,
}

/// Unlike live launch proof, this remains usable after the selected run exits.
/// SQLite AUTOINCREMENT preserves run IDs across ordinary row deletion; the
/// pinned database file separates those IDs from a recreated database.
#[derive(Clone, Debug)]
pub(crate) struct LocalObservation {
    database: Option<(u64, u64)>,
    pub(crate) sandbox_id: i32,
    pub(crate) run_id: Option<i32>,
    pub(crate) process: Option<std::sync::Arc<super::reap::PinnedRuntime>>,
}

impl LocalObservation {
    pub(crate) fn capture(
        backend: &LocalBackend,
        sandbox_id: i32,
        run_id: Option<i32>,
        launch: Option<super::LocalLaunch>,
    ) -> Self {
        #[cfg(target_os = "linux")]
        let database = backend.launch_database_identity().ok();
        #[cfg(not(target_os = "linux"))]
        let database = {
            let _ = backend;
            None
        };
        let process = launch
            .and_then(|launch| super::reap::PinnedRuntime::open(backend, launch).ok())
            .map(std::sync::Arc::new);
        Self {
            database,
            sandbox_id,
            run_id,
            process,
        }
    }

    pub(crate) fn ensure_current(&self, name: &str, current: &Self) -> MicrosandboxResult<()> {
        self.database
            .ok_or(MicrosandboxError::LaunchBindingUnsupported)?;
        if (self.database, self.sandbox_id, self.run_id)
            != (current.database, current.sandbox_id, current.run_id)
        {
            return Err(MicrosandboxError::SandboxLaunchChanged {
                name: name.to_owned(),
            });
        }
        Ok(())
    }
}
