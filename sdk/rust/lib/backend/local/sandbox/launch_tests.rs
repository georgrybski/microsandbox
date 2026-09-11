//! Native host-state and relay fixtures; these tests do not boot a guest.

use std::sync::Arc;
use std::time::Duration;

use microsandbox_protocol::{
    codec,
    core::Ready,
    exec::ExecExited,
    message::{Message, MessageType},
};
use sea_orm::{ActiveModelTrait, EntityTrait, Set};
use tempfile::TempDir;
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};

use super::{LocalBackend, run_entity, sandbox_entity};
use crate::MicrosandboxError;
use crate::backend::{Backend, SandboxBackend};
use crate::sandbox::{Sandbox, SandboxConfig, SandboxHandle, SandboxStatus};

//--------------------------------------------------------------------------------------------------
// Fixtures
//--------------------------------------------------------------------------------------------------

struct Fixture {
    _temp: TempDir,
    backend: Arc<LocalBackend>,
    name: String,
    sandbox_id: i32,
    run_id: i32,
}

impl Fixture {
    async fn new(name: &str) -> Self {
        let temp = tempfile::Builder::new()
            .prefix("msb-bound-")
            .tempdir_in("/tmp")
            .unwrap();
        let backend = Arc::new(
            LocalBackend::builder()
                .home(temp.path())
                .build()
                .await
                .unwrap(),
        );
        let mut config = SandboxConfig::default();
        config.spec.name = name.to_owned();
        let sandbox_id =
            LocalBackend::insert_sandbox_record(backend.db().await.unwrap().write(), &config)
                .await
                .unwrap();
        LocalBackend::update_sandbox_status(
            backend.db().await.unwrap().write(),
            sandbox_id,
            SandboxStatus::Running,
        )
        .await
        .unwrap();
        let mut fixture = Self {
            _temp: temp,
            backend,
            name: name.to_owned(),
            sandbox_id,
            run_id: 0,
        };
        fixture.new_run().await;
        fixture
    }

    async fn new_run(&mut self) {
        let db = self.backend.db().await.unwrap();
        if self.run_id != 0 {
            let old = run_entity::Entity::find_by_id(self.run_id)
                .one(db.read())
                .await
                .unwrap()
                .unwrap();
            let mut old: run_entity::ActiveModel = old.into();
            old.status = Set(run_entity::RunStatus::Terminated);
            old.update(db.write()).await.unwrap();
        }
        self.run_id = run_entity::Entity::insert(run_entity::ActiveModel {
            sandbox_id: Set(self.sandbox_id),
            pid: Set(Some(std::process::id() as i32)),
            status: Set(run_entity::RunStatus::Running),
            ..Default::default()
        })
        .exec(db.write())
        .await
        .unwrap()
        .last_insert_id;
    }

    async fn handle(&self) -> SandboxHandle {
        let backend: Arc<dyn Backend> = self.backend.clone();
        self.backend.get(backend, &self.name).await.unwrap()
    }

    async fn clear_runtime_pid(&self) {
        let db = self.backend.db().await.unwrap();
        let mut run: run_entity::ActiveModel = run_entity::Entity::find_by_id(self.run_id)
            .one(db.read())
            .await
            .unwrap()
            .unwrap()
            .into();
        run.pid = Set(None);
        run.update(db.write()).await.unwrap();
    }

    async fn ephemeral(&self) {
        let db = self.backend.db().await.unwrap();
        let model = sandbox_entity::Entity::find_by_id(self.sandbox_id)
            .one(db.read())
            .await
            .unwrap()
            .unwrap();
        let mut config: SandboxConfig = serde_json::from_str(&model.config).unwrap();
        config.spec.lifecycle.ephemeral = true;
        let mut model: sandbox_entity::ActiveModel = model.into();
        model.config = Set(serde_json::to_string(&config).unwrap());
        model.update(db.write()).await.unwrap();
    }

    async fn remove_row(&self) {
        sandbox_entity::Entity::delete_by_id(self.sandbox_id)
            .exec(self.backend.db().await.unwrap().write())
            .await
            .unwrap();
    }

    async fn assert_unreconciled(&self) {
        let db = self.backend.db().await.unwrap();
        assert_eq!(
            sandbox_entity::Entity::find_by_id(self.sandbox_id)
                .one(db.read())
                .await
                .unwrap()
                .unwrap()
                .status,
            SandboxStatus::Running
        );
        assert_eq!(
            run_entity::Entity::find_by_id(self.run_id)
                .one(db.read())
                .await
                .unwrap()
                .unwrap()
                .status,
            run_entity::RunStatus::Running
        );
    }

    fn listener(&self) -> UnixListener {
        let path =
            crate::runtime::sandbox_agent_socket_path_candidates_for(&self.backend, &self.name)
                .remove(0);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        UnixListener::bind(path).unwrap()
    }

    async fn connected(&self) -> (Sandbox, UnixStream) {
        let listener = self.listener();
        let handle = self.handle().await;
        let (sandbox, socket) = tokio::join!(handle.connect(), async {
            let (mut socket, _) = listener.accept().await.unwrap();
            ready(&mut socket).await;
            socket
        },);
        (sandbox.unwrap(), socket)
    }
}

async fn ready(socket: &mut UnixStream) {
    socket.write_all(&1u32.to_be_bytes()).await.unwrap();
    socket
        .write_all(&microsandbox_protocol::AGENT_RELAY_ID_RANGE_STEP.to_be_bytes())
        .await
        .unwrap();
    let message = Message::with_payload(MessageType::Ready, 0, &Ready::default()).unwrap();
    codec::write_message(socket, &message).await.unwrap();
}

async fn no_request(socket: &mut UnixStream) {
    assert!(
        tokio::time::timeout(Duration::from_millis(20), codec::read_raw_frame(socket))
            .await
            .is_err()
    );
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn launch_binding_exec_uses_retained_connection_for_two_sandboxes() {
    let first = Fixture::new("first").await;
    let second = Fixture::new("second").await;
    let (first_sandbox, mut first_socket) = first.connected().await;
    let (second_sandbox, mut second_socket) = second.connected().await;
    let first_exec = first_sandbox
        .exec_stream("first-command", std::iter::empty::<String>())
        .await
        .unwrap();
    let second_exec = second_sandbox
        .exec_stream("second-command", std::iter::empty::<String>())
        .await
        .unwrap();
    for (socket, command) in [
        (&mut first_socket, "first-command"),
        (&mut second_socket, "second-command"),
    ] {
        let frame = tokio::time::timeout(Duration::from_secs(1), codec::read_raw_frame(socket))
            .await
            .unwrap()
            .unwrap();
        let message = codec::raw_frame_to_message(frame).unwrap();
        assert_eq!(message.t, MessageType::ExecRequest);
        assert_eq!(
            message
                .payload::<microsandbox_protocol::exec::ExecRequest>()
                .unwrap()
                .cmd,
            command
        );
    }
    drop((first_exec, second_exec));
}

#[tokio::test]
async fn launch_binding_old_handle_refuses_same_sandbox_new_run_before_dial() {
    let mut fixture = Fixture::new("restart").await;
    let old = fixture.handle().await;
    let identity = old.launch_identity().unwrap();
    fixture.new_run().await;
    let listener = fixture.listener();
    assert!(matches!(
        old.connect().await,
        Err(MicrosandboxError::SandboxLaunchChanged { .. })
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(20), listener.accept())
            .await
            .is_err()
    );
    let fresh = old.refresh().await.unwrap();
    assert_ne!(identity, fresh.launch_identity().unwrap());
    assert_eq!(identity, old.launch_identity().unwrap());
}

#[tokio::test]
async fn launch_binding_replacement_during_handshake_refuses_before_exec() {
    let mut fixture = Fixture::new("during-connect").await;
    let old = fixture.handle().await;
    let listener = fixture.listener();
    let (connected, socket) = tokio::join!(old.connect(), async {
        let (mut socket, _) = listener.accept().await.unwrap();
        fixture.new_run().await;
        fixture.clear_runtime_pid().await;
        ready(&mut socket).await;
        socket
    });
    assert!(matches!(
        connected,
        Err(MicrosandboxError::SandboxLaunchChanged { .. })
    ));
    fixture.assert_unreconciled().await;
    // A refused connection closes without a command frame.
    let mut socket = socket;
    assert!(
        tokio::time::timeout(Duration::from_secs(1), codec::read_raw_frame(&mut socket))
            .await
            .unwrap()
            .is_err()
    );
}

#[tokio::test]
async fn launch_binding_clones_cannot_exec_after_explicit_refresh() {
    let mut fixture = Fixture::new("clones").await;
    let (old, mut socket) = fixture.connected().await;
    let clone = old.clone();
    fixture.new_run().await;
    let fresh = fixture.handle().await;
    assert_ne!(
        old.launch_identity().unwrap(),
        fresh.launch_identity().unwrap()
    );
    assert_eq!(
        old.launch_identity().unwrap(),
        clone.launch_identity().unwrap()
    );
    for sandbox in [&old, &clone] {
        assert!(matches!(
            sandbox
                .exec_stream("forbidden", std::iter::empty::<String>())
                .await,
            Err(MicrosandboxError::SandboxLaunchChanged { .. })
        ));
    }
    no_request(&mut socket).await;
}

#[tokio::test]
async fn launch_binding_attach_refuses_stale_receiver_before_tty_or_request() {
    let mut fixture = Fixture::new("stale-attach").await;
    let (old, mut socket) = fixture.connected().await;
    fixture.new_run().await;
    assert!(matches!(
        old.attach("forbidden", std::iter::empty::<String>()).await,
        Err(MicrosandboxError::SandboxLaunchChanged { .. })
    ));
    assert!(matches!(
        old.attach_shell().await,
        Err(MicrosandboxError::SandboxLaunchChanged { .. })
    ));
    no_request(&mut socket).await;
}

#[tokio::test]
async fn launch_binding_remove_recreate_refuses_old_connection() {
    let fixture = Fixture::new("reused").await;
    let (old, mut socket) = fixture.connected().await;
    let db = fixture.backend.db().await.unwrap();
    sandbox_entity::Entity::delete_by_id(fixture.sandbox_id)
        .exec(db.write())
        .await
        .unwrap();
    let mut config = SandboxConfig::default();
    config.spec.name = fixture.name.clone();
    let new_id = LocalBackend::insert_sandbox_record(db.write(), &config)
        .await
        .unwrap();
    assert_ne!(new_id, fixture.sandbox_id);
    assert!(matches!(
        old.exec_stream("forbidden", std::iter::empty::<String>())
            .await,
        Err(MicrosandboxError::SandboxReplaced { .. })
    ));
    no_request(&mut socket).await;
}

#[tokio::test]
async fn launch_binding_missing_run_is_not_guest_ready_authority() {
    let fixture = Fixture::new("missing-run").await;
    let old = fixture.handle().await;
    run_entity::Entity::delete_by_id(fixture.run_id)
        .exec(fixture.backend.db().await.unwrap().write())
        .await
        .unwrap();
    assert!(old.connect().await.is_err());
}

#[tokio::test]
async fn launch_binding_replaced_database_path_cannot_authorize_old_pool() {
    let fixture = Fixture::new("database-replaced").await;
    let (old, mut socket) = fixture.connected().await;
    let path = fixture
        .backend
        .config()
        .home()
        .join(microsandbox_utils::DB_SUBDIR)
        .join(microsandbox_utils::DB_FILENAME);
    // The open pools and pinned descriptor still refer to the original inode.
    std::fs::rename(&path, path.with_extension("retained")).unwrap();
    std::fs::write(&path, b"replacement is not the open database").unwrap();
    assert!(fixture.backend.launch_database_identity().is_err());
    assert!(
        old.exec_stream("forbidden", std::iter::empty::<String>())
            .await
            .is_err()
    );
    no_request(&mut socket).await;
}

#[tokio::test]
async fn launch_binding_injected_transport_has_no_kernel_peer_proof() {
    let fixture = Fixture::new("unverified-peer").await;
    let (stream, mut socket) = UnixStream::pair().unwrap();
    let (client, ()) = tokio::join!(
        crate::agent::AgentClient::connect_stream_with_timeout(stream, Duration::from_secs(1)),
        ready(&mut socket),
    );
    let client = Arc::new(client.unwrap());
    assert_eq!(client.peer_pid(), None);
    let run = LocalBackend::load_active_run(
        fixture.backend.db().await.unwrap().read(),
        fixture.sandbox_id,
    )
    .await
    .unwrap();
    let launch = fixture.backend.launch_from_run(run.as_ref()).unwrap();
    let mut config = SandboxConfig::default();
    config.spec.name = fixture.name.clone();
    let backend: Arc<dyn Backend> = fixture.backend.clone();
    let sandbox = Sandbox::from_local(
        backend,
        crate::backend::SandboxLocalState {
            db_id: fixture.sandbox_id,
            launch,
            observation: crate::sandbox::LocalObservation::capture(
                &fixture.backend,
                fixture.sandbox_id,
                Some(launch.run_id),
                Some(launch),
            ),
            handle: None,
            client,
        },
        config,
    );
    assert!(matches!(
        sandbox
            .exec_stream("forbidden", std::iter::empty::<String>())
            .await,
        Err(MicrosandboxError::LaunchBindingUnsupported)
    ));
    no_request(&mut socket).await;
}

#[tokio::test]
async fn launch_binding_control_keeps_original_connection_after_run_change() {
    let mut fixture = Fixture::new("control").await;
    let (sandbox, mut socket) = fixture.connected().await;
    let mut exec = sandbox
        .exec_stream("command", std::iter::empty::<String>())
        .await
        .unwrap();
    let frame = codec::read_raw_frame(&mut socket).await.unwrap();
    let eof =
        codec::raw_frame_to_message(codec::read_raw_frame(&mut socket).await.unwrap()).unwrap();
    assert_eq!((eof.id, eof.t), (frame.id, MessageType::ExecStdin));
    assert!(
        eof.payload::<microsandbox_protocol::exec::ExecStdin>()
            .unwrap()
            .data
            .is_empty()
    );
    let control = exec.control();
    fixture.new_run().await;
    control.signal(15).await.unwrap();
    let signal =
        codec::raw_frame_to_message(codec::read_raw_frame(&mut socket).await.unwrap()).unwrap();
    assert_eq!(signal.t, MessageType::ExecSignal);
    assert_eq!(signal.id, frame.id);
    let exited =
        Message::with_payload(MessageType::ExecExited, frame.id, &ExecExited { code: 143 })
            .unwrap();
    codec::write_message(&mut socket, &exited).await.unwrap();
    assert_eq!(exec.wait().await.unwrap().code, 143);
}

#[tokio::test]
async fn launch_lifecycle_old_handle_cannot_dispatch_to_a_later_run() {
    let mut fixture = Fixture::new("old-lifecycle").await;
    let old = fixture.handle().await;
    fixture.new_run().await;
    for result in [
        old.request_stop().await,
        old.request_kill().await,
        old.request_drain().await,
        old.stop_with_timeout(Duration::ZERO).await,
        old.remove().await,
    ] {
        assert!(matches!(
            result,
            Err(MicrosandboxError::SandboxLaunchChanged { .. })
        ));
    }
    assert!(matches!(
        old.start().await,
        Err(MicrosandboxError::SandboxLaunchChanged { .. })
    ));
    assert!(matches!(
        old.start_detached().await,
        Err(MicrosandboxError::SandboxLaunchChanged { .. })
    ));
    assert!(matches!(
        old.connect_or_start().await,
        Err(MicrosandboxError::SandboxLaunchChanged { .. })
    ));
    assert_eq!(
        fixture.handle().await.status_snapshot(),
        SandboxStatus::Running
    );
}

#[tokio::test]
async fn launch_lifecycle_stale_connect_and_exec_never_reconcile_new_run() {
    let mut fixture = Fixture::new("no-reconcile").await;
    let handle = fixture.handle().await;
    let (sandbox, mut socket) = fixture.connected().await;
    fixture.new_run().await;
    fixture.clear_runtime_pid().await;
    assert!(matches!(
        handle.connect().await,
        Err(MicrosandboxError::SandboxLaunchChanged { .. })
    ));
    fixture.assert_unreconciled().await;
    assert!(matches!(
        sandbox
            .exec_stream("forbidden", std::iter::empty::<String>())
            .await,
        Err(MicrosandboxError::SandboxLaunchChanged { .. })
    ));
    fixture.assert_unreconciled().await;
    no_request(&mut socket).await;
}

#[tokio::test]
async fn launch_lifecycle_ephemeral_row_absence_does_not_finish_live_wait() {
    let fixture = Fixture::new("ephemeral-live").await;
    fixture.ephemeral().await;
    let old = fixture.handle().await;
    fixture.remove_row().await;
    assert!(
        tokio::time::timeout(Duration::from_millis(20), old.wait_until_stopped())
            .await
            .is_err()
    );
    assert!(
        !old.local()
            .unwrap()
            .observation
            .process
            .as_ref()
            .unwrap()
            .has_exited()
            .unwrap()
    );
}

#[tokio::test]
async fn launch_lifecycle_ephemeral_missing_row_rechecks_database_domain() {
    let fixture = Fixture::new("ephemeral-domain").await;
    fixture.ephemeral().await;
    let old = fixture.handle().await;
    fixture.remove_row().await;
    let path = fixture
        .backend
        .config()
        .home()
        .join(microsandbox_utils::DB_SUBDIR)
        .join(microsandbox_utils::DB_FILENAME);
    std::fs::rename(&path, path.with_extension("retained")).unwrap();
    std::fs::write(&path, b"not the selected database").unwrap();
    assert!(matches!(
        old.wait_until_stopped().await,
        Err(MicrosandboxError::SandboxLaunchChanged { .. })
    ));
}

#[tokio::test]
async fn launch_lifecycle_historical_terminal_without_pidfd_cannot_be_removed() {
    let fixture = Fixture::new("historical-terminal").await;
    fixture.clear_runtime_pid().await;
    LocalBackend::update_sandbox_status(
        fixture.backend.db().await.unwrap().write(),
        fixture.sandbox_id,
        SandboxStatus::Stopped,
    )
    .await
    .unwrap();
    let old = fixture.handle().await;
    assert!(old.local().unwrap().observation.process.is_none());
    assert!(matches!(
        old.remove().await,
        Err(MicrosandboxError::LaunchBindingUnsupported)
    ));
    assert!(matches!(
        old.stop().await,
        Err(MicrosandboxError::LaunchBindingUnsupported)
    ));
    assert!(
        sandbox_entity::Entity::find_by_id(fixture.sandbox_id)
            .one(fixture.backend.db().await.unwrap().read())
            .await
            .unwrap()
            .is_some()
    );
    fixture.remove_row().await;
    assert!(matches!(
        fixture
            .backend
            .removed_runtime_has_exited(&fixture.name, &old.local().unwrap().observation)
            .await,
        Err(MicrosandboxError::LaunchBindingUnsupported)
    ));
}

#[tokio::test]
async fn launch_lifecycle_created_without_run_can_be_removed() {
    let fixture = Fixture::new("created-no-run").await;
    let db = fixture.backend.db().await.unwrap();
    run_entity::Entity::delete_by_id(fixture.run_id)
        .exec(db.write())
        .await
        .unwrap();
    LocalBackend::update_sandbox_status(db.write(), fixture.sandbox_id, SandboxStatus::Created)
        .await
        .unwrap();
    let selected = fixture.handle().await;
    assert!(selected.local().unwrap().observation.run_id.is_none());
    tokio::time::timeout(Duration::from_secs(1), selected.stop())
        .await
        .unwrap()
        .unwrap();
    selected.kill_with_timeout(Duration::ZERO).await.unwrap();
    assert_eq!(
        selected.refresh_selected().await.unwrap().status_snapshot(),
        SandboxStatus::Created
    );
    assert!(
        LocalBackend::load_latest_run(db.read(), fixture.sandbox_id)
            .await
            .unwrap()
            .is_none()
    );
    selected.remove().await.unwrap();
    assert!(
        sandbox_entity::Entity::find_by_id(fixture.sandbox_id)
            .one(db.read())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn launch_lifecycle_created_selection_refuses_stop_after_first_run() {
    let fixture = Fixture::new("created-then-started").await;
    let db = fixture.backend.db().await.unwrap();
    run_entity::Entity::delete_by_id(fixture.run_id)
        .exec(db.write())
        .await
        .unwrap();
    LocalBackend::update_sandbox_status(db.write(), fixture.sandbox_id, SandboxStatus::Created)
        .await
        .unwrap();
    let selected = fixture.handle().await;
    assert!(selected.local().unwrap().observation.run_id.is_none());
    run_entity::Entity::insert(run_entity::ActiveModel {
        sandbox_id: Set(fixture.sandbox_id),
        pid: Set(Some(std::process::id() as i32)),
        status: Set(run_entity::RunStatus::Running),
        ..Default::default()
    })
    .exec(db.write())
    .await
    .unwrap();
    LocalBackend::update_sandbox_status(db.write(), fixture.sandbox_id, SandboxStatus::Running)
        .await
        .unwrap();
    assert!(matches!(
        selected.stop().await,
        Err(MicrosandboxError::SandboxLaunchChanged { .. })
    ));
    assert!(matches!(
        selected.kill().await,
        Err(MicrosandboxError::SandboxLaunchChanged { .. })
    ));
    assert_eq!(
        sandbox_entity::Entity::find_by_id(fixture.sandbox_id)
            .one(db.read())
            .await
            .unwrap()
            .unwrap()
            .status,
        SandboxStatus::Running
    );
}

#[tokio::test]
async fn launch_lifecycle_connected_receiver_keeps_original_selection() {
    let mut fixture = Fixture::new("connected-lifecycle").await;
    let (sandbox, mut socket) = fixture.connected().await;
    let clone = sandbox.clone();
    fixture.new_run().await;
    assert!(matches!(
        sandbox.request_stop().await,
        Err(MicrosandboxError::SandboxLaunchChanged { .. })
    ));
    assert!(matches!(
        clone.request_kill().await,
        Err(MicrosandboxError::SandboxLaunchChanged { .. })
    ));
    assert!(matches!(
        clone.request_drain().await,
        Err(MicrosandboxError::SandboxLaunchChanged { .. })
    ));
    no_request(&mut socket).await;
}

#[tokio::test]
async fn launch_lifecycle_stopped_snapshot_cannot_remove_after_another_run() {
    let mut fixture = Fixture::new("stopped-lifecycle").await;
    let db = fixture.backend.db().await.unwrap();
    LocalBackend::update_sandbox_status(db.write(), fixture.sandbox_id, SandboxStatus::Stopped)
        .await
        .unwrap();
    let old = fixture.handle().await;
    fixture.new_run().await;
    // Even if that newer run has already stopped, removal must not reinterpret
    // the old stopped snapshot as permission to delete its state.
    assert!(matches!(
        old.remove().await,
        Err(MicrosandboxError::SandboxLaunchChanged { .. })
    ));
    assert!(matches!(
        old.start().await,
        Err(MicrosandboxError::SandboxLaunchChanged { .. })
    ));
    assert!(
        old.refresh().await.is_ok(),
        "explicit refresh returns a new selection"
    );
}

#[tokio::test]
async fn launch_lifecycle_checks_selection_after_waiting_for_transition_lock() {
    let mut fixture = Fixture::new("locked-lifecycle").await;
    let old = fixture.handle().await;
    let guard = LocalBackend::acquire_sandbox_transition_guard(
        &fixture.backend.config().run_dir(),
        &fixture.name,
    )
    .await
    .unwrap();
    let pending = tokio::spawn(async move { old.request_stop().await });
    tokio::task::yield_now().await;
    assert!(!pending.is_finished());
    fixture.new_run().await;
    drop(guard);
    assert!(matches!(
        pending.await.unwrap(),
        Err(MicrosandboxError::SandboxLaunchChanged { .. })
    ));
}

#[tokio::test]
async fn launch_lifecycle_shutdown_uses_verified_retained_peer() {
    let fixture = Fixture::new("retained-shutdown").await;
    let (sandbox, mut socket) = fixture.connected().await;
    assert!(
        !sandbox
            .local()
            .unwrap()
            .observation
            .process
            .as_ref()
            .unwrap()
            .has_exited()
            .unwrap()
    );
    sandbox.request_stop().await.unwrap();
    let message =
        codec::raw_frame_to_message(codec::read_raw_frame(&mut socket).await.unwrap()).unwrap();
    assert_eq!(message.t, MessageType::Shutdown);
}

#[tokio::test]
async fn launch_lifecycle_nonowner_stop_and_wait_refuses_before_shutdown() {
    let fixture = Fixture::new("nonowner-shutdown").await;
    let (sandbox, mut socket) = fixture.connected().await;
    assert!(sandbox.stop_and_wait().await.is_err());
    no_request(&mut socket).await;
}

struct OwnedRuntimeFixture(std::process::Child);

impl OwnedRuntimeFixture {
    fn spawn() -> Self {
        Self(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "backend::local::sandbox::launch_tests::runtime_pidfd_fixture",
                ])
                .env("MSB_TEST_OWNED_PIDFD_CHILD", "1")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                // No new process group: the test supervisor retains cancellation
                // ownership; this guard also reaps on ordinary assertion failures.
                .spawn()
                .unwrap(),
        )
    }
}

impl Drop for OwnedRuntimeFixture {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

#[test]
fn runtime_pidfd_fixture() {
    if std::env::var("MSB_TEST_OWNED_PIDFD_CHILD").as_deref() == Ok("1") {
        std::thread::sleep(Duration::from_secs(60));
    }
}

async fn select_child(fixture: &Fixture, child: &OwnedRuntimeFixture) -> SandboxHandle {
    let db = fixture.backend.db().await.unwrap();
    let mut run: run_entity::ActiveModel = run_entity::Entity::find_by_id(fixture.run_id)
        .one(db.read())
        .await
        .unwrap()
        .unwrap()
        .into();
    run.pid = Set(Some(child.0.id() as i32));
    run.update(db.write()).await.unwrap();
    fixture.handle().await
}

#[tokio::test]
async fn launch_lifecycle_pidfd_observes_exact_owned_child_exit() {
    let fixture = Fixture::new("pidfd-exit").await;
    let mut child = OwnedRuntimeFixture::spawn();
    let handle = select_child(&fixture, &child).await;
    let process = handle
        .local()
        .unwrap()
        .observation
        .process
        .as_ref()
        .unwrap();
    assert!(!process.has_exited().unwrap());
    assert!(
        tokio::time::timeout(
            Duration::from_millis(20),
            process.wait(Duration::from_secs(1))
        )
        .await
        .is_err()
    );
    process.signal(9).unwrap();
    process.wait(Duration::from_secs(2)).await.unwrap();
    assert!(process.has_exited().unwrap());
    assert!(!child.0.wait().unwrap().success());
}

#[tokio::test]
async fn launch_lifecycle_expired_grace_escalates_retained_child_and_observes_exit() {
    use std::os::unix::process::ExitStatusExt;
    let fixture = Fixture::new("pidfd-escalation").await;
    let mut child = OwnedRuntimeFixture::spawn();
    let handle = select_child(&fixture, &child).await;
    let observation = &handle.local().unwrap().observation;
    fixture
        .backend
        .await_bound_runtime_exit_with_grace(&fixture.name, observation, false, Duration::ZERO)
        .await
        .unwrap();
    assert!(observation.process.as_ref().unwrap().has_exited().unwrap());
    assert_eq!(child.0.wait().unwrap().signal(), Some(9));
}

#[tokio::test]
async fn launch_lifecycle_ephemeral_wait_requires_and_observes_retained_exit() {
    let fixture = Fixture::new("ephemeral-exited").await;
    fixture.ephemeral().await;
    let mut child = OwnedRuntimeFixture::spawn();
    let old = select_child(&fixture, &child).await;
    fixture.remove_row().await;
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    let result = tokio::time::timeout(Duration::from_secs(1), old.wait_until_stopped())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result.status, SandboxStatus::Stopped);
    assert_eq!(
        result.exit_code, None,
        "pidfd readiness is not an exit code"
    );
}

#[tokio::test]
async fn launch_lifecycle_retained_exited_runtime_still_requires_ownership_lock() {
    let fixture = Fixture::new("terminal-lock").await;
    let mut child = OwnedRuntimeFixture::spawn();
    let old = select_child(&fixture, &child).await;
    let guard = microsandbox_runtime::ipc::try_acquire_lifecycle_guard(
        &fixture.backend.config().run_dir(),
        &fixture.name,
    )
    .unwrap()
    .unwrap();
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    LocalBackend::update_sandbox_status(
        fixture.backend.db().await.unwrap().write(),
        fixture.sandbox_id,
        SandboxStatus::Stopped,
    )
    .await
    .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(20), old.remove())
            .await
            .is_err()
    );
    assert!(
        sandbox_entity::Entity::find_by_id(fixture.sandbox_id)
            .one(fixture.backend.db().await.unwrap().read())
            .await
            .unwrap()
            .is_some()
    );
    drop(guard);
    old.remove().await.unwrap();
}

#[tokio::test]
async fn launch_lifecycle_escalation_rechecks_run_and_does_not_signal_replacement() {
    let mut fixture = Fixture::new("pidfd-stale-escalation").await;
    let mut child = OwnedRuntimeFixture::spawn();
    let handle = select_child(&fixture, &child).await;
    let observation = handle.local().unwrap().observation.clone();
    fixture
        .backend
        .validate_observation(&fixture.name, &observation)
        .await
        .unwrap();
    // Exercise the post-grace escalation seam with a replacement inserted
    // after the initial selection check, without relying on task scheduling.
    fixture.new_run().await;
    assert!(matches!(
        fixture
            .backend
            .escalate_bound_runtime_exit(&fixture.name, &observation, false)
            .await,
        Err(MicrosandboxError::SandboxLaunchChanged { .. })
    ));
    assert!(
        child.0.try_wait().unwrap().is_none(),
        "stale escalation must not signal even the old owned child"
    );
}
