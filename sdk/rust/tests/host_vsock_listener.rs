//! Real host-listen transport through libkrun and brokerd's host-peer check.
//! Uses disposable network-disabled VMs and an explicit offline smoke image.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use microsandbox::backend::{Backend, LocalBackend};
use microsandbox::sandbox::PullPolicy;
use microsandbox::{Image, Sandbox};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

#[test]
#[ignore = "requires MSB_TEST_OLD_RUNTIME pointing to a real older runtime"]
fn older_runtime_refuses_host_listener_capability_before_startup() {
    use microsandbox_runtime::launch::{
        HOST_VSOCK_LISTEN_CAPABILITY, HostVsockListener, LaunchConfig,
    };
    let old =
        PathBuf::from(std::env::var_os("MSB_TEST_OLD_RUNTIME").expect("set MSB_TEST_OLD_RUNTIME"));
    assert!(old.is_absolute() && old.is_file());
    let root = tempfile::tempdir().unwrap();
    let endpoint = root.path().join("service.sock");
    let runtime_dir = root.path().join("runtime");
    let launch = LaunchConfig {
        db_path: root.path().join("db/msb.db"),
        log_dir: root.path().join("logs"),
        runtime_dir: runtime_dir.clone(),
        sandboxes_dir: root.path().join("sandboxes"),
        run_dir: root.path().join("run"),
        host_vsock_listeners: vec![HostVsockListener {
            host_socket: endpoint.clone(),
            guest_port: 5000,
        }],
        ..Default::default()
    };
    let config = root.path().join("launch.json");
    std::fs::write(&config, serde_json::to_vec(&launch).unwrap()).unwrap();
    let output = std::process::Command::new(old)
        .env_clear()
        .env("HOME", root.path())
        .env("MSB_HOME", root.path().join("msb"))
        .env("MSB_CONFIG_PATH", root.path().join("absent.toml"))
        .current_dir(root.path())
        .args([
            "sandbox",
            "--name",
            "old-runtime-probe",
            "--sandbox-id",
            "1",
            "--config-file",
        ])
        .arg(config)
        .args(["--require-launch-capability", HOST_VSOCK_LISTEN_CAPABILITY])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("unsupported launch capability: host-vsock-listen-v1"),
        "{output:?}"
    );
    assert!(!endpoint.exists());
    assert!(!runtime_dir.exists());
}

async fn create(name: &str, cid: u32, path: &Path, replace: bool) -> Result<Sandbox, String> {
    let mut builder = Sandbox::builder(name)
        .image("microsandbox-runtime-smoke:test")
        .pull_policy(PullPolicy::Never)
        .cpus(1)
        .memory(256)
        .disable_network()
        .guest_cid(cid)
        .vsock_host_listen(path, 5000);
    if replace {
        builder = builder.replace();
    }
    tokio::time::timeout(Duration::from_secs(90), builder.create())
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

async fn start_probe(vm: &Sandbox, token: u32) -> Result<(), String> {
    let command =
        format!("/bin/vsock-guest-probe 5000 /tmp/probe-ready {token} >/tmp/probe.log 2>&1 &");
    let started = vm
        .exec("/bin/sh", ["-c", &command])
        .await
        .map_err(|e| e.to_string())?;
    if !started.status().success {
        return Err(format!("probe launch failed: {:?}", started.stderr()));
    }
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let ready = vm
                .exec("/bin/cat", ["/tmp/probe-ready"])
                .await
                .map_err(|e| e.to_string())?;
            if ready.status().success
                && ready.stdout().map_err(|e| e.to_string())? == token.to_string()
            {
                return Ok::<(), String>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .map_err(|e| format!("broker transport probe not ready: {e}"))?
}

async fn round_trips(path: &Path, seed: usize) -> Result<(), String> {
    tokio::time::timeout(Duration::from_secs(30), async {
        for length in [0, 1, 31, 64, 512, 4096] {
            let payload: Vec<u8> = (0..length).map(|i| ((i * 73 + seed) % 256) as u8).collect();
            let mut stream = UnixStream::connect(path).await.map_err(|e| e.to_string())?;
            stream
                .write_u32(length as u32)
                .await
                .map_err(|e| e.to_string())?;
            for fragment in payload.chunks(7) {
                stream
                    .write_all(fragment)
                    .await
                    .map_err(|e| e.to_string())?;
            }
            let mut actual = vec![0; length];
            stream
                .read_exact(&mut actual)
                .await
                .map_err(|e| e.to_string())?;
            if actual != payload {
                return Err("host/guest byte mismatch".into());
            }
            let mut trailing = [0];
            if stream
                .read(&mut trailing)
                .await
                .map_err(|e| e.to_string())?
                != 0
            {
                return Err("unexpected bytes after probe response".into());
            }
        }
        Ok::<(), String>(())
    })
    .await
    .map_err(|e| format!("host-listen round trip timed out: {e}"))?
}

async fn wait_removed(path: &Path) -> Result<(), String> {
    tokio::time::timeout(Duration::from_secs(5), async {
        while path.exists() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .map_err(|e| {
        format!(
            "owned socket survived normal VMM exit: {}: {e}",
            path.display()
        )
    })
}

#[tokio::test]
#[ignore = "requires KVM, an explicit runtime and the offline runtime smoke archive"]
async fn host_listeners_reach_broker_transport_in_fresh_and_replaced_guests() {
    let config_path = PathBuf::from(
        std::env::var_os("MSB_CONFIG_PATH").expect("set a nonexistent test MSB_CONFIG_PATH"),
    );
    assert!(
        config_path.is_absolute() && !config_path.exists(),
        "ambient config must not be loaded"
    );
    let runtime = PathBuf::from(std::env::var_os("MSB_PATH").expect("set explicit MSB_PATH"));
    assert!(runtime.is_absolute() && runtime.is_file());
    let archive = PathBuf::from(
        std::env::var_os("MSB_TEST_IMAGE_ARCHIVE").expect("set offline MSB_TEST_IMAGE_ARCHIVE"),
    );
    assert!(archive.is_absolute() && archive.is_file());
    let root = tempfile::Builder::new()
        .prefix("msb-listen-")
        .tempdir()
        .unwrap()
        .keep();
    eprintln!("Host-listener test artifacts: {}", root.display());
    let first_path = root.join("first.sock");
    let second_path = root.join("second.sock");
    let replacement_path = root.join("replacement.sock");
    let backend: Arc<dyn Backend> = Arc::new(
        LocalBackend::builder()
            .home(root.join("msb"))
            .build()
            .await
            .unwrap(),
    );
    microsandbox::with_backend(backend, async {
        let result = async {
            Image::load(&archive, Vec::new())
                .await
                .map_err(|e| e.to_string())?;
            let first = create("listen-first", 70_000, &first_path, false).await?;
            let second = create("listen-second", 70_001, &second_path, false).await?;
            start_probe(&first, 70_000).await?;
            start_probe(&second, 70_001).await?;
            tokio::try_join!(round_trips(&first_path, 17), round_trips(&second_path, 29))?;

            if create("listen-collision", 70_002, &first_path, false)
                .await
                .is_ok()
            {
                return Err("occupied listener path did not fail launch".into());
            }
            round_trips(&first_path, 41).await?;
            let replacement = create("listen-first", 70_003, &replacement_path, true).await?;
            wait_removed(&first_path).await?;
            if UnixStream::connect(&first_path).await.is_ok() {
                return Err("old launch endpoint still accepts connections".into());
            }
            start_probe(&replacement, 70_003).await?;
            tokio::try_join!(
                round_trips(&replacement_path, 53),
                round_trips(&second_path, 67)
            )?;
            replacement.stop().await.map_err(|e| e.to_string())?;
            wait_removed(&replacement_path).await?;
            round_trips(&second_path, 79).await?;
            second.stop().await.map_err(|e| e.to_string())?;
            wait_removed(&second_path).await?;
            Ok::<(), String>(())
        }
        .await;
        for name in ["listen-first", "listen-second", "listen-collision"] {
            if let Ok(handle) = Sandbox::get(name).await {
                handle.kill().await.expect("clean up owned test VM");
                handle.remove().await.expect("remove owned test VM");
            }
        }
        result.expect("fresh/replaced host-listener acceptance");
    })
    .await;
}
