//! Real-VM CID projection: two live guests and a replacement use independently
//! reserved CIDs. Requires a local runtime, KVM and the runtime-smoke-image
//! archive. Explicitly ignored; no image pull or live-home fallback is allowed.

#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use microsandbox::backend::{Backend, LocalBackend};
use microsandbox::sandbox::PullPolicy;
use microsandbox::{Image, Sandbox};

async fn check_cid(sandbox: &Sandbox, expected: u32) -> Result<(), String> {
    let output = tokio::time::timeout(
        Duration::from_secs(15),
        sandbox.exec("/bin/guest-cid", std::iter::empty::<&str>()),
    )
    .await
    .map_err(|error| error.to_string())?
    .map_err(|error| error.to_string())?;
    if !output.status().success {
        return Err(format!("guest CID probe failed: {:?}", output.stderr()));
    }
    let actual = output.stdout().map_err(|error| error.to_string())?;
    if actual.trim() != expected.to_string() {
        return Err(format!("expected guest CID {expected}, got {actual:?}"));
    }
    Ok(())
}

async fn create(name: &str, cid: u32, route: &std::path::Path) -> Result<Sandbox, String> {
    tokio::time::timeout(
        Duration::from_secs(90),
        Sandbox::builder(name)
            .image("microsandbox-runtime-smoke:test")
            .pull_policy(PullPolicy::Never)
            .cpus(1)
            .memory(256)
            .disable_network()
            .guest_cid(cid)
            .vsock(route, 5000)
            .create(),
    )
    .await
    .map_err(|error| error.to_string())?
    .map_err(|error| error.to_string())
}

#[tokio::test]
#[ignore = "requires KVM, an explicit runtime and the offline runtime smoke archive"]
async fn reserved_cids_reach_fresh_and_replaced_guests() {
    let config_path = PathBuf::from(
        std::env::var_os("MSB_CONFIG_PATH")
            .expect("set MSB_CONFIG_PATH to a nonexistent test path"),
    );
    assert!(
        config_path.is_absolute() && !config_path.exists(),
        "ambient config must not be loaded"
    );
    let runtime = PathBuf::from(std::env::var_os("MSB_PATH").expect("set an explicit MSB_PATH"));
    assert!(runtime.is_absolute() && runtime.is_file());
    let archive = PathBuf::from(
        std::env::var_os("MSB_TEST_IMAGE_ARCHIVE").expect("set MSB_TEST_IMAGE_ARCHIVE"),
    );
    assert!(archive.is_absolute() && archive.is_file());
    // Keep artifacts even on failure; only this fresh backend is cleaned up.
    let root = tempfile::Builder::new()
        .prefix("msb-cid-")
        .tempdir()
        .unwrap()
        .keep();
    eprintln!("CID test artifacts: {}", root.display());
    let route = root.join("service.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&route).unwrap();
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
                .map_err(|error| error.to_string())?;
            let first = create("cid-first", 65_536, &route).await?;
            let second = create("cid-second", 65_537, &route).await?;
            check_cid(&first, 65_536).await?;
            check_cid(&second, 65_537).await?;
            first.stop().await.map_err(|error| error.to_string())?;
            drop(first);
            Sandbox::remove("cid-first")
                .await
                .map_err(|error| error.to_string())?;
            let replacement = create("cid-first", 65_538, &route).await?;
            check_cid(&replacement, 65_538).await?;
            check_cid(&second, 65_537).await?;
            replacement
                .stop()
                .await
                .map_err(|error| error.to_string())?;
            second.stop().await.map_err(|error| error.to_string())?;
            Ok::<(), String>(())
        }
        .await;
        for name in ["cid-first", "cid-second"] {
            if let Ok(handle) = Sandbox::get(name).await {
                handle.kill().await.expect("clean up owned test VM");
                handle.remove().await.expect("remove owned test VM");
            }
        }
        result.expect("fresh/replaced guest CID validation");
    })
    .await;
}
