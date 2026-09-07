//! Binary entry point for `microsandbox-brokerd`.
//!
//! Runs as PID 1 inside the broker VM. Performs minimal synchronous init
//! (essential filesystems, optional block-root pivot — never guest
//! networking), moves the sealed bootstrap key into custody, then enters
//! the async broker loop.

use std::process;

#[cfg(target_os = "linux")]
use microsandbox_brokerd::{Broker, BrokerConfig, BrokerError, console, init, keys};
#[cfg(target_os = "linux")]
use microsandbox_protocol::bootstrap::GuestBootstrap;

//--------------------------------------------------------------------------------------------------
// Functions: main
//--------------------------------------------------------------------------------------------------

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("brokerd is only supported on Linux");
    process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() {
    if let Err(e) = run() {
        eprintln!("brokerd: {e}");
        process::exit(1);
    }
    process::exit(0);
}

#[cfg(target_os = "linux")]
fn run() -> Result<(), BrokerError> {
    // Mount only what console discovery needs, then receive the typed
    // bootstrap frame that the host queued before entering the VM.
    init::prepare_bootstrap_console()?;
    let port = console::open_agent_port()?;
    let (bootstrap, boot_console) = console::receive_bootstrap(&port)?;

    // Move sealed key material into custody first: without it every later
    // phase would fail closed anyway, so refuse before touching disks.
    // Destructured (not cloned) so no second copy of the seed exists.
    let GuestBootstrap {
        block_root,
        broker_key,
        broker_upstream,
        ..
    } = bootstrap;
    let key = keys::require_bootstrap_key(broker_key)?;

    // Synchronous init. The guest IP stack stays down by design: there is
    // deliberately no network configuration step here.
    init::init(block_root.as_ref())?;

    let config = BrokerConfig::new(
        microsandbox_brokerd::config::SSH_DIVERT_LISTEN_PORT,
        microsandbox_brokerd::config::EGRESS_CONNECT_PORT,
        broker_upstream,
    );
    // The remaining bootstrap fields are dropped here; custody owns the
    // only retained keypair.
    drop(block_root);

    let broker = Broker::new(config, key)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("brokerd: failed to build tokio runtime");
    rt.block_on(async { broker.run(port, boot_console).await })
}
