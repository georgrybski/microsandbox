//! Ordinary managed broker service, without PID 1 initialization or agent console.
//!
//! The host must map the two listen ports to separately protected host sockets.
//! The management socket is owner-only; diverted headers are accepted only after
//! that host route verifies the original launch and destination. A guest-supplied
//! header is not a bearer credential. Upstream trust remains independently pinned.

use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use microsandbox_protocol::broker as wire;
use tokio::task::JoinSet;

use crate::broker::{Broker, ManagedRelay};
use crate::config::BrokerConfig;
use crate::management::{ManagedControl, ManagementError};
use crate::policy::{Launch, RelayContext};
use crate::ssh::TerminationHandle;
use crate::vsock::{VsockListener, VsockStream};

const MAX_RELAYS: usize = 256;
const DIVERT_TIMEOUT: Duration = Duration::from_secs(10);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(20);

/// Help never reads credentials, performs PID 1 initialization or binds a port.
pub const HELP: &str = "Usage: brokerd service --credentials-directory ABS --host-principal NAME --management-port PORT --divert-port PORT --egress-port PORT\n\nRuns an ordinary managed broker service. Supply host-key, host-certificate and host-ca.pub through the explicit credentials directory. Host sockets and verified diversion routing must be provisioned independently.\n";

/// Explicit service inputs; no host key, certificate or trust fallback.
#[derive(Debug, PartialEq, Eq)]
pub struct ServiceOptions {
    /// Absolute systemd credentials directory, never a workload HOME.
    pub credentials_directory: PathBuf,
    /// Exact stable lowercase broker host-certificate principal.
    pub host_principal: String,
    /// HOST-only direct management listen port.
    pub management_port: u32,
    /// HOST-only verified diversion listen port.
    pub divert_port: u32,
    /// Guest-to-host upstream tunnel port.
    pub egress_port: u32,
}

/// Parsed service command, including the strictly nonbinding help operation.
#[derive(Debug, PartialEq, Eq)]
pub enum ServiceCommand {
    /// Print help and return without reading runtime inputs.
    Help,
    /// Run using all required explicit inputs.
    Run(ServiceOptions),
}

/// Safe static diagnostics preserve incomplete cleanup independently of cause.
#[derive(Debug, thiserror::Error)]
#[error("{reason}; owned cleanup incomplete: {cleanup_incomplete}")]
pub struct ServiceError {
    reason: &'static str,
    cleanup_incomplete: bool,
}

fn error(reason: &'static str) -> ServiceError {
    ServiceError {
        reason,
        cleanup_incomplete: false,
    }
}

impl ServiceCommand {
    /// Parse arguments after the literal `service` subcommand. Unknown,
    /// duplicate and incomplete options refuse before any service effects.
    pub fn parse(arguments: &[String]) -> Result<Self, ServiceError> {
        if arguments == ["--help"] || arguments == ["-h"] {
            return Ok(Self::Help);
        }
        let (mut directory, mut principal, mut management, mut divert, mut egress) =
            (None, None, None, None, None);
        if arguments.len() != 10 {
            return Err(error("invalid managed service arguments"));
        }
        for pair in arguments.chunks_exact(2) {
            let value = &pair[1];
            match pair[0].as_str() {
                "--credentials-directory" if directory.is_none() => {
                    directory = Some(PathBuf::from(value))
                }
                "--host-principal" if principal.is_none() => principal = Some(value.clone()),
                "--management-port" if management.is_none() => management = Some(port(value)?),
                "--divert-port" if divert.is_none() => divert = Some(port(value)?),
                "--egress-port" if egress.is_none() => egress = Some(port(value)?),
                _ => return Err(error("invalid managed service arguments")),
            }
        }
        let options = ServiceOptions {
            credentials_directory: directory
                .ok_or_else(|| error("credentials directory required"))?,
            host_principal: principal.ok_or_else(|| error("host principal required"))?,
            management_port: management.ok_or_else(|| error("management port required"))?,
            divert_port: divert.ok_or_else(|| error("divert port required"))?,
            egress_port: egress.ok_or_else(|| error("egress port required"))?,
        };
        if !options.credentials_directory.is_absolute()
            || options.host_principal.is_empty()
            || options.management_port == options.divert_port
            || options.management_port == options.egress_port
            || options.divert_port == options.egress_port
        {
            return Err(error("invalid managed service arguments"));
        }
        Ok(Self::Run(options))
    }
}

fn port(value: &str) -> Result<u32, ServiceError> {
    let port: u32 = value
        .parse()
        .map_err(|_| error("invalid managed service port"))?;
    if port < 1024 || port == u32::MAX || port.to_string() != value {
        return Err(error("invalid managed service port"));
    }
    Ok(port)
}

/// Validate the complete host identity, then run the ordinary systemd service.
/// No console, guest filesystem initialization or network-interface setup runs.
pub async fn run(options: ServiceOptions) -> Result<(), ServiceError> {
    let host = crate::host_identity::load_host_config(
        &options.credentials_directory,
        &options.host_principal,
    )
    .map_err(|_| error("managed broker host identity refused"))?;
    let mut incarnation = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut incarnation))
        .map_err(|_| error("broker incarnation unavailable"))?;
    let broker = Broker::new_managed(
        BrokerConfig::new(options.divert_port, options.egress_port, None),
        host,
        incarnation,
        256,
        MAX_RELAYS,
    )
    .map_err(|_| error("managed broker configuration refused"))?;
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| error("service signal registration failed"))?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .map_err(|_| error("service signal registration failed"))?;
    // Host identity validation precedes both listeners. Binding either listener
    // does not report any launch policy Applied or native upstream readiness.
    let management = VsockListener::bind(options.management_port)
        .map_err(|_| error("management listener unavailable"))?;
    let diversion = VsockListener::bind(options.divert_port)
        .map_err(|_| error("diversion listener unavailable"))?;
    let stop = TerminationHandle::new();
    let mut controls = JoinSet::new();
    let mut relays = JoinSet::new();
    let result = loop {
        tokio::select! {
            _ = term.recv() => break Ok(()),
            _ = interrupt.recv() => break Ok(()),
            result = controls.join_next(), if !controls.is_empty() => {
                if !matches!(result, Some(Ok(Ok(())))) {
                    break Err(error("managed connection retirement incomplete"));
                }
            }
            _ = relays.join_next(), if !relays.is_empty() => {},
            result = accept_protected(|| management.accept()), if controls.is_empty() => {
                match result {
                    Ok(stream) => {
                        let control = match broker.spawn_managed_control(stream) {
                            Ok(control) => control,
                            Err(_) => break Err(error("managed control refused")),
                        };
                        controls.spawn(join_control(control, stop.clone()));
                    }
                    Err(_) => break Err(error("management accept failed")),
                }
            }
            result = accept_protected(|| diversion.accept()), if relays.len() < MAX_RELAYS => {
                match result {
                    Ok(stream) => { relays.spawn(divert(Arc::clone(&broker), stream, options.egress_port, stop.clone())); }
                    Err(_) => break Err(error("diversion accept failed")),
                }
            }
        }
    };
    stop.terminate();
    drop((management, diversion));
    let cleanup = tokio::time::timeout(SHUTDOWN_TIMEOUT, async {
        let complete = drain_owned(&mut controls, &mut relays).await;
        complete
            && broker
                .managed_policy()
                .expect("managed service")
                .lock()
                .await
                .relays_retired()
    })
    .await;
    if !matches!(cleanup, Ok(true)) {
        let mut failure = result
            .err()
            .unwrap_or_else(|| error("managed service stopped"));
        failure.cleanup_incomplete = true;
        return Err(failure);
    }
    result
}

/// Refuse an unauthorized peer without taking down unrelated admitted work.
/// Only the existing vsock peer check produces this explicit denial; actual
/// listener failures still propagate to service supervision.
async fn accept_protected<T, F, Fut>(mut accept: F) -> std::io::Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = std::io::Result<T>>,
{
    loop {
        match accept().await {
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                tokio::task::yield_now().await;
                continue;
            }
            result => return result,
        }
    }
}

async fn drain_owned(controls: &mut JoinSet<Result<(), ()>>, relays: &mut JoinSet<()>) -> bool {
    let mut complete = true;
    while let Some(result) = controls.join_next().await {
        complete &= matches!(result, Ok(Ok(())));
    }
    while let Some(result) = relays.join_next().await {
        complete &= result.is_ok();
    }
    complete
}

async fn join_control(control: ManagedControl, stop: TerminationHandle) -> Result<(), ()> {
    let cancel = control.termination();
    let joined = control.join();
    tokio::pin!(joined);
    let result = tokio::select! {
        result = &mut joined => result,
        _ = stop.terminated() => { cancel.terminate(); joined.await },
    };
    match result {
        Ok(()) | Err(ManagementError::Connection | ManagementError::Refused) => Ok(()),
        Err(ManagementError::RetirementIncomplete { .. }) => Err(()),
    }
}

async fn divert(
    broker: Arc<Broker>,
    mut stream: VsockStream,
    egress_port: u32,
    stop: TerminationHandle,
) {
    let header = tokio::select! {
        _ = stop.terminated() => return,
        result = tokio::time::timeout(DIVERT_TIMEOUT, wire::read_divert(&mut stream)) => {
            match result { Ok(Ok(header)) => header, _ => return }
        },
    };
    let transaction = header.transaction;
    if stop.is_terminated() {
        return;
    }
    let fence = match broker
        .managed_policy()
        .expect("managed service")
        .lock()
        .await
        .fence_for(transaction.session)
    {
        Ok(fence) => fence,
        Err(_) => return,
    };
    let context = RelayContext {
        fence,
        launch: Launch::from_wire(&transaction.launch),
        revision: transaction.revision,
        digest: transaction.policy_digest.bytes(),
        host: header.destination_host,
        port: header.destination_port,
    };
    let host = context.host.clone();
    let port = context.port;
    let relay = match broker
        .spawn_managed_relay(context, stream, async move {
            let mut stream = VsockStream::connect(egress_port).await?;
            crate::egress::open_egress_tunnel(&mut stream, &host, port).await?;
            Ok(stream)
        })
        .await
    {
        Ok(relay) => relay,
        Err(_) => return,
    };
    join_relay(relay, stop).await;
}

async fn join_relay(relay: ManagedRelay, stop: TerminationHandle) {
    let cancel = relay.termination();
    let joined = relay.join();
    tokio::pin!(joined);
    tokio::select! {
        _ = &mut joined => {},
        _ = stop.terminated() => { cancel.terminate(); let _ = joined.await; },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> Vec<String> {
        [
            "--credentials-directory",
            "/run/credentials/broker.service",
            "--host-principal",
            "broker.example",
            "--management-port",
            "3024",
            "--divert-port",
            "3022",
            "--egress-port",
            "3023",
        ]
        .map(String::from)
        .to_vec()
    }

    #[test]
    fn help_is_explicit_and_does_not_need_runtime_inputs() {
        assert_eq!(
            ServiceCommand::parse(&["--help".into()]).unwrap(),
            ServiceCommand::Help
        );
        assert!(ServiceCommand::parse(&[]).is_err());
        assert!(matches!(
            ServiceCommand::parse(&args()).unwrap(),
            ServiceCommand::Run(_)
        ));
    }

    #[test]
    fn duplicate_unknown_relative_and_aliasing_ports_refuse() {
        for (index, value) in [
            (0, "--unknown"),
            (0, "--host-principal"),
            (1, "relative"),
            (5, "3022"),
            (5, "03024"),
            (5, "0"),
            (5, "4294967295"),
        ] {
            let mut arguments = args();
            arguments[index] = value.into();
            assert!(ServiceCommand::parse(&arguments).is_err());
        }
    }

    #[tokio::test]
    async fn peer_denial_is_skipped_but_listener_failure_is_fatal() {
        let mut results = std::collections::VecDeque::from([
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
            Ok(7),
        ]);
        let mut calls = 0;
        assert_eq!(
            accept_protected(|| {
                calls += 1;
                std::future::ready(results.pop_front().unwrap())
            })
            .await
            .unwrap(),
            7
        );
        assert_eq!(calls, 2);
        let result: std::io::Result<()> = accept_protected(|| {
            std::future::ready(Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe)))
        })
        .await;
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn failed_control_cleanup_still_joins_every_relay_owner() {
        let mut controls = JoinSet::new();
        controls.spawn(async { Err(()) });
        let mut relays = JoinSet::new();
        let (sent, received) = tokio::sync::oneshot::channel();
        relays.spawn(async move {
            tokio::task::yield_now().await;
            sent.send(()).unwrap();
        });
        assert!(!drain_owned(&mut controls, &mut relays).await);
        assert!(received.await.is_ok());
        assert!(controls.is_empty() && relays.is_empty());
    }
}
