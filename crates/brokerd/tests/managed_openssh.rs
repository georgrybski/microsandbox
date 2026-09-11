//! Stock OpenSSH against one managed broker with independently retiring launches.
//!
//! Run explicitly with `cargo test -p microsandbox-brokerd --test managed_openssh
//! -- --ignored`. Set `MSB_TEST_SSH` to the selected stock SSH executable.
//! Only disposable loopback endpoints and fresh fixture keys are used. The
//! fixture supplies trusted launch contexts directly; it does not establish
//! authentication of a management socket, guest attribution, or VM integration.

#![cfg(unix)]

use std::collections::BTreeMap;
use std::io;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use microsandbox_brokerd::broker::Broker;
use microsandbox_brokerd::config::BrokerConfig;
use microsandbox_brokerd::error::BrokerResult;
use microsandbox_brokerd::host_identity::load_host_config;
use microsandbox_brokerd::keys::BrokerKey;
use microsandbox_brokerd::policy::{
    ApplyStatus, CredentialBinding, CredentialRecord, Launch, LaunchPolicy, ManagementFence,
    PolicyError, ReadyCredential, RelayContext,
};
use microsandbox_brokerd::ssh::UpstreamPin;
use microsandbox_protocol::bootstrap::BrokerSshKey;
use microsandbox_protocol::broker as wire;
use russh::keys::ssh_key::certificate::{Builder, CertType};
use russh::keys::{Algorithm, PrivateKey, PublicKey, PublicKeyBase64};
use russh::server::{Auth, ChannelOpenHandle, Session};
use russh::{Channel, ChannelId};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};
use tokio::sync::oneshot;
use tokio::task::{JoinHandle, JoinSet};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const CAPTURE_LIMIT: usize = 64 * 1024;
const FINISH: &[u8] = b"finish\n";
// OpenSSH 10.3p1 rejects its certificate-to-raw-key fallback when only the
// certificate algorithm is allowed. These are distinct from negotiation failure.
const CA_REFUSAL: &str = "host key ssh-ed25519 not permitted by HostkeyAlgorithms\r\nCouldn't drop certificate: unknown or unsupported key type\r\n";
const ALIAS_REFUSAL: &str = "Certificate invalid: name is not a listed principal\r\nhost key ssh-ed25519 not permitted by HostkeyAlgorithms\r\nCouldn't drop certificate: unknown or unsupported key type\r\n";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
type Capture = Option<JoinHandle<io::Result<Vec<u8>>>>;

enum ExpectedClient {
    Ready(usize),
    StalePolicy,
    HostRefusal,
}

struct Upstream {
    keys: Arc<Vec<PublicKey>>,
    authenticated: Option<usize>,
    channel: Option<ChannelId>,
    input: Vec<u8>,
    events: Arc<Mutex<Vec<(usize, &'static str)>>>,
}

struct Client {
    child: Child,
    stdout: Capture,
    stderr: Capture,
}

struct Fixture {
    root: tempfile::TempDir,
    certificate_only: bool,
    log_level: &'static str,
    host_alias: &'static str,
    broker: Arc<Broker>,
    fence: ManagementFence,
    upstream: TcpListener,
    upstream_address: SocketAddr,
    upstream_config: Arc<russh::server::Config>,
    custody: Vec<Arc<BrokerKey>>,
    keys: Arc<Vec<PublicKey>>,
    contexts: Vec<RelayContext>,
    dials: Arc<AtomicUsize>,
    events: Arc<Mutex<Vec<(usize, &'static str)>>>,
    clients: Vec<Client>,
    relays: JoinSet<(usize, BrokerResult<()>)>,
    relay_results: BTreeMap<usize, BrokerResult<()>>,
    peers: JoinSet<Result<(), russh::Error>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Upstream {
    fn select(&self, user: &str, key: &PublicKey) -> Option<usize> {
        (user == "git")
            .then(|| {
                self.keys.iter().position(|expected| {
                    expected.algorithm() == key.algorithm() && expected.key_data() == key.key_data()
                })
            })
            .flatten()
    }
}

impl Fixture {
    async fn new(certified: bool) -> TestResult<Self> {
        let root = tempfile::tempdir()?;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
        let guest_key = random_key();
        let private = root.path().join("client_key");
        std::fs::write(
            &private,
            guest_key
                .to_openssh(russh::keys::ssh_key::LineEnding::LF)?
                .as_bytes(),
        )?;
        std::fs::set_permissions(private, std::fs::Permissions::from_mode(0o600))?;
        let server_key = random_key();
        let server = if certified {
            // Only these three files cross the service credential boundary.
            // The fresh issuing CA private key is never written to that directory.
            let ca = random_key();
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let mut builder = Builder::new(
                vec![7; 32],
                server_key.public_key().key_data().clone(),
                now.saturating_sub(10),
                now + 300,
            )?;
            builder.cert_type(CertType::Host)?;
            builder.valid_principal("broker.test")?;
            let certificate = builder.sign(&ca)?;
            let credentials = root.path().join("credentials");
            std::fs::create_dir(&credentials)?;
            std::fs::set_permissions(&credentials, std::fs::Permissions::from_mode(0o700))?;
            for (name, bytes) in [
                (
                    "host-key",
                    server_key
                        .to_openssh(russh::keys::ssh_key::LineEnding::LF)?
                        .to_string(),
                ),
                ("host-certificate", certificate.to_openssh()?),
                ("host-ca.pub", ca.public_key().to_openssh()?),
            ] {
                let path = credentials.join(name);
                std::fs::write(&path, bytes)?;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
            }
            std::fs::write(
                root.path().join("known_hosts"),
                format!(
                    "@cert-authority broker.test {}\n",
                    ca.public_key().to_openssh()?
                ),
            )?;
            load_host_config(&credentials, "broker.test")?
        } else {
            std::fs::write(
                root.path().join("known_hosts"),
                format!(
                    "broker.test {} {}\n",
                    server_key.public_key().algorithm(),
                    server_key.public_key().public_key_base64()
                ),
            )?;
            Arc::new(russh::server::Config {
                keys: vec![server_key],
                auth_rejection_time: Duration::ZERO,
                auth_rejection_time_initial: Some(Duration::ZERO),
                ..Default::default()
            })
        };
        let broker = Broker::new_managed(BrokerConfig::default(), server, [1; 32], 8, 8)?;
        let fence = broker.managed_policy()?.lock().await.connect([2; 32])?;
        let upstream = TcpListener::bind("127.0.0.1:0").await?;
        let upstream_address = upstream.local_addr()?;
        let upstream_config = Arc::new(russh::server::Config {
            keys: vec![random_key()],
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            ..Default::default()
        });
        let mut custody = Vec::new();
        let mut keys = Vec::new();
        for _ in 0..3 {
            let key = random_key();
            keys.push(key.public_key().clone());
            custody.push(Arc::new(BrokerKey::from_bootstrap(BrokerSshKey {
                key_type: "ed25519".into(),
                key_bytes: key
                    .key_data()
                    .ed25519()
                    .ok_or_else(|| io::Error::other("expected Ed25519"))?
                    .private
                    .to_bytes()
                    .to_vec(),
            })?));
        }
        for (index, key) in keys.iter().enumerate() {
            require(
                key.key_data() != guest_key.public_key().key_data(),
                "guest key equals custody key",
            )?;
            require(
                !keys[..index]
                    .iter()
                    .any(|other| other.key_data() == key.key_data()),
                "duplicate custody key",
            )?;
        }
        let contexts = (0..3)
            .map(|index| RelayContext {
                fence,
                launch: Launch {
                    instance: format!("context/workload-{index}/instance"),
                    generation: [index + 10; 32],
                },
                revision: 1,
                digest: [index + 20; 32],
                host: "upstream.test".into(),
                port: upstream_address.port(),
            })
            .collect();
        Ok(Self {
            root,
            certificate_only: certified,
            log_level: "LogLevel=ERROR",
            host_alias: "broker.test",
            broker,
            fence,
            upstream,
            upstream_address,
            upstream_config,
            custody,
            keys: Arc::new(keys),
            contexts,
            dials: Arc::new(AtomicUsize::new(0)),
            events: Arc::new(Mutex::new(Vec::new())),
            clients: Vec::new(),
            relays: JoinSet::new(),
            relay_results: BTreeMap::new(),
            peers: JoinSet::new(),
        })
    }

    async fn install(&self, index: usize) -> TestResult {
        let context = &self.contexts[index];
        let record = ReadyCredential::new(
            CredentialRecord {
                name: "git-key".into(),
                material: format!("owner-{index}/git-key"),
                binding: CredentialBinding::Broker,
                key_version: [index as u8 + 30; 32],
                trust_version: [40; 32],
                host: context.host.clone(),
                port: context.port,
                user: "git".into(),
                on_violation: "block".into(),
            },
            Arc::clone(&self.custody[index]),
            UpstreamPin {
                user: "git".into(),
                expected: self.upstream_config.keys[0].public_key().clone(),
            },
        )?;
        require(
            self.broker.managed_policy()?.lock().await.install(
                self.fence,
                None,
                LaunchPolicy::new(context.launch.clone(), 1, context.digest, vec![record])?,
            )? == ApplyStatus::Applied,
            "fresh policy not applied",
        )
    }

    fn command(&self, port: u16) -> Command {
        let mut command =
            Command::new(std::env::var_os("MSB_TEST_SSH").unwrap_or_else(|| "ssh".into()));
        command
            .env_clear()
            .env("HOME", self.root.path())
            .env("LC_ALL", "C")
            .kill_on_drop(true)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .args([
                "-F",
                "/dev/null",
                "-T",
                "-o",
                "BatchMode=yes",
                "-o",
                "IdentityAgent=none",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "PreferredAuthentications=publickey",
                "-o",
                "PasswordAuthentication=no",
                "-o",
                "KbdInteractiveAuthentication=no",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "GlobalKnownHostsFile=/dev/null",
                "-o",
                "UpdateHostKeys=no",
                "-o",
                self.log_level,
                "-o",
                "ConnectTimeout=5",
                "-o",
                "ConnectionAttempts=1",
            ])
            .arg("-o")
            .arg(format!("HostKeyAlias={}", self.host_alias))
            .arg("-o")
            .arg(format!(
                "UserKnownHostsFile={}",
                self.root.path().join("known_hosts").display()
            ))
            .arg("-i")
            .arg(self.root.path().join("client_key"))
            .arg("-p")
            .arg(port.to_string());
        if self.certificate_only {
            command.args(["-o", "HostKeyAlgorithms=ssh-ed25519-cert-v01@openssh.com"]);
        }
        command.args(["-l", "git", "127.0.0.1", "hold"]);
        command
    }

    async fn start(
        &mut self,
        context: RelayContext,
        expected: ExpectedClient,
    ) -> TestResult<usize> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let mut child = self.command(listener.local_addr()?.port()).spawn()?;
        let (ready_tx, ready_rx) = oneshot::channel();
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("missing stdout"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| io::Error::other("missing stderr"))?;
        let ready = matches!(expected, ExpectedClient::Ready(_)).then_some(ready_tx);
        let index = self.clients.len();
        self.clients.push(Client {
            child,
            stdout: Some(tokio::spawn(capture(stdout, ready))),
            stderr: Some(tokio::spawn(capture(stderr, None))),
        });
        let (guest, _) = listener.accept().await?;
        let dials = Arc::clone(&self.dials);
        let address = self.upstream_address;
        let relay = self
            .broker
            .spawn_managed_relay(context, guest, async move {
                dials.fetch_add(1, Ordering::SeqCst);
                Ok(TcpStream::connect(address).await?)
            })
            .await;
        if let ExpectedClient::Ready(expected) = expected {
            let relay = relay?;
            self.relays
                .spawn(async move { (index, relay.join().await) });
            let (stream, _) = self.upstream.accept().await?;
            let config = Arc::clone(&self.upstream_config);
            let handler = Upstream {
                keys: Arc::clone(&self.keys),
                authenticated: None,
                channel: None,
                input: Vec::new(),
                events: Arc::clone(&self.events),
            };
            self.peers.spawn(async move {
                russh::server::run_stream(config, stream, handler)
                    .await?
                    .await
            });
            require(
                ready_rx.await? == format!("ready:{expected}\n").as_bytes(),
                "wrong launch key reached upstream",
            )?;
        } else if matches!(expected, ExpectedClient::HostRefusal) {
            let relay = relay?;
            self.relays
                .spawn(async move { (index, relay.join().await) });
        } else {
            match relay {
                Err(PolicyError::StalePolicy) => {}
                Ok(relay) => {
                    self.relays
                        .spawn(async move { (index, relay.join().await) });
                    return Err(io::Error::other("stale tuple was admitted").into());
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(index)
    }

    async fn result(
        &mut self,
        index: usize,
    ) -> TestResult<(std::process::ExitStatus, Vec<u8>, Vec<u8>)> {
        let client = &mut self.clients[index];
        let status = client.child.wait().await?;
        let stdout = finish_capture(&mut client.stdout).await?;
        let stderr = finish_capture(&mut client.stderr).await?;
        Ok((status, stdout, stderr))
    }

    async fn relay_result(&mut self, index: usize) -> TestResult<BrokerResult<()>> {
        while !self.relay_results.contains_key(&index) {
            let (owner, result) = self
                .relays
                .join_next()
                .await
                .ok_or_else(|| io::Error::other("missing relay owner"))??;
            self.relay_results.insert(owner, result);
        }
        Ok(self
            .relay_results
            .remove(&index)
            .expect("observed owned relay"))
    }

    async fn finish(&mut self, client: usize, launch: usize) -> TestResult {
        self.clients[client]
            .child
            .stdin
            .as_mut()
            .ok_or_else(|| io::Error::other("missing stdin"))?
            .write_all(FINISH)
            .await?;
        self.clients[client].child.stdin.take();
        let (status, stdout, stderr) = self.result(client).await?;
        require(
            status.code() == Some(17 + launch as i32),
            "wrong upstream exit status",
        )?;
        require(
            stdout == format!("ready:{launch}\nbody\0{launch}\n").as_bytes(),
            "stdout changed",
        )?;
        require(
            stderr == format!("err:{launch}\n").as_bytes(),
            "stderr changed",
        )?;
        self.relay_result(client).await??;
        Ok(())
    }

    async fn exercise(&mut self) -> TestResult {
        self.install(0).await?;
        self.install(1).await?;
        let first = self
            .start(self.contexts[0].clone(), ExpectedClient::Ready(0))
            .await?;
        let second = self
            .start(self.contexts[1].clone(), ExpectedClient::Ready(1))
            .await?;
        require(
            self.clients[first].child.try_wait()?.is_none()
                && self.clients[second].child.try_wait()?.is_none(),
            "sessions were not simultaneously live",
        )?;
        let dials_before = self.dials.load(Ordering::SeqCst);
        let events_before = self.events.lock().unwrap().clone();
        let mut relabeled = self.contexts[0].clone();
        relabeled.launch.instance = self.contexts[1].launch.instance.clone();
        let mut stale = self.contexts[0].clone();
        stale.launch.generation = [99; 32];
        for context in [relabeled, stale] {
            let denied = self.start(context, ExpectedClient::StalePolicy).await?;
            let (status, stdout, _) = self.result(denied).await?;
            require(
                status.code() == Some(255) && stdout.is_empty(),
                "stale SSH unexpectedly succeeded",
            )?;
            require(
                self.dials.load(Ordering::SeqCst) == dials_before
                    && *self.events.lock().unwrap() == events_before,
                "stale tuple caused an upstream effect",
            )?;
        }
        // The third policy arrives after two actual SSH sessions exist.
        self.install(2).await?;
        let third = self
            .start(self.contexts[2].clone(), ExpectedClient::Ready(2))
            .await?;
        let first_context = self.contexts[0].clone();
        require(
            self.broker.managed_policy()?.lock().await.install(
                self.fence,
                Some(1),
                LaunchPolicy::new(first_context.launch.clone(), 2, [50; 32], vec![])?,
            )? == ApplyStatus::Pending,
            "active revocation skipped retirement",
        )?;
        let (status, stdout, _) = self.result(first).await?;
        require(
            status.code() == Some(255) && stdout == b"ready:0\n",
            "revoked command completed normally",
        )?;
        require(
            self.relay_result(first).await?.is_err(),
            "revoked relay claimed normal completion",
        )?;
        require(
            self.broker.managed_policy()?.lock().await.finish(
                self.fence,
                &first_context.launch,
                2,
                [50; 32],
            )? == ApplyStatus::Applied,
            "joined revoke stayed pending",
        )?;
        require(
            self.clients[second].child.try_wait()?.is_none()
                && self.clients[third].child.try_wait()?.is_none(),
            "revocation affected another launch",
        )?;
        self.finish(second, 1).await?;
        // A terminal destroyed policy is distinct from the first empty revoke.
        let destroyed = wire::Policy {
            destroyed: true,
            credentials: vec![],
            patterns: vec![],
        };
        let digest = wire::policy_digest(&destroyed)?.bytes();
        require(
            self.broker.managed_policy()?.lock().await.install(
                self.fence,
                Some(1),
                LaunchPolicy::from_wire(self.contexts[1].launch.clone(), 2, digest, destroyed)?,
            )? == ApplyStatus::Applied,
            "finished launch did not destroy",
        )?;
        require(
            self.clients[third].child.try_wait()?.is_none(),
            "destroy affected another launch",
        )?;
        self.finish(third, 2).await?;
        require(
            self.dials.load(Ordering::SeqCst) == 3,
            "unexpected upstream dial count",
        )?;
        let events = self.events.lock().unwrap();
        for launch in 0..3 {
            require(
                events
                    .iter()
                    .filter(|row| **row == (launch, "auth"))
                    .count()
                    == 1
                    && events
                        .iter()
                        .filter(|row| **row == (launch, "exec"))
                        .count()
                        == 1,
                "wrong per-launch authentication or command count",
            )?;
        }
        Ok(())
    }

    async fn host_refusal(&mut self, expected_diagnostic: &str, exact: bool) -> TestResult {
        self.install(0).await?;
        let client = self
            .start(self.contexts[0].clone(), ExpectedClient::HostRefusal)
            .await?;
        let (status, stdout, stderr) = self.result(client).await?;
        require(
            status.code() == Some(255) && stdout.is_empty(),
            "host trust refusal did not fail SSH",
        )?;
        if !host_diagnostic_matches(&stderr, expected_diagnostic, exact) {
            // All inputs belong to this synthetic fixture. Keep a bounded
            // diagnostic without replacing the specific refusal oracle.
            return Err(io::Error::other(format!(
                "missing specific host trust refusal; stderr ({} bytes): {:?}",
                stderr.len(),
                String::from_utf8_lossy(&stderr[..stderr.len().min(2048)])
            ))
            .into());
        }
        require(
            self.relay_result(client).await?.is_err(),
            "host trust refusal completed relay normally",
        )?;
        require(
            self.dials.load(Ordering::SeqCst) == 0 && self.events.lock().unwrap().is_empty(),
            "host trust refusal caused upstream effect",
        )
    }

    async fn cleanup(&mut self) -> TestResult {
        // Keep all ownership in the fixture even when the main deadline fires.
        let mut errors = Vec::new();
        match self.broker.managed_policy() {
            Ok(policy) => {
                if let Err(error) = policy.lock().await.state_lost(self.fence) {
                    errors.push(format!("policy retirement: {error}"));
                }
            }
            Err(error) => errors.push(format!("policy owner: {error}")),
        }
        for client in &mut self.clients {
            let running = match client.child.try_wait() {
                Ok(status) => status.is_none(),
                Err(error) => {
                    errors.push(format!("child observation: {error}"));
                    true
                }
            };
            if running {
                if let Err(error) = client.child.start_kill() {
                    errors.push(format!("child stop: {error}"));
                }
            }
            if let Err(error) = client.child.wait().await {
                errors.push(format!("child reap: {error}"));
            }
            for output in [&mut client.stdout, &mut client.stderr] {
                if let Some(task) = output.take() {
                    match task.await {
                        Ok(Ok(_)) => {}
                        Ok(Err(error)) => errors.push(format!("capture: {error}")),
                        Err(error) => errors.push(format!("capture join: {error}")),
                    }
                }
            }
        }
        while let Some(result) = self.relays.join_next().await {
            if let Err(error) = result {
                errors.push(format!("relay join: {error}"));
            }
        }
        while let Some(result) = self.peers.join_next().await {
            if let Err(error) = result {
                errors.push(format!("upstream join: {error}"));
            }
        }
        // A fresh management connection is refused while any transport lease
        // remains. Exercise that public contract instead of treating an outer
        // task join or expected SSH protocol failure as a retirement receipt.
        match self.broker.managed_policy() {
            Ok(policy) => {
                let mut policy = policy.lock().await;
                match policy.connect([3; 32]) {
                    Ok(fence) => match policy.state_lost(fence) {
                        Ok(ApplyStatus::Applied) => {}
                        result => errors.push(format!("final policy retirement: {result:?}")),
                    },
                    Err(error) => errors.push(format!("final admission retirement: {error}")),
                }
            }
            Err(error) => errors.push(format!("final policy owner: {error}")),
        }
        if !errors.is_empty() {
            return Err(io::Error::other(errors.join("; ")).into());
        }
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl russh::server::Handler for Upstream {
    type Error = russh::Error;

    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(if self.select(user, key).is_some() {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn auth_publickey(&mut self, user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        self.authenticated = self.select(user, key);
        if let Some(index) = self.authenticated {
            self.events.lock().unwrap().push((index, "auth"));
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<russh::server::Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        command: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(index) = self.authenticated else {
            return Err(russh::Error::Disconnect);
        };
        if command != b"hold" || self.channel.is_some() {
            return Err(russh::Error::Disconnect);
        }
        self.channel = Some(channel);
        self.events.lock().unwrap().push((index, "exec"));
        session.channel_success(channel)?;
        session.data(channel, format!("ready:{index}\n").into_bytes())?;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.channel != Some(channel) || self.input.len() + data.len() > FINISH.len() {
            return Err(russh::Error::Disconnect);
        }
        self.input.extend_from_slice(data);
        if !FINISH.starts_with(&self.input) {
            return Err(russh::Error::Disconnect);
        }
        if self.input == FINISH {
            let index = self.authenticated.ok_or(russh::Error::Disconnect)?;
            self.channel = None;
            session.data(channel, format!("body\0{index}\n").into_bytes())?;
            session.extended_data(channel, 1, format!("err:{index}\n").into_bytes())?;
            session.exit_status_request(channel, 17 + index as u32)?;
            session.eof(channel)?;
            session.close(channel)?;
        }
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn random_key() -> PrivateKey {
    PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap()
}

fn require(condition: bool, message: &'static str) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(io::Error::other(message).into())
    }
}

fn host_diagnostic_matches(stderr: &[u8], expected: &str, exact: bool) -> bool {
    if exact {
        stderr == expected.as_bytes()
    } else {
        String::from_utf8_lossy(stderr).contains(expected)
    }
}

async fn capture<R: AsyncRead + Unpin>(
    reader: R,
    ready: Option<oneshot::Sender<Vec<u8>>>,
) -> io::Result<Vec<u8>> {
    let mut limited = reader.take((CAPTURE_LIMIT + 1) as u64);
    let mut bytes = Vec::new();
    if let Some(ready) = ready {
        bytes.resize(8, 0);
        limited.read_exact(&mut bytes).await?;
        let _ = ready.send(bytes.clone());
    }
    limited.read_to_end(&mut bytes).await?;
    if bytes.len() > CAPTURE_LIMIT {
        return Err(io::Error::other("SSH output bound exceeded"));
    }
    Ok(bytes)
}

async fn finish_capture(capture: &mut Capture) -> TestResult<Vec<u8>> {
    let result = capture
        .as_mut()
        .ok_or_else(|| io::Error::other("missing capture owner"))?
        .await;
    capture.take();
    Ok(result??)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn certificate_refusal_diagnostics_are_exact_and_distinct() {
    for expected in [CA_REFUSAL, ALIAS_REFUSAL] {
        assert!(host_diagnostic_matches(expected.as_bytes(), expected, true));
        let extra = format!("{expected}unexpected\r\n");
        for wrong in [
            b"Host key verification failed.\r\n".as_slice(),
            b"Permission denied (publickey).\r\n".as_slice(),
            b"".as_slice(),
            &expected.as_bytes()[..expected.len() - 1],
            extra.as_bytes(),
        ] {
            assert!(!host_diagnostic_matches(wrong, expected, true));
        }
    }
    assert!(!host_diagnostic_matches(
        CA_REFUSAL.as_bytes(),
        ALIAS_REFUSAL,
        true
    ));
    assert!(!host_diagnostic_matches(
        ALIAS_REFUSAL.as_bytes(),
        CA_REFUSAL,
        true
    ));
}

#[tokio::test]
#[ignore = "requires explicit stock OpenSSH and disposable loopback listeners; no VM"]
async fn managed_openssh_keeps_launch_keys_and_retirement_independent() {
    let mut fixture = Fixture::new(false).await.expect("private native fixture");
    let result = tokio::time::timeout(Duration::from_secs(45), fixture.exercise()).await;
    let cleanup = tokio::time::timeout(Duration::from_secs(15), fixture.cleanup()).await;
    assert!(
        matches!(&result, Ok(Ok(()))) && matches!(&cleanup, Ok(Ok(()))),
        "managed OpenSSH acceptance: {result:?}; owned cleanup: {cleanup:?}"
    );
}

#[tokio::test]
#[ignore = "requires explicit stock OpenSSH and disposable loopback listeners; no VM"]
async fn managed_openssh_host_certificate_preserves_independent_launches() {
    let mut fixture = Fixture::new(true).await.expect("private certified fixture");
    let result = tokio::time::timeout(Duration::from_secs(45), fixture.exercise()).await;
    let cleanup = tokio::time::timeout(Duration::from_secs(15), fixture.cleanup()).await;
    assert!(
        matches!(&result, Ok(Ok(()))) && matches!(&cleanup, Ok(Ok(()))),
        "certified OpenSSH acceptance: {result:?}; owned cleanup: {cleanup:?}"
    );
}

#[tokio::test]
#[ignore = "requires explicit stock OpenSSH and disposable loopback listeners; no VM"]
async fn managed_openssh_certificate_trust_refuses_before_upstream_use() {
    for case in ["wrong-ca", "wrong-alias", "raw-server"] {
        let mut fixture = Fixture::new(case != "raw-server")
            .await
            .expect("private trust fixture");
        fixture.certificate_only = true;
        let diagnostic = if case == "wrong-ca" {
            std::fs::write(
                fixture.root.path().join("known_hosts"),
                format!(
                    "@cert-authority broker.test {}\n",
                    random_key().public_key().to_openssh().unwrap()
                ),
            )
            .unwrap();
            CA_REFUSAL
        } else if case == "wrong-alias" {
            let path = fixture.root.path().join("known_hosts");
            let known_hosts = std::fs::read_to_string(&path).unwrap();
            std::fs::write(path, known_hosts.replacen("broker.test", "wrong.test", 1)).unwrap();
            fixture.host_alias = "wrong.test";
            ALIAS_REFUSAL
        } else {
            // OpenSSH reports key-exchange negotiation failures at INFO,
            // including when it exits 255. Retain that specific diagnostic.
            fixture.log_level = "LogLevel=INFO";
            "no matching host key type found."
        };
        let result = tokio::time::timeout(
            Duration::from_secs(15),
            fixture.host_refusal(diagnostic, case != "raw-server"),
        )
        .await;
        let cleanup = tokio::time::timeout(Duration::from_secs(15), fixture.cleanup()).await;
        assert!(
            matches!(&result, Ok(Ok(()))) && matches!(&cleanup, Ok(Ok(()))),
            "certificate refusal {case}: {result:?}; owned cleanup: {cleanup:?}"
        );
    }
}
