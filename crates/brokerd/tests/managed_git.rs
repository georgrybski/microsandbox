//! Real Git clone/fetch/push through certified stock SSH and managed custody.
//!
//! Run explicitly with `cargo test -p microsandbox-brokerd --test managed_git
//! -- --ignored`. MSB_TEST_GIT, MSB_TEST_SSH and MSB_TEST_SHELL select immutable
//! executables. Only fresh repositories, fixture keys and loopback are used.
//! Trusted launch contexts are injected here; this is not guest attribution or
//! a test of the management service's transport authentication.

#![cfg(unix)]

use std::collections::BTreeMap;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use microsandbox_brokerd::broker::Broker;
use microsandbox_brokerd::config::BrokerConfig;
use microsandbox_brokerd::error::{BrokerError, BrokerResult};
use microsandbox_brokerd::host_identity::load_host_config;
use microsandbox_brokerd::keys::BrokerKey;
use microsandbox_brokerd::policy::{
    ApplyStatus, CredentialBinding, CredentialRecord, Launch, LaunchPolicy, ManagementFence,
    ReadyCredential, RelayContext,
};
use microsandbox_brokerd::ssh::UpstreamPin;
use microsandbox_protocol::bootstrap::BrokerSshKey;
use russh::keys::ssh_key::certificate::{Builder, CertType};
use russh::keys::{Algorithm, PrivateKey, PublicKey};
use russh::server::{Auth, ChannelOpenHandle, Session};
use russh::{Channel, ChannelId, ChannelMsg};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const OUTPUT_LIMIT: u64 = 8 * 1024 * 1024;
const PIPE_TIMEOUT: Duration = Duration::from_secs(5);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
type Capture = Option<JoinHandle<io::Result<Vec<u8>>>>;
type GitJobs = Arc<Mutex<Vec<JoinHandle<TestResult>>>>;
type Events = Arc<Mutex<Vec<(usize, &'static str)>>>;

#[derive(Clone)]
struct Tools {
    git: PathBuf,
    ssh: PathBuf,
    shell: PathBuf,
    home: PathBuf,
}

struct OwnedClient {
    child: Child,
    stdout: Capture,
    stderr: Capture,
}

struct Upstream {
    tools: Tools,
    keys: Arc<Vec<PublicKey>>,
    repositories: Arc<Vec<PathBuf>>,
    selected: Option<usize>,
    channels: BTreeMap<ChannelId, Channel<russh::server::Msg>>,
    jobs: GitJobs,
    events: Events,
    stop: watch::Receiver<bool>,
}

struct Fixture {
    phase: &'static str,
    root: tempfile::TempDir,
    tools: Tools,
    broker: Arc<Broker>,
    fence: ManagementFence,
    contexts: Vec<RelayContext>,
    keys: Arc<Vec<PublicKey>>,
    repositories: Arc<Vec<PathBuf>>,
    upstream: TcpListener,
    upstream_config: Arc<russh::server::Config>,
    events: Events,
    jobs: GitJobs,
    stop: watch::Sender<bool>,
    owned_jobs: Vec<JoinHandle<TestResult>>,
    clients: Vec<OwnedClient>,
    relays: JoinSet<BrokerResult<()>>,
    peers: JoinSet<Result<(), russh::Error>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Tools {
    fn load(home: &Path) -> TestResult<Self> {
        fn selected(name: &str) -> TestResult<PathBuf> {
            let path = PathBuf::from(std::env::var_os(name).ok_or("explicit tool required")?);
            let canonical = path.canonicalize()?;
            require(
                canonical.starts_with("/nix/store") && canonical.is_file(),
                "fixture executable is not an immutable store file",
            )?;
            Ok(canonical)
        }
        Ok(Self {
            git: selected("MSB_TEST_GIT")?,
            ssh: selected("MSB_TEST_SSH")?,
            shell: selected("MSB_TEST_SHELL")?,
            home: home.to_owned(),
        })
    }

    fn git(&self, cwd: &Path) -> Command {
        let mut command = Command::new(&self.git);
        command
            .env_clear()
            .env("HOME", &self.home)
            .env("LC_ALL", "C")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_TEMPLATE_DIR", self.home.join("empty"))
            .env("GIT_AUTHOR_NAME", "Fixture")
            .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
            .env("GIT_COMMITTER_NAME", "Fixture")
            .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
            .env("GIT_AUTHOR_DATE", "2001-01-01T00:00:00Z")
            .env("GIT_COMMITTER_DATE", "2001-01-01T00:00:00Z")
            .current_dir(cwd)
            .kill_on_drop(true)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .args([
                "-c",
                "gc.auto=0",
                "-c",
                "maintenance.auto=false",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "tag.gpgsign=false",
                "-c",
                "core.autocrlf=false",
                "-c",
                "protocol.allow=never",
                "-c",
                "protocol.file.allow=always",
                "-c",
                "protocol.ssh.allow=always",
            ])
            .arg("-c")
            .arg(format!(
                "core.hooksPath={}",
                self.home.join("empty").display()
            ));
        command
    }
}

impl Fixture {
    async fn new() -> TestResult<Self> {
        let root = tempfile::tempdir()?;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
        let tools = Tools::load(root.path())?;
        std::fs::create_dir(root.path().join("empty"))?;
        let guest_key = random_key();
        write_private(
            &root.path().join("client-key"),
            &guest_key.to_openssh(russh::keys::ssh_key::LineEnding::LF)?,
        )?;
        let ca = random_key();
        let host = random_key();
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let mut certificate = Builder::new(
            vec![9; 32],
            host.public_key().key_data().clone(),
            now - 10,
            now + 300,
        )?;
        certificate.cert_type(CertType::Host)?;
        certificate.valid_principal("broker.test")?;
        let credentials = root.path().join("credentials");
        std::fs::create_dir(&credentials)?;
        std::fs::set_permissions(&credentials, std::fs::Permissions::from_mode(0o700))?;
        write_private(
            &credentials.join("host-key"),
            &host.to_openssh(russh::keys::ssh_key::LineEnding::LF)?,
        )?;
        write_private(
            &credentials.join("host-certificate"),
            &certificate.sign(&ca)?.to_openssh()?,
        )?;
        write_private(
            &credentials.join("host-ca.pub"),
            &ca.public_key().to_openssh()?,
        )?;
        write_private(
            &root.path().join("known_hosts"),
            &format!(
                "@cert-authority broker.test {}\n",
                ca.public_key().to_openssh()?
            ),
        )?;
        let broker = Broker::new_managed(
            BrokerConfig::default(),
            load_host_config(&credentials, "broker.test")?,
            [1; 32],
            4,
            8,
        )?;
        let fence = broker.managed_policy()?.lock().await.connect([2; 32])?;
        let upstream = TcpListener::bind("127.0.0.1:0").await?;
        let upstream_config = Arc::new(russh::server::Config {
            keys: vec![random_key()],
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            ..Default::default()
        });
        let mut keys = Vec::new();
        let mut contexts = Vec::new();
        for index in 0..2u8 {
            let private = random_key();
            keys.push(private.public_key().clone());
            require(
                private.public_key().key_data() != guest_key.public_key().key_data(),
                "guest key equals custody key",
            )?;
            let custody = Arc::new(BrokerKey::from_bootstrap(BrokerSshKey {
                key_type: "ed25519".into(),
                key_bytes: private
                    .key_data()
                    .ed25519()
                    .ok_or("Ed25519 fixture key required")?
                    .private
                    .to_bytes()
                    .to_vec(),
            })?);
            let context = RelayContext {
                fence,
                launch: Launch {
                    instance: format!("context/repo-{index}/instance"),
                    generation: [index + 10; 32],
                },
                revision: 1,
                digest: [index + 20; 32],
                host: "upstream.test".into(),
                port: upstream.local_addr()?.port(),
            };
            let credential = ReadyCredential::new(
                CredentialRecord {
                    name: "git-key".into(),
                    material: format!("owner-{index}/git-key"),
                    binding: CredentialBinding::Broker,
                    key_version: [index + 30; 32],
                    trust_version: [40; 32],
                    host: context.host.clone(),
                    port: context.port,
                    user: "git".into(),
                    on_violation: "block".into(),
                },
                custody,
                UpstreamPin {
                    user: "git".into(),
                    expected: upstream_config.keys[0].public_key().clone(),
                },
            )?;
            require(
                broker.managed_policy()?.lock().await.install(
                    fence,
                    None,
                    LaunchPolicy::new(context.launch.clone(), 1, context.digest, vec![credential])?,
                )? == ApplyStatus::Applied,
                "launch policy was not applied",
            )?;
            contexts.push(context);
        }
        require(
            keys[0].key_data() != keys[1].key_data(),
            "custody keys collide",
        )?;
        let repositories = Arc::new(
            (0..2)
                .map(|index| root.path().join(format!("bare-{index}")))
                .collect(),
        );
        let (stop, _) = watch::channel(false);
        Ok(Self {
            phase: "initialized",
            root,
            tools,
            broker,
            fence,
            contexts,
            keys: Arc::new(keys),
            repositories,
            upstream,
            upstream_config,
            events: Arc::new(Mutex::new(Vec::new())),
            jobs: Arc::new(Mutex::new(Vec::new())),
            stop,
            owned_jobs: Vec::new(),
            clients: Vec::new(),
            relays: JoinSet::new(),
            peers: JoinSet::new(),
        })
    }

    fn start_client(&mut self, mut command: Command) -> TestResult<usize> {
        let mut child = command.spawn()?;
        let stdout = child.stdout.take().ok_or("missing stdout pipe")?;
        let stderr = child.stderr.take().ok_or("missing stderr pipe")?;
        let index = self.clients.len();
        self.clients.push(OwnedClient {
            child,
            stdout: Some(tokio::spawn(capture(stdout))),
            stderr: Some(tokio::spawn(capture(stderr))),
        });
        Ok(index)
    }

    async fn client_result(&mut self, index: usize) -> TestResult<(ExitStatus, Vec<u8>, Vec<u8>)> {
        let client = &mut self.clients[index];
        let status = client.child.wait().await?;
        let stdout = finish_capture(&mut client.stdout).await?;
        let stderr = finish_capture(&mut client.stderr).await?;
        Ok((status, stdout, stderr))
    }

    async fn local(&mut self, cwd: &Path, arguments: &[&str]) -> TestResult<Vec<u8>> {
        self.phase = "local Git child";
        eprintln!("local Git begin: {}", arguments[0]);
        let mut command = self.tools.git(cwd);
        command.args(arguments);
        let index = self.start_client(command)?;
        let (status, stdout, stderr) = self.client_result(index).await?;
        eprintln!("local Git complete: {}; {status}", arguments[0]);
        if !status.success() {
            return Err(io::Error::other(format!(
                "fixture Git {arguments:?} failed: {status}; {:?}",
                String::from_utf8_lossy(&stderr[..stderr.len().min(2048)])
            ))
            .into());
        }
        Ok(stdout)
    }

    async fn network(
        &mut self,
        launch: usize,
        repository: usize,
        cwd: &Path,
        verb: &str,
        extra: &[&str],
    ) -> TestResult<bool> {
        eprintln!("network Git begin: launch={launch} repository={repository} verb={verb}");
        let expected_denial = launch != repository;
        let snapshots = if expected_denial {
            Some([self.snapshot(0).await?, self.snapshot(1).await?])
        } else {
            None
        };
        let event_start = self.events.lock().unwrap().len();
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let config = self.root.path().join("ssh-config");
        write_private(
            &config,
            &format!(
                "Host *\n  HostName 127.0.0.1\n  Port {}\n  User git\n  BatchMode yes\n  IdentityAgent none\n  IdentitiesOnly yes\n  IdentityFile {}\n  PreferredAuthentications publickey\n  PasswordAuthentication no\n  KbdInteractiveAuthentication no\n  StrictHostKeyChecking yes\n  GlobalKnownHostsFile /dev/null\n  UserKnownHostsFile {}\n  HostKeyAlias broker.test\n  HostKeyAlgorithms ssh-ed25519-cert-v01@openssh.com\n  UpdateHostKeys no\n  LogLevel ERROR\n  ConnectTimeout 5\n  ConnectionAttempts 1\n",
                listener.local_addr()?.port(),
                self.root.path().join("client-key").display(),
                self.root.path().join("known_hosts").display()
            ),
        )?;
        let wrapper = self.root.path().join("git-ssh");
        // The shell executes one fixed tool only. Git's arguments are forwarded
        // as argv, never evaluated as a shell command or repository path.
        write_private(
            &wrapper,
            &format!(
                "#!{}\nexec {} -F {} \"$@\"\n",
                self.tools.shell.display(),
                shell_quote(&self.tools.ssh),
                shell_quote(&config)
            ),
        )?;
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700))?;
        let mut command = self.tools.git(cwd);
        command
            .env("GIT_SSH", wrapper)
            .env("GIT_SSH_VARIANT", "ssh");
        command
            .arg(verb)
            .arg(format!("ssh://git@127.0.0.1/repo-{repository}"))
            .args(extra);
        let client = self.start_client(command)?;
        self.phase = "accept stock SSH client";
        let (guest, _) = listener.accept().await?;
        eprintln!("network Git: stock SSH accepted");
        let address = self.upstream.local_addr()?;
        self.phase = "start managed relay";
        let relay = self
            .broker
            .spawn_managed_relay(self.contexts[launch].clone(), guest, async move {
                Ok(TcpStream::connect(address).await?)
            })
            .await?;
        self.relays.spawn(relay.join());
        self.phase = "accept upstream SSH";
        let (socket, _) = self.upstream.accept().await?;
        eprintln!("network Git: upstream SSH accepted");
        let handler = Upstream {
            tools: self.tools.clone(),
            keys: Arc::clone(&self.keys),
            repositories: Arc::clone(&self.repositories),
            selected: None,
            channels: BTreeMap::new(),
            jobs: Arc::clone(&self.jobs),
            events: Arc::clone(&self.events),
            stop: self.stop.subscribe(),
        };
        let config = Arc::clone(&self.upstream_config);
        self.peers.spawn(async move {
            russh::server::run_stream(config, socket, handler)
                .await?
                .await
        });
        self.phase = "wait Git client and pipes";
        let (status, stdout, stderr) = self.client_result(client).await?;
        eprintln!(
            "network Git client complete: {status}; stdout_bytes={} stderr_bytes={}",
            stdout.len(),
            stderr.len()
        );
        if let Some(snapshots) = snapshots {
            require(
                status.code() == Some(128),
                "denied Git request did not exit 128",
            )?;
            require(stdout.is_empty(), "denied Git request returned stdout")?;
            {
                let events = self.events.lock().unwrap();
                let current = &events[event_start..];
                require(
                    current
                        .iter()
                        .filter(|event| **event == (launch, "denied"))
                        .count()
                        == 1,
                    "missing exact upstream denial event",
                )?;
                require(
                    !current
                        .iter()
                        .any(|(_, event)| matches!(*event, "upload" | "receive")),
                    "denied request spawned Git server",
                )?;
            }
            require(
                snapshots == [self.snapshot(0).await?, self.snapshot(1).await?],
                "denied request changed refs or objects",
            )?;
        }
        self.finish_sessions(expected_denial).await?;
        if launch == repository && !status.success() {
            return Err(io::Error::other(format!(
                "network Git {verb} failed: {status}; {:?}",
                String::from_utf8_lossy(&stderr[..stderr.len().min(2048)])
            ))
            .into());
        }
        Ok(status.success())
    }

    async fn finish_sessions(&mut self, expected_denial: bool) -> TestResult {
        self.phase = "join broker relays";
        while let Some(result) = self.relays.join_next().await {
            if let Err(error) = result? {
                if !expected_denial_disconnect(&error, expected_denial) {
                    return Err(error.into());
                }
            }
        }
        // Ordinary SSH EOF may be a russh protocol error; task completion and
        // exact Git/output/policy oracles, not that error, establish this fixture.
        self.phase = "join upstream SSH peers";
        while let Some(result) = self.peers.join_next().await {
            let _ = result?;
        }
        self.finish_git_jobs().await?;
        Ok(())
    }

    async fn finish_git_jobs(&mut self) -> TestResult {
        self.phase = "join Git server jobs";
        self.owned_jobs.append(&mut *self.jobs.lock().unwrap());
        let mut errors = Vec::new();
        while let Some(task) = self.owned_jobs.last_mut() {
            let result = task.await;
            self.owned_jobs.pop();
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => errors.push(error.to_string()),
                Err(error) => errors.push(error.to_string()),
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(io::Error::other(format!("Git server owners: {errors:?}")).into())
        }
    }

    async fn commit(&mut self, work: &Path, text: &str) -> TestResult<Vec<u8>> {
        std::fs::write(work.join("identity.txt"), text)?;
        self.local(work, &["add", "identity.txt"]).await?;
        self.local(work, &["commit", "-m", "fixture content"])
            .await?;
        self.local(work, &["rev-parse", "HEAD"]).await
    }

    async fn snapshot(&mut self, index: usize) -> TestResult<(Vec<u8>, Vec<u8>)> {
        let bare = self.repositories[index].clone();
        let snapshot = (
            self.local(
                &bare,
                &["for-each-ref", "--format=%(refname) %(objectname)"],
            )
            .await?,
            self.local(
                &bare,
                &[
                    "cat-file",
                    "--batch-all-objects",
                    "--batch-check=%(objectname)",
                ],
            )
            .await?,
        );
        eprintln!(
            "repository {index}: refs={} objects={}",
            snapshot
                .0
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
                .count(),
            snapshot
                .1
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
                .count()
        );
        Ok(snapshot)
    }

    async fn exercise(&mut self) -> TestResult {
        let root = self.root.path().to_owned();
        let mut initial_heads = Vec::new();
        for index in 0..2 {
            let bare = self.repositories[index].clone();
            let seed = root.join(format!("seed-{index}"));
            let template = format!("--template={}", root.join("empty").display());
            self.local(
                &root,
                &[
                    "init",
                    "--bare",
                    "--initial-branch=main",
                    &template,
                    bare.to_str().ok_or("path encoding")?,
                ],
            )
            .await?;
            self.local(
                &root,
                &[
                    "init",
                    "--initial-branch=main",
                    &template,
                    seed.to_str().ok_or("path encoding")?,
                ],
            )
            .await?;
            let initial = self
                .commit(&seed, &format!("repo-{index}: initial\n"))
                .await?;
            initial_heads.push(initial);
            self.local(
                &seed,
                &[
                    "push",
                    bare.to_str().ok_or("path encoding")?,
                    "HEAD:refs/heads/main",
                ],
            )
            .await?;
        }
        for index in 0..2 {
            let bare = self.repositories[index].clone();
            let seed = root.join(format!("seed-{index}"));
            let clone = root.join(format!("clone-{index}"));
            let other = self.snapshot(1 - index).await?;
            self.network(
                index,
                index,
                &root,
                "clone",
                &[clone.to_str().ok_or("path encoding")?],
            )
            .await?;
            require(
                self.events
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|event| **event == (index, "env-denied"))
                    .count()
                    == 1,
                "clone environment request was not explicitly refused",
            )?;
            require(
                self.local(&clone, &["rev-parse", "HEAD"]).await? == initial_heads[index],
                "clone object identity differs",
            )?;
            require(
                std::fs::read(clone.join("identity.txt"))?
                    == format!("repo-{index}: initial\n").as_bytes(),
                "clone bytes differ",
            )?;
            require(
                self.snapshot(1 - index).await? == other,
                "clone affected another repository",
            )?;
            let fetched = self
                .commit(&seed, &format!("repo-{index}: fetched\n"))
                .await?;
            self.local(
                &seed,
                &[
                    "push",
                    bare.to_str().ok_or("path encoding")?,
                    "HEAD:refs/heads/main",
                ],
            )
            .await?;
            self.network(index, index, &clone, "fetch", &["main"])
                .await?;
            require(
                self.events
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|event| **event == (index, "env-denied"))
                    .count()
                    == 2,
                "fetch environment request was not explicitly refused",
            )?;
            require(
                self.local(&clone, &["rev-parse", "FETCH_HEAD"]).await? == fetched,
                "fetch object identity differs",
            )?;
            require(
                self.snapshot(1 - index).await? == other,
                "fetch affected another repository",
            )?;
            self.local(&clone, &["merge", "--ff-only", "FETCH_HEAD"])
                .await?;
            let pushed = self
                .commit(&clone, &format!("repo-{index}: pushed\n"))
                .await?;
            self.network(index, index, &clone, "push", &["HEAD:refs/heads/main"])
                .await?;
            require(
                self.local(&bare, &["rev-parse", "refs/heads/main"]).await? == pushed,
                "push object identity differs",
            )?;
            require(
                self.local(&bare, &["show", "main:identity.txt"]).await?
                    == format!("repo-{index}: pushed\n").as_bytes(),
                "pushed content differs",
            )?;
            require(
                self.snapshot(1 - index).await? == other,
                "push affected another repository",
            )?;
        }
        let before = [self.snapshot(0).await?, self.snapshot(1).await?];
        let commands_before = self
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, kind)| matches!(*kind, "upload" | "receive"))
            .count();
        require(
            !self.network(0, 1, &root, "ls-remote", &[]).await?,
            "cross-repository upload was accepted",
        )?;
        require(
            !self
                .network(
                    0,
                    1,
                    &root.join("clone-0"),
                    "push",
                    &["HEAD:refs/heads/intrusion"],
                )
                .await?,
            "cross-repository receive was accepted",
        )?;
        require(
            before == [self.snapshot(0).await?, self.snapshot(1).await?],
            "denied request changed refs or objects",
        )?;
        let events = self.events.lock().unwrap();
        require(
            events
                .iter()
                .filter(|(_, kind)| matches!(*kind, "upload" | "receive"))
                .count()
                == commands_before,
            "denied request spawned Git server",
        )?;
        for index in 0..2 {
            for (kind, expected) in [
                ("upload", 2),
                ("receive", 1),
                ("denied", if index == 0 { 2 } else { 0 }),
                ("auth", if index == 0 { 5 } else { 3 }),
            ] {
                require(
                    events
                        .iter()
                        .filter(|event| **event == (index, kind))
                        .count()
                        == expected,
                    "wrong per-launch Git credential/command count",
                )?;
            }
        }
        Ok(())
    }

    async fn cleanup(&mut self) -> TestResult {
        self.stop.send_replace(true);
        let mut errors = Vec::new();
        if let Err(error) = self
            .broker
            .managed_policy()?
            .lock()
            .await
            .state_lost(self.fence)
        {
            errors.push(error.to_string());
        }
        for (index, client) in self.clients.iter_mut().enumerate() {
            if !matches!(client.child.try_wait(), Ok(Some(_))) {
                if let Err(error) = client.child.start_kill() {
                    errors.push(error.to_string());
                }
            }
            if let Err(error) = client.child.wait().await {
                errors.push(error.to_string());
            }
            for (label, capture) in [
                ("stdout", &mut client.stdout),
                ("stderr", &mut client.stderr),
            ] {
                if capture.is_some() {
                    match finish_capture(capture).await {
                        Ok(bytes) => {
                            // These pipes contain only disposable fixture data.
                            // Never print key material or ambient diagnostics.
                            eprintln!("unfinished client {index} {label}: {} bytes", bytes.len());
                            if label == "stderr" {
                                eprintln!(
                                    "synthetic stderr: {:?}",
                                    String::from_utf8_lossy(&bytes[..bytes.len().min(2048)])
                                );
                            }
                        }
                        Err(error) => errors.push(error.to_string()),
                    }
                }
            }
        }
        while let Some(result) = self.relays.join_next().await {
            if let Err(error) = result {
                errors.push(error.to_string());
            }
        }
        while let Some(result) = self.peers.join_next().await {
            if let Err(error) = result {
                errors.push(error.to_string());
            }
        }
        if let Err(error) = self.finish_git_jobs().await {
            errors.push(error.to_string());
        }
        let mut policy = self.broker.managed_policy()?.lock().await;
        match policy.connect([3; 32]) {
            Ok(fence) => {
                if !matches!(policy.state_lost(fence), Ok(ApplyStatus::Applied)) {
                    errors.push("incomplete final retirement".into());
                }
            }
            Err(error) => errors.push(error.to_string()),
        }
        require(errors.is_empty(), "Git fixture cleanup incomplete")
            .map_err(|error| io::Error::other(format!("{error}: {errors:?}")).into())
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for Fixture {
    fn drop(&mut self) {
        // A cancelled cleanup cannot silently detach Tokio task owners. These
        // requests are not reap receipts: the native test runner's subreaper
        // additionally requires all owned descendants to exit before success.
        self.stop.send_replace(true);
        for client in &mut self.clients {
            if !matches!(client.child.try_wait(), Ok(Some(_))) {
                let _ = client.child.start_kill();
            }
            for capture in [&client.stdout, &client.stderr].into_iter().flatten() {
                capture.abort();
            }
        }
        self.relays.abort_all();
        self.peers.abort_all();
        for task in &self.owned_jobs {
            task.abort();
        }
        for task in self.jobs.lock().unwrap().iter() {
            task.abort();
        }
    }
}

impl russh::server::Handler for Upstream {
    type Error = russh::Error;

    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(
            if user == "git"
                && self.keys.iter().any(|expected| {
                    expected.algorithm() == key.algorithm() && expected.key_data() == key.key_data()
                })
            {
                Auth::Accept
            } else {
                Auth::reject()
            },
        )
    }

    async fn auth_publickey(&mut self, user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        self.selected = (user == "git")
            .then(|| {
                self.keys.iter().position(|expected| {
                    expected.algorithm() == key.algorithm() && expected.key_data() == key.key_data()
                })
            })
            .flatten();
        Ok(if let Some(index) = self.selected {
            self.events.lock().unwrap().push((index, "auth"));
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<russh::server::Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.channels.is_empty() {
            self.channels.insert(channel.id(), channel);
            reply.accept().await;
        }
        Ok(())
    }

    async fn exec_request(
        &mut self,
        id: ChannelId,
        command: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let selected = self.selected.ok_or(russh::Error::Disconnect)?;
        let Some(operation) = select_command(command, selected) else {
            self.events.lock().unwrap().push((selected, "denied"));
            session.channel_failure(id)?;
            session.eof(id)?;
            session.close(id)?;
            return Ok(());
        };
        let channel = self.channels.remove(&id).ok_or(russh::Error::Disconnect)?;
        session.channel_success(id)?;
        self.events.lock().unwrap().push((
            selected,
            if operation == "upload-pack" {
                "upload"
            } else {
                "receive"
            },
        ));
        self.jobs.lock().unwrap().push(tokio::spawn(serve_git(
            self.tools.clone(),
            self.repositories[selected].clone(),
            operation,
            channel,
            session.handle(),
            self.stop.clone(),
        )));
        Ok(())
    }

    async fn env_request(
        &mut self,
        id: ChannelId,
        _name: &str,
        _value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // The fixture intentionally forwards no environment into Git. russh
        // requires an explicit reply; its default callback does not send one.
        let selected = self.selected.ok_or(russh::Error::Disconnect)?;
        self.events.lock().unwrap().push((selected, "env-denied"));
        session.channel_failure(id)?;
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

fn write_private(path: &Path, bytes: &str) -> io::Result<()> {
    std::fs::write(path, bytes)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

fn shell_quote(path: &Path) -> String {
    format!(
        "'{}'",
        path.to_str()
            .expect("fixture path encoding")
            .replace('\'', "'\\''")
    )
}

fn select_command(command: &[u8], selected: usize) -> Option<&'static str> {
    if selected > 1 {
        return None;
    }
    for operation in ["upload-pack", "receive-pack"] {
        if command == format!("git-{operation} '/repo-{selected}'").as_bytes() {
            return Some(operation);
        }
    }
    None
}

fn expected_denial_disconnect(error: &BrokerError, expected_denial: bool) -> bool {
    // Only after exact client, server-event and repository no-effect checks.
    // An EOF is never by itself evidence that authorization was enforced.
    expected_denial
        && matches!(error, BrokerError::Ssh(message) if message == "guest session failed: ssh: early eof")
}

async fn capture<R: AsyncRead + Unpin>(reader: R) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take(OUTPUT_LIMIT + 1)
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() as u64 > OUTPUT_LIMIT {
        return Err(io::Error::other("Git capture bound exceeded"));
    }
    Ok(bytes)
}

async fn finish_capture(capture: &mut Capture) -> TestResult<Vec<u8>> {
    let result = capture.as_mut().ok_or("missing capture")?.await;
    capture.take();
    Ok(result??)
}

async fn send_output<R: AsyncRead + Unpin>(
    mut reader: R,
    session: russh::server::Handle,
    id: ChannelId,
    extended: bool,
) -> TestResult {
    let mut bytes = [0u8; 16 * 1024];
    let mut total = 0u64;
    loop {
        let length = reader.read(&mut bytes).await?;
        if length == 0 {
            return Ok(());
        }
        total += length as u64;
        require(total <= OUTPUT_LIMIT, "Git server output bound exceeded")?;
        let send = async {
            if extended {
                session.extended_data(id, 1, bytes[..length].to_vec()).await
            } else {
                session.data(id, bytes[..length].to_vec()).await
            }
        };
        tokio::time::timeout(PIPE_TIMEOUT, send)
            .await?
            .map_err(|_| io::Error::other("Git SSH output channel closed"))?;
    }
}

async fn serve_git(
    tools: Tools,
    repository: PathBuf,
    operation: &'static str,
    mut channel: Channel<russh::server::Msg>,
    session: russh::server::Handle,
    mut stop: watch::Receiver<bool>,
) -> TestResult {
    let id = channel.id();
    require(!*stop.borrow(), "Git fixture is stopping")?;
    let mut command = tools.git(&tools.home);
    command
        .arg(operation)
        .arg(&repository)
        .stdin(Stdio::piped());
    let mut child = command.spawn()?;
    let mut stdin = child.stdin.take().ok_or("Git stdin missing")?;
    let stdout = child.stdout.take().ok_or("Git stdout missing")?;
    let stderr = child.stderr.take().ok_or("Git stderr missing")?;
    let result = async {
        let input = async {
            let mut total = 0u64;
            loop {
                match channel.wait().await {
                    Some(ChannelMsg::Data { data }) => {
                        total += data.len() as u64;
                        require(total <= OUTPUT_LIMIT, "Git server input bound exceeded")?;
                        tokio::time::timeout(PIPE_TIMEOUT, stdin.write_all(&data)).await??;
                    }
                    Some(ChannelMsg::Eof | ChannelMsg::Close) | None => { drop(stdin); return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(()); }
                    _ => {}
                }
            }
        };
        let output = async { tokio::try_join!(send_output(stdout, session.clone(), id, false), send_output(stderr, session.clone(), id, true))?; Ok::<_, Box<dyn std::error::Error + Send + Sync>>(()) };
        tokio::pin!(input, output);
        let mut input_done = false;
        let mut output_done = false;
        let mut status = None;
        let deadline = tokio::time::sleep(Duration::from_secs(30));
        tokio::pin!(deadline);
        loop {
            if output_done && status.is_some() { break; }
            tokio::select! {
                result = &mut input, if !input_done => { result?; input_done = true; }
                result = &mut output, if !output_done => { result?; output_done = true; }
                result = child.wait(), if status.is_none() => { status = Some(result?); }
                _ = stop.changed() => { return Err(io::Error::other("Git server cancelled").into()); }
                _ = &mut deadline => { return Err(io::Error::other("Git server deadline exceeded").into()); }
            }
        }
        let status = status.ok_or("Git status missing")?;
        require(status.success(), "Git server did not exit successfully")?;
        tokio::time::timeout(PIPE_TIMEOUT, async {
            session.exit_status_request(id, status.code().ok_or(())? as u32).await?;
            session.eof(id).await?;
            session.close(id).await
        }).await?.map_err(|_| io::Error::other("Git SSH completion channel closed"))?;
        Ok(())
    }.await;
    // No detached pipe tasks or process groups: this owner always reaps the
    // direct child before the fixture can report its completion.
    let kill_error = if !matches!(child.try_wait(), Ok(Some(_))) {
        child.start_kill().err()
    } else {
        None
    };
    let cleanup = tokio::time::timeout(PIPE_TIMEOUT, child.wait()).await;
    if kill_error.is_some() || !matches!(&cleanup, Ok(Ok(_))) {
        return Err(io::Error::other(format!(
            "Git server: {result:?}; kill: {kill_error:?}; reap: {cleanup:?}"
        ))
        .into());
    }
    result
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn git_command_selection_is_exact_and_repository_scoped() {
    let eof = BrokerError::Ssh("guest session failed: ssh: early eof".into());
    assert!(expected_denial_disconnect(&eof, true));
    assert!(!expected_denial_disconnect(&eof, false));
    for error in [
        BrokerError::Ssh("early eof".into()),
        BrokerError::Ssh("guest session failed: ssh: early eof: other".into()),
        BrokerError::Ssh("SSH relay retirement incomplete".into()),
        BrokerError::Egress("guest session failed: ssh: early eof".into()),
    ] {
        assert!(!expected_denial_disconnect(&error, true));
    }
    assert_eq!(select_command(b"git-upload-pack '/repo-0'", 2), None);
    for index in 0..2 {
        for operation in ["upload-pack", "receive-pack"] {
            assert_eq!(
                select_command(format!("git-{operation} '/repo-{index}'").as_bytes(), index),
                Some(operation)
            );
            assert_eq!(
                select_command(
                    format!("git-{operation} '/repo-{}'", 1 - index).as_bytes(),
                    index
                ),
                None
            );
        }
    }
    for denied in [
        "git-upload-pack /repo-0",
        "git-upload-pack '/repo-0'; id",
        "git-upload-pack '/repo-0/../repo-1'",
        "git-receive-pack '/repo-0' --help",
        "sh",
        "git-upload-pack '/repo-0'\n",
    ] {
        assert_eq!(select_command(denied.as_bytes(), 0), None);
    }
}

#[tokio::test]
#[ignore = "requires explicitly pinned Git/OpenSSH/shell and private loopback; no VM"]
async fn managed_git_preserves_objects_and_launch_credential_boundaries() {
    let mut fixture = Fixture::new().await.expect("private Git fixture");
    let result = tokio::time::timeout(Duration::from_secs(90), fixture.exercise()).await;
    let phase = fixture.phase;
    eprintln!(
        "exercise ended at {phase}; clients={}; retained events={:?}",
        fixture.clients.len(),
        fixture
            .events
            .lock()
            .unwrap()
            .iter()
            .take(32)
            .collect::<Vec<_>>()
    );
    let cleanup = tokio::time::timeout(Duration::from_secs(20), fixture.cleanup()).await;
    assert!(
        matches!(&result, Ok(Ok(()))) && matches!(&cleanup, Ok(Ok(()))),
        "managed Git at {phase}: {result:?}; owned cleanup: {cleanup:?}"
    );
}
