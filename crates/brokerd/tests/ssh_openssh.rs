//! Stock OpenSSH against the actual two-session broker and a disposable SSH server.
//!
//! Run explicitly with `cargo test -p microsandbox-brokerd --test ssh_openssh
//! -- --ignored`. Requires `ssh` (or `MSB_TEST_SSH`) but no VM, host keys, agents,
//! external network, user configuration or real credentials.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use microsandbox_brokerd::keys::BrokerKey;
use microsandbox_brokerd::prelude::SessionIdentity;
use microsandbox_brokerd::ssh::{build_server_config, parse_upstream_pin, reoriginate};
use microsandbox_protocol::bootstrap::{BROKER_KEY_TYPE_ED25519, BrokerSshKey, BrokerUpstreamHost};
use microsandbox_scan::PatternLibrary;
use russh::keys::{Algorithm, PrivateKey, PublicKey, PublicKeyBase64};
use russh::server::{Auth, ChannelOpenHandle, Session};
use russh::{Channel, ChannelId};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;
use tokio::task::JoinSet;

struct Upstream {
    expected: PublicKey,
    auth_attempts: Arc<AtomicUsize>,
    commands: Arc<AtomicUsize>,
}

impl russh::server::Handler for Upstream {
    type Error = russh::Error;

    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        self.auth_attempts.fetch_add(1, Ordering::SeqCst);
        Ok(
            if user == "git" && key.key_data() == self.expected.key_data() {
                Auth::Accept
            } else {
                Auth::reject()
            },
        )
    }

    async fn auth_publickey(&mut self, user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        self.auth_attempts.fetch_add(1, Ordering::SeqCst);
        Ok(
            if user == "git" && key.key_data() == self.expected.key_data() {
                Auth::Accept
            } else {
                Auth::reject()
            },
        )
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
        self.commands.fetch_add(1, Ordering::SeqCst);
        assert_eq!(command, b"smoke-command");
        session.channel_success(channel)?;
        session.data(channel, b"broker-stdout\n".as_slice())?;
        session.extended_data(channel, 1, b"broker-stderr\n".as_slice())?;
        session.exit_status_request(channel, 23)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }
}

fn random_key() -> PrivateKey {
    PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap()
}

async fn exercise(
    user: &str,
    wrong_upstream_pin: bool,
    wrong_broker_pin: bool,
    public_only: bool,
) -> (std::process::Output, usize, usize, usize) {
    let root = tempfile::tempdir().unwrap();
    let client_key = random_key();
    let identity_path = root.path().join("client_key");
    std::fs::write(
        &identity_path,
        client_key
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    std::fs::set_permissions(&identity_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let identity_path = if public_only {
        let path = root.path().join("public_only");
        std::fs::write(&path, client_key.public_key().to_openssh().unwrap()).unwrap();
        path
    } else {
        identity_path
    };
    let custody = BrokerKey::from_bootstrap(BrokerSshKey {
        key_type: BROKER_KEY_TYPE_ED25519.to_string(),
        key_bytes: vec![42; 32],
    })
    .unwrap();
    let upstream_key = random_key();
    let upstream_public = upstream_key.public_key().clone();
    let upstream_config = Arc::new(russh::server::Config {
        keys: vec![upstream_key],
        auth_rejection_time: Duration::ZERO,
        auth_rejection_time_initial: Some(Duration::ZERO),
        ..Default::default()
    });
    let broker_config = build_server_config().unwrap();
    let broker_public = if wrong_broker_pin {
        random_key().public_key().clone()
    } else {
        broker_config.keys[0].public_key().clone()
    };
    let known_hosts = root.path().join("known_hosts");
    std::fs::write(
        &known_hosts,
        format!(
            "broker.test {} {}\n",
            broker_public.algorithm(),
            broker_public.public_key_base64()
        ),
    )
    .unwrap();
    let auth_attempts = Arc::new(AtomicUsize::new(0));
    let commands = Arc::new(AtomicUsize::new(0));
    let upstream_dials = Arc::new(AtomicUsize::new(0));
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let broker = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let broker_address = broker.local_addr().unwrap();
    let expected: PublicKey = custody.public_key_openssh().parse().unwrap();
    assert_ne!(
        expected,
        *client_key.public_key(),
        "guest key must not be the upstream credential"
    );
    let handler = Upstream {
        expected,
        auth_attempts: auth_attempts.clone(),
        commands: commands.clone(),
    };
    let mut workers = JoinSet::new();
    workers.spawn(async move {
        let (stream, _) = upstream.accept().await.unwrap();
        match russh::server::run_stream(upstream_config, stream, handler).await {
            Ok(session) => {
                if let Err(error) = session.await {
                    eprintln!("test upstream session: {error}");
                }
            }
            Err(error) => eprintln!("test upstream handshake: {error}"),
        }
    });
    let pinned_key = if wrong_upstream_pin {
        random_key().public_key().clone()
    } else {
        upstream_public
    };
    let pin = parse_upstream_pin(&BrokerUpstreamHost {
        host: "upstream.test".to_string(),
        port: upstream_address.port(),
        user: "git".to_string(),
        public_key: format!(
            "{} {}",
            pinned_key.algorithm(),
            pinned_key.public_key_base64()
        ),
    })
    .unwrap();
    let dials = Arc::clone(&upstream_dials);
    workers.spawn(async move {
        let (guest, _) = broker.accept().await.unwrap();
        let upstream = async move {
            dials.fetch_add(1, Ordering::SeqCst);
            Ok(TcpStream::connect(upstream_address).await?)
        };
        if let Err(error) = reoriginate(
            guest,
            upstream,
            &custody,
            &pin,
            broker_config,
            SessionIdentity {
                cid: 7,
                epoch: 1_700_000_000,
            },
            PatternLibrary::empty(),
        )
        .await
        {
            eprintln!("test broker session: {error}");
        }
    });
    let mut command =
        Command::new(std::env::var_os("MSB_TEST_SSH").unwrap_or_else(|| "ssh".into()));
    command
        .env_clear()
        .env("HOME", root.path())
        .env("LC_ALL", "C")
        .kill_on_drop(true)
        .args(["-F", "/dev/null", "-T", "-n"])
        .args([
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentityAgent=none",
            "-o",
            "IdentitiesOnly=yes",
        ])
        .args([
            "-o",
            "PreferredAuthentications=publickey",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
        ])
        .args([
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "UpdateHostKeys=no",
        ])
        .args([
            "-o",
            "HostKeyAlias=broker.test",
            "-o",
            "LogLevel=ERROR",
            "-o",
            "ConnectTimeout=5",
            "-o",
            "ConnectionAttempts=1",
        ])
        .arg("-o")
        .arg(format!("UserKnownHostsFile={}", known_hosts.display()))
        .arg("-i")
        .arg(&identity_path)
        .arg("-p")
        .arg(broker_address.port().to_string())
        .args(["-l", user, "127.0.0.1", "smoke-command"]);
    let output = tokio::time::timeout(Duration::from_secs(15), command.output())
        .await
        .expect("SSH exchange must finish within its test deadline")
        .expect("OpenSSH executable must be installed for this explicit test");
    // Dropping the set aborts pending fixture tasks even on a failed handshake.
    workers.abort_all();
    while workers.join_next().await.is_some() {}
    (
        output,
        auth_attempts.load(Ordering::SeqCst),
        commands.load(Ordering::SeqCst),
        upstream_dials.load(Ordering::SeqCst),
    )
}

#[tokio::test]
#[ignore = "requires stock OpenSSH; run explicitly with --ignored"]
async fn openssh_two_session_exec_preserves_output_and_exit_status() {
    let (output, auth_attempts, commands, dials) = exercise("git", false, false, false).await;
    assert_eq!(
        output.status.code(),
        Some(23),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"broker-stdout\n");
    assert_eq!(output.stderr, b"broker-stderr\n");
    assert!(auth_attempts > 0);
    assert_eq!(commands, 1);
    assert_eq!(dials, 1);
}

#[tokio::test]
#[ignore = "requires stock OpenSSH; run explicitly with --ignored"]
async fn openssh_wrong_requested_user_cannot_use_broker_key() {
    let (output, auth_attempts, commands, dials) =
        exercise("not-authorized", false, false, false).await;
    assert_eq!(output.status.code(), Some(255));
    assert_eq!(commands, 0);
    assert_eq!(
        dials, 0,
        "unauthorized user must not cause an upstream dial"
    );
    assert_eq!(
        auth_attempts, 0,
        "guest user must be checked before upstream key use"
    );
}

#[tokio::test]
#[ignore = "requires stock OpenSSH; run explicitly with --ignored"]
async fn openssh_rejects_wrong_upstream_host_key() {
    let (output, auth_attempts, commands, dials) = exercise("git", true, false, false).await;
    assert_eq!(output.status.code(), Some(255));
    assert_eq!(commands, 0);
    assert_eq!(auth_attempts, 0);
    assert_eq!(
        dials, 1,
        "upstream identity is verified on its independent connection"
    );
}

#[tokio::test]
#[ignore = "requires stock OpenSSH; run explicitly with --ignored"]
async fn openssh_guest_verifies_broker_before_upstream_key_use() {
    let (output, auth_attempts, commands, dials) = exercise("git", false, true, false).await;
    assert_eq!(output.status.code(), Some(255));
    assert_eq!(commands, 0);
    assert_eq!(
        dials, 0,
        "guest host-trust rejection must not dial upstream"
    );
    assert_eq!(
        auth_attempts, 0,
        "guest handshake rejection must precede upstream authentication"
    );
}

#[tokio::test]
#[ignore = "requires stock OpenSSH; run explicitly with --ignored"]
async fn openssh_unsigned_key_offer_cannot_use_upstream_credential() {
    let (output, auth_attempts, commands, dials) = exercise("git", false, false, true).await;
    assert_eq!(output.status.code(), Some(255));
    assert_eq!(commands, 0);
    assert_eq!(dials, 0, "unsigned key offers must not dial upstream");
    assert_eq!(
        auth_attempts, 0,
        "offering a public key must not trigger upstream authentication"
    );
}
