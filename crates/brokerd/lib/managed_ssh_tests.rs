//! Real SSH over private in-memory transports, not mocked authentication.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use microsandbox_protocol::bootstrap::BrokerSshKey;
use russh::keys::{PrivateKey, PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate};
use russh::server::{Auth, ChannelOpenHandle, Session};
use russh::{ChannelId, ChannelMsg};
use tokio::io::DuplexStream;

use crate::broker::Broker;
use crate::config::BrokerConfig;
use crate::keys::BrokerKey;
use crate::policy::{
    ApplyStatus, CredentialBinding, CredentialRecord, Launch, LaunchPolicy, ReadyCredential,
    RelayContext,
};
use crate::ssh::UpstreamPin;

fn key(seed: u8) -> BrokerKey {
    BrokerKey::from_bootstrap(BrokerSshKey {
        key_type: "ed25519".into(),
        key_bytes: vec![seed; 32],
    })
    .unwrap()
}

struct PinnedClient(PublicKey);

impl russh::client::Handler for PinnedClient {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        // SSH carries the algorithm and key bytes, not a local key comment.
        Ok(matches!(key, PublicKeyOrCertificate::PublicKey { key, .. }
            if key.algorithm() == self.0.algorithm() && key.key_data() == self.0.key_data()))
    }
}

struct Upstream {
    key: PublicKey,
    authentications: Arc<AtomicUsize>,
    channels: Arc<AtomicUsize>,
    dropped: Arc<AtomicBool>,
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
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
                && key.algorithm() == self.key.algorithm()
                && key.key_data() == self.key.key_data()
            {
                Auth::Accept
            } else {
                Auth::reject()
            },
        )
    }
    async fn auth_publickey(&mut self, user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        self.authentications.fetch_add(1, Ordering::SeqCst);
        Ok(
            if user == "git"
                && key.algorithm() == self.key.algorithm()
                && key.key_data() == self.key.key_data()
            {
                Auth::Accept
            } else {
                Auth::reject()
            },
        )
    }
    async fn channel_open_session(
        &mut self,
        _channel: russh::Channel<russh::server::Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.fetch_add(1, Ordering::SeqCst);
        reply.accept().await;
        Ok(())
    }
    async fn exec_request(
        &mut self,
        channel: ChannelId,
        command: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        assert_eq!(command, b"fixture-command");
        session.channel_success(channel)?;
        session.data(channel, b"exact\0stdout".as_slice())?;
        session.extended_data(channel, 1, b"exact stderr".as_slice())?;
        session.exit_status_request(channel, 17)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }
}

struct Fixture {
    broker: Arc<Broker>,
    context: RelayContext,
    server_public: PublicKey,
    guest_key: Arc<PrivateKey>,
    dials: Arc<AtomicUsize>,
    authentications: Arc<AtomicUsize>,
    channels: Arc<AtomicUsize>,
    upstream_dropped: Arc<AtomicBool>,
}

impl Fixture {
    async fn new(wrong_upstream_pin: bool) -> Self {
        let server_key = key(41);
        let custody = Arc::new(key(42));
        let upstream_key = key(43);
        let server_public = server_key.private_key().public_key().clone();
        let server = Arc::new(russh::server::Config {
            keys: vec![server_key.private_key().clone()],
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            ..Default::default()
        });
        let broker = Broker::new_managed(BrokerConfig::default(), server, [1; 32], 4, 4).unwrap();
        let mut store = broker.managed_policy().unwrap().lock().await;
        let fence = store.connect([2; 32]).unwrap();
        let launch = Launch {
            instance: "context/workload/instance".into(),
            generation: [3; 32],
        };
        let record = ReadyCredential::new(
            CredentialRecord {
                name: "git-key".into(),
                material: "owner/git-key".into(),
                binding: CredentialBinding::Broker,
                key_version: [4; 32],
                trust_version: [5; 32],
                host: "git.example".into(),
                port: 22,
                user: "git".into(),
                on_violation: "block".into(),
            },
            custody,
            UpstreamPin {
                user: "git".into(),
                expected: if wrong_upstream_pin {
                    key(99).private_key().public_key().clone()
                } else {
                    upstream_key.private_key().public_key().clone()
                },
            },
        )
        .unwrap();
        store
            .install(
                fence,
                None,
                LaunchPolicy::new(launch.clone(), 1, [6; 32], vec![record]).unwrap(),
            )
            .unwrap();
        drop(store);
        Self {
            broker,
            context: RelayContext {
                fence,
                launch,
                revision: 1,
                digest: [6; 32],
                host: "git.example".into(),
                port: 22,
            },
            server_public,
            guest_key: Arc::new(key(44).private_key().clone()),
            dials: Arc::new(AtomicUsize::new(0)),
            authentications: Arc::new(AtomicUsize::new(0)),
            channels: Arc::new(AtomicUsize::new(0)),
            upstream_dropped: Arc::new(AtomicBool::new(false)),
        }
    }

    async fn start(
        &self,
    ) -> (
        crate::broker::ManagedRelay,
        DuplexStream,
        tokio::task::JoinHandle<()>,
    ) {
        let (guest_client, guest_server) = tokio::io::duplex(128 * 1024);
        let (upstream_client, upstream_server) = tokio::io::duplex(128 * 1024);
        let upstream_config = Arc::new(russh::server::Config {
            keys: vec![key(43).private_key().clone()],
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            ..Default::default()
        });
        let handler = Upstream {
            key: key(42).private_key().public_key().clone(),
            authentications: Arc::clone(&self.authentications),
            channels: Arc::clone(&self.channels),
            dropped: Arc::clone(&self.upstream_dropped),
        };
        let peer = tokio::spawn(async move {
            if let Ok(session) =
                russh::server::run_stream(upstream_config, upstream_server, handler).await
            {
                let _ = session.await;
            }
        });
        let dials = Arc::clone(&self.dials);
        let relay = self
            .broker
            .spawn_managed_relay(self.context.clone(), guest_server, async move {
                dials.fetch_add(1, Ordering::SeqCst);
                Ok(upstream_client)
            })
            .await
            .unwrap();
        (relay, guest_client, peer)
    }

    async fn revoke(&self) -> ApplyStatus {
        self.broker
            .managed_policy()
            .unwrap()
            .lock()
            .await
            .install(
                self.context.fence,
                Some(1),
                LaunchPolicy::new(self.context.launch.clone(), 2, [7; 32], vec![]).unwrap(),
            )
            .unwrap()
    }

    async fn assert_revocation_complete(&self) {
        let mut store = self.broker.managed_policy().unwrap().lock().await;
        assert_eq!(
            store.finish(self.context.fence, &self.context.launch, 2, [7; 32]),
            Ok(ApplyStatus::Applied)
        );
        assert!(self.upstream_dropped.load(Ordering::SeqCst));
    }
}

async fn bounded<F: std::future::Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(15), future)
        .await
        .expect("all fixture tasks must complete")
}

#[tokio::test]
async fn managed_real_ssh_relays_and_joins_both_legs_before_revoke_completes() {
    bounded(async {
        let fixture = Fixture::new(false).await;
        let (relay, guest, peer) = fixture.start().await;
        let mut client = russh::client::connect_stream(
            Arc::new(russh::client::Config::default()),
            guest,
            PinnedClient(fixture.server_public.clone()),
        )
        .await
        .unwrap();
        assert!(
            client
                .authenticate_publickey(
                    "git",
                    PrivateKeyWithHashAlg::new(Arc::clone(&fixture.guest_key), None)
                )
                .await
                .unwrap()
                .success()
        );
        assert_eq!(fixture.dials.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.authentications.load(Ordering::SeqCst), 1);
        let mut channel = client.channel_open_session().await.unwrap();
        channel
            .exec(true, b"fixture-command".as_slice())
            .await
            .unwrap();
        let (mut stdout, mut stderr, mut status) = (Vec::new(), Vec::new(), None);
        while let Some(message) = channel.wait().await {
            match message {
                ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
                ChannelMsg::ExtendedData { data, ext: 1 } => stderr.extend_from_slice(&data),
                ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
                ChannelMsg::Close => break,
                _ => {}
            }
        }
        assert_eq!(stdout, b"exact\0stdout");
        assert_eq!(stderr, b"exact stderr");
        assert_eq!(status, Some(17));
        assert_eq!(fixture.revoke().await, ApplyStatus::Pending);
        assert!(
            relay.join().await.is_err(),
            "revocation retains cancellation result"
        );
        let _ = client.await;
        peer.await.unwrap();
        fixture.assert_revocation_complete().await;
    })
    .await;
}

#[tokio::test]
async fn managed_wrong_user_has_no_upstream_dial_or_authentication() {
    bounded(async {
        let fixture = Fixture::new(false).await;
        let (relay, guest, peer) = fixture.start().await;
        let mut client = russh::client::connect_stream(
            Arc::new(russh::client::Config::default()),
            guest,
            PinnedClient(fixture.server_public.clone()),
        )
        .await
        .unwrap();
        assert!(
            !client
                .authenticate_publickey(
                    "root",
                    PrivateKeyWithHashAlg::new(Arc::clone(&fixture.guest_key), None)
                )
                .await
                .unwrap()
                .success()
        );
        assert_eq!(fixture.revoke().await, ApplyStatus::Pending);
        assert!(relay.join().await.is_err());
        let _ = client.await;
        peer.await.unwrap();
        assert_eq!(fixture.dials.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.authentications.load(Ordering::SeqCst), 0);
        fixture.assert_revocation_complete().await;
    })
    .await;
}

#[tokio::test]
async fn managed_preauth_state_loss_joins_without_dial() {
    bounded(async {
        let fixture = Fixture::new(false).await;
        let (relay, guest, peer) = fixture.start().await;
        assert_eq!(
            fixture
                .broker
                .managed_policy()
                .unwrap()
                .lock()
                .await
                .state_lost(fixture.context.fence),
            Ok(ApplyStatus::Pending)
        );
        assert!(relay.join().await.is_err());
        drop(guest);
        peer.await.unwrap();
        assert_eq!(fixture.dials.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.authentications.load(Ordering::SeqCst), 0);
        assert!(
            fixture
                .broker
                .managed_policy()
                .unwrap()
                .lock()
                .await
                .connect([8; 32])
                .is_ok()
        );
    })
    .await;
}

#[tokio::test]
async fn managed_dropped_owner_cancels_but_retains_independent_cleanup_task() {
    bounded(async {
        let fixture = Fixture::new(false).await;
        let (relay, guest, peer) = fixture.start().await;
        drop(relay);
        // Revoke must await the owned task rather than depending on polling its
        // caller-facing handle. No direct store-completion call is used here.
        let _ = fixture.revoke().await;
        drop(guest);
        peer.await.unwrap();
        loop {
            let status = fixture
                .broker
                .managed_policy()
                .unwrap()
                .lock()
                .await
                .finish(fixture.context.fence, &fixture.context.launch, 2, [7; 32])
                .unwrap();
            if status == ApplyStatus::Applied {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(fixture.dials.load(Ordering::SeqCst), 0);
        fixture.assert_revocation_complete().await;
    })
    .await;
}

#[tokio::test]
async fn managed_normal_guest_disconnect_joins_the_upstream_and_channel_pump() {
    bounded(async {
        let fixture = Fixture::new(false).await;
        let (relay, guest, peer) = fixture.start().await;
        let mut client = russh::client::connect_stream(
            Arc::new(russh::client::Config::default()),
            guest,
            PinnedClient(fixture.server_public.clone()),
        )
        .await
        .unwrap();
        assert!(
            client
                .authenticate_publickey(
                    "git",
                    PrivateKeyWithHashAlg::new(Arc::clone(&fixture.guest_key), None)
                )
                .await
                .unwrap()
                .success()
        );
        let channel = client.channel_open_session().await.unwrap();
        client
            .disconnect(russh::Disconnect::ByApplication, "fixture complete", "en")
            .await
            .unwrap();
        let _ = client.await;
        drop(channel);
        relay.join().await.unwrap();
        peer.await.unwrap();
        assert_eq!(fixture.revoke().await, ApplyStatus::Applied);
        fixture.assert_revocation_complete().await;
    })
    .await;
}

#[tokio::test]
async fn managed_channel_cap_rejects_before_upstream_and_reclaims_joined_pumps() {
    bounded(async {
        let fixture = Fixture::new(false).await;
        let (relay, guest, peer) = fixture.start().await;
        let mut client = russh::client::connect_stream(
            Arc::new(russh::client::Config::default()),
            guest,
            PinnedClient(fixture.server_public.clone()),
        )
        .await
        .unwrap();
        assert!(
            client
                .authenticate_publickey(
                    "git",
                    PrivateKeyWithHashAlg::new(Arc::clone(&fixture.guest_key), None)
                )
                .await
                .unwrap()
                .success()
        );
        let limit = crate::ssh::MANAGED_CHANNEL_LIMIT;
        let mut channels = Vec::new();
        for _ in 0..limit {
            channels.push(client.channel_open_session().await.unwrap());
        }
        assert_eq!(fixture.channels.load(Ordering::SeqCst), limit);
        assert!(client.channel_open_session().await.is_err());
        assert_eq!(
            fixture.channels.load(Ordering::SeqCst),
            limit,
            "capacity refusal must precede the upstream channel-open request"
        );
        let mut completed = channels.pop().unwrap();
        completed
            .exec(true, b"fixture-command".as_slice())
            .await
            .unwrap();
        while let Some(message) = completed.wait().await {
            if matches!(message, ChannelMsg::Close) {
                break;
            }
        }
        // The close is delivered before the pump returns. Admission may remain
        // closed briefly; it must reopen after observing and joining that pump.
        let replacement = loop {
            match client.channel_open_session().await {
                Ok(channel) => break channel,
                Err(_) => tokio::task::yield_now().await,
            }
        };
        assert_eq!(fixture.channels.load(Ordering::SeqCst), limit + 1);
        assert!(client.channel_open_session().await.is_err());
        assert_eq!(fixture.channels.load(Ordering::SeqCst), limit + 1);
        client
            .disconnect(russh::Disconnect::ByApplication, "fixture complete", "en")
            .await
            .unwrap();
        let _ = client.await;
        drop((replacement, completed, channels));
        relay.join().await.unwrap();
        peer.await.unwrap();
        assert_eq!(fixture.revoke().await, ApplyStatus::Applied);
    })
    .await;
}

#[tokio::test]
async fn managed_wrong_upstream_pin_never_uses_custody_and_retirement_is_joined() {
    bounded(async {
        let fixture = Fixture::new(true).await;
        let (relay, guest, peer) = fixture.start().await;
        let mut client = russh::client::connect_stream(
            Arc::new(russh::client::Config::default()),
            guest,
            PinnedClient(fixture.server_public.clone()),
        )
        .await
        .unwrap();
        let auth = client
            .authenticate_publickey(
                "git",
                PrivateKeyWithHashAlg::new(Arc::clone(&fixture.guest_key), None),
            )
            .await;
        assert!(!matches!(auth, Ok(result) if result.success()));
        assert!(relay.join().await.is_err());
        let _ = client.await;
        peer.await.unwrap();
        assert_eq!(fixture.authentications.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.revoke().await, ApplyStatus::Applied);
        fixture.assert_revocation_complete().await;
    })
    .await;
}
