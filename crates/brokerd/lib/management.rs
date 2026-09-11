//! Direct, protected broker management over a transport separate from agentd.
//!
//! The caller authenticates the transport owner before handing it over. Hello
//! identifies that owner's controller incarnation; it is not a credential.
//! This module owns applied state only, never desired policy or its persistence.

use std::sync::Arc;
use std::time::Duration;

use microsandbox_protocol::broker as wire;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Instant;

use crate::broker::Broker;
use crate::policy::{ApplyStatus, Launch, LaunchPolicy, ManagementFence, PolicyError};
use crate::ssh::TerminationHandle;

const FRAME_TIMEOUT: Duration = Duration::from_secs(30);
const RETIREMENT_TIMEOUT: Duration = Duration::from_secs(6);

/// Static transport/policy errors; never raw credential or parser details.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ManagementError {
    /// Malformed, unavailable, timed-out or cancelled protected connection.
    #[error("broker management connection unavailable")]
    Connection,
    /// The connection or policy was not current/admissible.
    #[error("broker management session refused")]
    Refused,
    /// Cleanup was requested, but not every owned relay was observed joined.
    #[error("broker management retirement incomplete; primary failure: {primary:?}")]
    RetirementIncomplete {
        /// Preserve the original static connection/policy failure, if any.
        primary: Option<ManagementFailure>,
    },
}

/// Primary failure retained when cleanup also cannot establish retirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagementFailure {
    /// Protected connection failed, timed out or was cancelled.
    Connection,
    /// Authentication/session/policy handling refused the connection.
    Refused,
}

/// Owned connection task. Dropping its caller handle cancels the connection,
/// but never aborts the independently owned task that fences and retires it.
pub struct ManagedControl {
    stop: TerminationHandle,
    task: Option<tokio::task::JoinHandle<Result<(), ManagementError>>>,
}

impl ManagedControl {
    /// Request connection fencing and retirement, without claiming completion.
    pub fn terminate(&self) {
        self.stop.terminate();
    }

    /// Cancellation capability for the owner, not evidence of task retirement.
    pub fn termination(&self) -> TerminationHandle {
        self.stop.clone()
    }

    /// Observe actual connection-task completion. An error retains its primary
    /// cause even if retirement also could not be established.
    pub async fn join(mut self) -> Result<(), ManagementError> {
        self.task
            .take()
            .expect("one owned connection task")
            .await
            .map_err(|_| ManagementError::RetirementIncomplete { primary: None })?
    }
}

impl Drop for ManagedControl {
    fn drop(&mut self) {
        self.stop.terminate();
    }
}

impl Broker {
    /// Accept only a transport already authenticated by the host-listen route
    /// and guest HOST-CID check. No guest exec/console or arbitrary socket is
    /// authenticated by calling this Rust seam. A second live owner is refused.
    pub fn spawn_managed_control<S>(
        self: &Arc<Self>,
        stream: S,
    ) -> Result<ManagedControl, PolicyError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.managed_policy()?;
        let stop = TerminationHandle::new();
        let task_stop = stop.clone();
        let broker = Arc::clone(self);
        let task = tokio::spawn(async move { run(broker, stream, task_stop).await });
        Ok(ManagedControl {
            stop,
            task: Some(task),
        })
    }
}

async fn receive<S: AsyncRead + Unpin>(
    stream: &mut S,
    stop: &TerminationHandle,
    deadline: Instant,
) -> Result<wire::Request, ManagementError> {
    current_time(deadline, stop)?;
    let result = tokio::select! {
        _ = stop.terminated() => Err(ManagementError::Connection),
        result = tokio::time::timeout_at(deadline.min(Instant::now() + FRAME_TIMEOUT), wire::read_request(stream)) =>
            result.map_err(|_| ManagementError::Connection)?
                .map_err(|_| ManagementError::Connection),
    };
    current_time(deadline, stop)?;
    result
}

async fn send<S: AsyncWrite + Unpin>(
    stream: &mut S,
    stop: &TerminationHandle,
    reply: &wire::Reply,
    deadline: Instant,
) -> Result<(), ManagementError> {
    current_time(deadline, stop)?;
    let result = tokio::select! {
        _ = stop.terminated() => Err(ManagementError::Connection),
        result = tokio::time::timeout_at(deadline.min(Instant::now() + FRAME_TIMEOUT), wire::write_reply(stream, reply)) =>
            result.map_err(|_| ManagementError::Connection)?
                .map_err(|_| ManagementError::Connection),
    };
    current_time(deadline, stop)?;
    result
}

fn current_time(deadline: Instant, stop: &TerminationHandle) -> Result<(), ManagementError> {
    if Instant::now() >= deadline || stop.is_terminated() {
        Err(ManagementError::Connection)
    } else {
        Ok(())
    }
}

async fn run<S: AsyncRead + AsyncWrite + Unpin>(
    broker: Arc<Broker>,
    mut stream: S,
    stop: TerminationHandle,
) -> Result<(), ManagementError> {
    let wire::Request::Hello(hello) =
        receive(&mut stream, &stop, Instant::now() + FRAME_TIMEOUT).await?
    else {
        return Err(ManagementError::Refused);
    };
    let fence = broker
        .managed_policy()
        .map_err(|_| ManagementError::Refused)?
        .lock()
        .await
        .connect(hello.controller.bytes())
        .map_err(|_| ManagementError::Refused)?;
    // Once the fence exists, every ordinary return below passes through session
    // invalidation. No caller is given authority to abort this owned task.
    let result: Result<(), ManagementError> = async {
        let mut deadline = Instant::now() + Duration::from_secs(wire::MANAGEMENT_LEASE_SECS);
        send(
            &mut stream,
            &stop,
            &wire::Reply::Hello(wire::Welcome {
                version: wire::VERSION,
                session: fence.session(),
            }),
            deadline,
        )
        .await?;
        loop {
            let request = receive(&mut stream, &stop, deadline).await?;
            let reply = match request {
                wire::Request::Probe(session) => {
                    let current = session == fence.session();
                    if current {
                        let applied = broker
                            .managed_policy()
                            .map_err(|_| ManagementError::Refused)?;
                        applied
                            .lock()
                            .await
                            .fence_for(session)
                            .map_err(|_| ManagementError::Refused)?;
                        // A slow frame, blocked lock or compiler must not revive
                        // an already expired lease. Only this exact probe renews.
                        current_time(deadline, &stop)?;
                        deadline =
                            Instant::now() + Duration::from_secs(wire::MANAGEMENT_LEASE_SECS);
                    }
                    wire::Reply::Probe(wire::Probe { session, current })
                }
                request => {
                    wire::Reply::Observation(apply(&broker, fence, request, deadline, &stop).await?)
                }
            };
            send(&mut stream, &stop, &reply, deadline).await?;
        }
    }
    .await;
    let cleanup = retire(&broker, fence).await;
    finish(result, cleanup)
}

fn finish(
    result: Result<(), ManagementError>,
    cleanup: Result<(), ManagementError>,
) -> Result<(), ManagementError> {
    if cleanup.is_err() {
        return Err(ManagementError::RetirementIncomplete {
            primary: match result {
                Err(ManagementError::Connection) => Some(ManagementFailure::Connection),
                Err(ManagementError::Refused) => Some(ManagementFailure::Refused),
                Err(ManagementError::RetirementIncomplete { primary }) => primary,
                Ok(()) => None,
            },
        });
    }
    result
}

async fn apply(
    broker: &Broker,
    fence: ManagementFence,
    request: wire::Request,
    deadline: Instant,
    stop: &TerminationHandle,
) -> Result<wire::Observation, ManagementError> {
    let (transaction, proposed) = match request {
        wire::Request::Hello(_) | wire::Request::Probe(_) => return Err(ManagementError::Refused),
        wire::Request::Finish(transaction) => (transaction, None),
        wire::Request::Apply(apply) => (
            apply.transaction,
            Some((apply.expected_revision, apply.policy)),
        ),
    };
    // An old or relabelled transaction cannot poison a current session.
    if transaction.session != fence.session() {
        return Ok(rejected(transaction, wire::Failure::StaleLaunch));
    }
    let launch = Launch::from_wire(&transaction.launch);
    let result = if let Some((expected, policy)) = proposed {
        match LaunchPolicy::from_wire(
            launch,
            transaction.revision,
            transaction.policy_digest.bytes(),
            policy,
        ) {
            Ok(policy) => {
                let mut store = broker
                    .managed_policy()
                    .map_err(|_| ManagementError::Refused)?
                    .lock()
                    .await;
                current_time(deadline, stop)?;
                store.install(fence, expected, policy)
            }
            Err(error) => Err(error),
        }
    } else {
        let mut store = broker
            .managed_policy()
            .map_err(|_| ManagementError::Refused)?
            .lock()
            .await;
        current_time(deadline, stop)?;
        store.finish(
            fence,
            &launch,
            transaction.revision,
            transaction.policy_digest.bytes(),
        )
    };
    match result {
        Ok(status) => Ok(wire::Observation {
            transaction,
            outcome: match status {
                ApplyStatus::Applied => wire::Outcome::Applied,
                ApplyStatus::Pending => wire::Outcome::Pending,
            },
            failure: None,
        }),
        // A real local state loss closes/fences this entire connection. It is
        // never repaired by accepting another request on the same session.
        Err(PolicyError::StaleManagement) => Err(ManagementError::Refused),
        Err(error) => Ok(rejected(
            transaction,
            match error {
                PolicyError::InvalidPolicy | PolicyError::AmbiguousCredential => {
                    wire::Failure::InvalidPolicy
                }
                PolicyError::RetirementIncomplete => wire::Failure::RetirementIncomplete,
                PolicyError::Capacity => wire::Failure::Unavailable,
                _ => wire::Failure::StaleLaunch,
            },
        )),
    }
}

fn rejected(transaction: wire::TransactionRef, failure: wire::Failure) -> wire::Observation {
    wire::Observation {
        transaction,
        outcome: wire::Outcome::Rejected,
        failure: Some(failure),
    }
}

async fn retire(broker: &Broker, fence: ManagementFence) -> Result<(), ManagementError> {
    retire_after(broker, fence, RETIREMENT_TIMEOUT).await
}

async fn retire_after(
    broker: &Broker,
    fence: ManagementFence,
    timeout: Duration,
) -> Result<(), ManagementError> {
    let store = broker
        .managed_policy()
        .map_err(|_| ManagementError::Refused)?;
    // Refusing an obsolete fence cannot clear a newly authenticated session.
    if store.lock().await.state_lost(fence) == Ok(ApplyStatus::Applied) {
        return Ok(());
    }
    tokio::time::timeout(timeout, async {
        loop {
            if store
                .lock()
                .await
                .connection_retired(fence)
                .map_err(|_| ManagementError::Refused)?
            {
                break Ok(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| ManagementError::RetirementIncomplete { primary: None })?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BrokerConfig;
    use crate::keys::BrokerKey;
    use crate::policy::{PolicyStore, RelayContext};
    use microsandbox_protocol::bootstrap::BrokerSshKey;
    use tokio::io::AsyncWriteExt;

    fn id(byte: u8) -> wire::Id {
        wire::Id::from_bytes([byte; 32]).unwrap()
    }

    fn broker() -> Arc<Broker> {
        let key = BrokerKey::from_bootstrap(BrokerSshKey {
            key_type: "ed25519".into(),
            key_bytes: vec![1; 32],
        })
        .unwrap();
        Broker::new_managed(
            BrokerConfig::default(),
            Arc::new(russh::server::Config {
                keys: vec![key.private_key().clone()],
                ..Default::default()
            }),
            [2; 32],
            4,
            4,
        )
        .unwrap()
    }

    fn policy() -> wire::Policy {
        let key = BrokerKey::from_bootstrap(BrokerSshKey {
            key_type: "ed25519".into(),
            key_bytes: vec![3; 32],
        })
        .unwrap();
        wire::Policy {
            destroyed: false,
            patterns: vec![],
            credentials: vec![wire::ReadyRecord {
                name: "key".into(),
                material: "owner/key".into(),
                binding: wire::Binding::Broker,
                key_version: id(3),
                trust_version: id(4),
                host: "git.example".into(),
                port: 22,
                user: "git".into(),
                on_violation: wire::Violation::Block,
                key_kind: wire::KeyKind::Ed25519Seed,
                key_bytes: wire::SecretBytes::new(vec![3; 32]),
                upstream_public_key: key.private_key().public_key().to_openssh().unwrap(),
            }],
        }
    }

    fn transaction(
        session: wire::BrokerSession,
        revision: u64,
        policy: &wire::Policy,
    ) -> wire::TransactionRef {
        wire::TransactionRef {
            session,
            revision,
            policy_digest: wire::policy_digest(policy).unwrap(),
            launch: wire::LaunchRef {
                generation: id(5),
                instance: wire::InstanceRef {
                    workload: wire::WorkloadRef {
                        context: Some("context".into()),
                        name: "agent".into(),
                    },
                    instance: "one".into(),
                },
            },
        }
    }

    async fn connect(
        broker: &Arc<Broker>,
        incarnation: u8,
    ) -> (ManagedControl, tokio::io::DuplexStream, wire::BrokerSession) {
        let (mut client, server) = tokio::io::duplex(2 * wire::MAX_FRAME_BYTES);
        let control = broker.spawn_managed_control(server).unwrap();
        wire::write_request(
            &mut client,
            &wire::Request::Hello(wire::Hello {
                version: wire::VERSION,
                controller: id(incarnation),
            }),
        )
        .await
        .unwrap();
        let wire::Reply::Hello(welcome) = wire::read_reply(&mut client).await.unwrap() else {
            panic!("welcome");
        };
        assert_eq!(welcome.session.controller, id(incarnation));
        assert_eq!(welcome.session.broker, id(2));
        (control, client, welcome.session)
    }

    async fn observation(
        client: &mut tokio::io::DuplexStream,
        request: wire::Request,
    ) -> wire::Observation {
        wire::write_request(client, &request).await.unwrap();
        let wire::Reply::Observation(reply) = wire::read_reply(client).await.unwrap() else {
            panic!("observation");
        };
        reply
    }

    async fn bounded<F: std::future::Future>(future: F) -> F::Output {
        tokio::time::timeout(Duration::from_secs(10), future)
            .await
            .expect("owned fixture deadline")
    }

    #[tokio::test]
    async fn exact_wire_apply_and_eof_require_new_fence_and_full_reapply() {
        bounded(async {
            let broker = broker();
            let (control, mut client, session) = connect(&broker, 7).await;
            let policy = policy();
            let tx = transaction(session, 1, &policy);
            assert_eq!(
                observation(
                    &mut client,
                    wire::Request::Apply(wire::Apply {
                        transaction: tx.clone(),
                        expected_revision: None,
                        policy,
                    })
                )
                .await
                .outcome,
                wire::Outcome::Applied
            );
            drop(client);
            assert_eq!(control.join().await, Err(ManagementError::Connection));
            let (control, mut client, fresh) = connect(&broker, 7).await;
            assert!(fresh.connection > session.connection);
            let stale = observation(&mut client, wire::Request::Finish(tx.clone())).await;
            assert_eq!(stale.outcome, wire::Outcome::Rejected);
            assert_eq!(stale.failure, Some(wire::Failure::StaleLaunch));
            let mut fresh_tx = tx;
            fresh_tx.session = fresh;
            assert_eq!(
                observation(&mut client, wire::Request::Finish(fresh_tx.clone()))
                    .await
                    .outcome,
                wire::Outcome::Rejected,
                "reconnect did not restore authority"
            );
            assert_eq!(
                observation(
                    &mut client,
                    wire::Request::Apply(wire::Apply {
                        transaction: fresh_tx,
                        expected_revision: None,
                        policy: self::policy(),
                    })
                )
                .await
                .outcome,
                wire::Outcome::Applied
            );
            drop(client);
            assert!(control.join().await.is_err());
        })
        .await;
    }

    #[tokio::test]
    async fn pending_ack_requires_explicit_transport_retirement_and_drop_fences() {
        bounded(async {
            let broker = broker();
            let (control, mut client, session) = connect(&broker, 7).await;
            let policy = policy();
            let tx = transaction(session, 1, &policy);
            assert_eq!(
                observation(
                    &mut client,
                    wire::Request::Apply(wire::Apply {
                        transaction: tx.clone(),
                        expected_revision: None,
                        policy,
                    })
                )
                .await
                .outcome,
                wire::Outcome::Applied
            );
            let store = broker.managed_policy().unwrap();
            let fence = store.lock().await.fence_for(session).unwrap();
            let lease = store
                .lock()
                .await
                .reserve_transport(RelayContext {
                    fence,
                    launch: Launch::from_wire(&tx.launch),
                    revision: 1,
                    digest: tx.policy_digest.bytes(),
                    host: "git.example".into(),
                    port: 22,
                })
                .unwrap();
            let empty = wire::Policy {
                destroyed: false,
                credentials: vec![],
                patterns: vec![],
            };
            let next = transaction(session, 2, &empty);
            assert_eq!(
                observation(
                    &mut client,
                    wire::Request::Apply(wire::Apply {
                        transaction: next.clone(),
                        expected_revision: Some(1),
                        policy: empty,
                    })
                )
                .await
                .outcome,
                wire::Outcome::Pending
            );
            assert!(lease.termination().is_terminated());
            assert_eq!(
                observation(&mut client, wire::Request::Finish(next.clone()))
                    .await
                    .outcome,
                wire::Outcome::Pending
            );
            store.lock().await.complete_transport(lease).unwrap();
            assert_eq!(
                observation(&mut client, wire::Request::Finish(next))
                    .await
                    .outcome,
                wire::Outcome::Applied
            );
            drop(control);
            assert!(wire::read_reply(&mut client).await.is_err());
            assert!(store.lock().await.fence_for(session).is_err());
        })
        .await;
    }

    #[tokio::test]
    async fn malformed_frame_invalidates_current_management_session() {
        bounded(async {
            let broker = broker();
            let (control, mut client, session) = connect(&broker, 7).await;
            client.write_all(&[0, 0, 0, 1, 0xff]).await.unwrap();
            assert!(control.join().await.is_err());
            assert!(
                broker
                    .managed_policy()
                    .unwrap()
                    .lock()
                    .await
                    .fence_for(session)
                    .is_err()
            );
        })
        .await;
    }

    #[tokio::test]
    async fn second_connection_refusal_does_not_clear_the_first_owner() {
        bounded(async {
            let broker = broker();
            let (first, mut client, session) = connect(&broker, 7).await;
            let (mut other, server) = tokio::io::duplex(4096);
            let second = broker.spawn_managed_control(server).unwrap();
            wire::write_request(
                &mut other,
                &wire::Request::Hello(wire::Hello {
                    version: wire::VERSION,
                    controller: id(8),
                }),
            )
            .await
            .unwrap();
            assert_eq!(second.join().await, Err(ManagementError::Refused));
            assert!(
                broker
                    .managed_policy()
                    .unwrap()
                    .lock()
                    .await
                    .fence_for(session)
                    .is_ok()
            );
            let policy = policy();
            let tx = transaction(session, 1, &policy);
            assert_eq!(
                observation(
                    &mut client,
                    wire::Request::Apply(wire::Apply {
                        transaction: tx,
                        expected_revision: None,
                        policy,
                    })
                )
                .await
                .outcome,
                wire::Outcome::Applied
            );
            drop(client);
            assert!(first.join().await.is_err());
        })
        .await;
    }

    #[tokio::test]
    async fn invalid_material_replacement_preserves_applied_policy() {
        bounded(async {
            let broker = broker();
            let (control, mut client, session) = connect(&broker, 7).await;
            let policy = policy();
            let tx = transaction(session, 1, &policy);
            assert_eq!(
                observation(
                    &mut client,
                    wire::Request::Apply(wire::Apply {
                        transaction: tx.clone(),
                        expected_revision: None,
                        policy,
                    })
                )
                .await
                .outcome,
                wire::Outcome::Applied
            );
            let mut invalid = self::policy();
            invalid.credentials[0].upstream_public_key = "invalid-key".into();
            let next = transaction(session, 2, &invalid);
            let refused = observation(
                &mut client,
                wire::Request::Apply(wire::Apply {
                    transaction: next,
                    expected_revision: Some(1),
                    policy: invalid,
                }),
            )
            .await;
            assert_eq!(refused.outcome, wire::Outcome::Rejected);
            assert_eq!(refused.failure, Some(wire::Failure::InvalidPolicy));
            assert_eq!(
                observation(&mut client, wire::Request::Finish(tx))
                    .await
                    .outcome,
                wire::Outcome::Applied
            );
            drop(client);
            assert!(control.join().await.is_err());
        })
        .await;
    }

    async fn install_lease(
        broker: &Arc<Broker>,
        client: &mut tokio::io::DuplexStream,
        session: wire::BrokerSession,
    ) -> crate::policy::TransportAdmission {
        let policy = policy();
        let tx = transaction(session, 1, &policy);
        assert_eq!(
            observation(
                client,
                wire::Request::Apply(wire::Apply {
                    transaction: tx.clone(),
                    expected_revision: None,
                    policy,
                })
            )
            .await
            .outcome,
            wire::Outcome::Applied
        );
        let store = broker.managed_policy().unwrap();
        let fence = store.lock().await.fence_for(session).unwrap();
        store
            .lock()
            .await
            .reserve_transport(RelayContext {
                fence,
                launch: Launch::from_wire(&tx.launch),
                revision: 1,
                digest: tx.policy_digest.bytes(),
                host: "git.example".into(),
                port: 22,
            })
            .unwrap()
    }

    async fn probe(
        client: &mut tokio::io::DuplexStream,
        session: wire::BrokerSession,
        current: bool,
    ) {
        wire::write_request(client, &wire::Request::Probe(session))
            .await
            .unwrap();
        let wire::Reply::Probe(reply) = wire::read_reply(client).await.unwrap() else {
            panic!("probe");
        };
        assert_eq!(reply.session, session);
        assert_eq!(reply.current, current);
    }

    #[tokio::test(start_paused = true)]
    async fn current_probes_keep_owned_transport_alive_without_policy_reassertion() {
        let broker = broker();
        let (control, mut client, session) = connect(&broker, 7).await;
        let lease = install_lease(&broker, &mut client, session).await;
        for _ in 0..8 {
            tokio::time::advance(Duration::from_secs(wire::MANAGEMENT_PROBE_SECS)).await;
            probe(&mut client, session, true).await;
            assert!(!lease.termination().is_terminated());
        }
        assert!(
            broker
                .managed_policy()
                .unwrap()
                .lock()
                .await
                .select_transport(&lease, "git")
                .is_ok()
        );
        broker
            .managed_policy()
            .unwrap()
            .lock()
            .await
            .complete_transport(lease)
            .unwrap();
        drop(client);
        assert_eq!(control.join().await, Err(ManagementError::Connection));
    }

    #[tokio::test(start_paused = true)]
    async fn missed_probe_expires_absolute_lease_and_requests_owned_retirement() {
        let broker = broker();
        let (control, mut client, session) = connect(&broker, 7).await;
        let lease = install_lease(&broker, &mut client, session).await;
        tokio::time::advance(Duration::from_secs(31)).await;
        tokio::task::yield_now().await;
        assert!(lease.termination().is_terminated());
        let store = broker.managed_policy().unwrap();
        assert!(store.lock().await.fence_for(session).is_err());
        assert_eq!(
            store.lock().await.connect([8; 32]),
            Err(PolicyError::RetirementIncomplete)
        );
        store.lock().await.complete_transport(lease).unwrap();
        assert_eq!(control.join().await, Err(ManagementError::Connection));
    }

    #[tokio::test(start_paused = true)]
    async fn stale_probe_and_partial_frame_do_not_postpone_absolute_expiry() {
        for partial in [false, true] {
            let broker = broker();
            let (control, mut client, session) = connect(&broker, 7).await;
            tokio::time::advance(Duration::from_secs(25)).await;
            if partial {
                client.write_all(&[0, 0]).await.unwrap();
            } else {
                let mut stale = session;
                stale.connection += 1;
                probe(&mut client, stale, false).await;
                assert!(
                    broker
                        .managed_policy()
                        .unwrap()
                        .lock()
                        .await
                        .fence_for(session)
                        .is_ok()
                );
            }
            tokio::time::advance(Duration::from_secs(6)).await;
            assert_eq!(control.join().await, Err(ManagementError::Connection));
            assert!(
                broker
                    .managed_policy()
                    .unwrap()
                    .lock()
                    .await
                    .fence_for(session)
                    .is_err()
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn unjoined_relay_deadline_preserves_primary_and_retirement_failures() {
        let broker = broker();
        let (control, mut client, session) = connect(&broker, 7).await;
        let lease = install_lease(&broker, &mut client, session).await;
        drop(client);
        assert_eq!(
            control.join().await,
            Err(ManagementError::RetirementIncomplete {
                primary: Some(ManagementFailure::Connection),
            })
        );
        assert!(lease.termination().is_terminated());
        let store = broker.managed_policy().unwrap();
        assert!(store.lock().await.fence_for(session).is_err());
        assert_eq!(
            store.lock().await.connect([8; 32]),
            Err(PolicyError::RetirementIncomplete)
        );
        store.lock().await.complete_transport(lease).unwrap();
        assert!(store.lock().await.connect([8; 32]).is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn expired_apply_cannot_install_after_parsing_or_waiting_for_store() {
        let broker = broker();
        let fence = broker
            .managed_policy()
            .unwrap()
            .lock()
            .await
            .connect([7; 32])
            .unwrap();
        let policy = policy();
        let tx = transaction(fence.session(), 1, &policy);
        assert!(matches!(
            apply(
                &broker,
                fence,
                wire::Request::Apply(wire::Apply {
                    transaction: tx.clone(),
                    expected_revision: None,
                    policy,
                }),
                Instant::now(),
                &TerminationHandle::new()
            )
            .await,
            Err(ManagementError::Connection)
        ));
        assert_eq!(
            broker.managed_policy().unwrap().lock().await.finish(
                fence,
                &Launch::from_wire(&tx.launch),
                tx.revision,
                tx.policy_digest.bytes()
            ),
            Err(PolicyError::StalePolicy)
        );
        broker
            .managed_policy()
            .unwrap()
            .lock()
            .await
            .state_lost(fence)
            .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn old_cleanup_never_waits_for_or_cancels_newer_connection_relays() {
        let broker = broker();
        let store = broker.managed_policy().unwrap();
        let old = store.lock().await.connect([7; 32]).unwrap();
        assert_eq!(store.lock().await.state_lost(old), Ok(ApplyStatus::Applied));
        let fresh = store.lock().await.connect([8; 32]).unwrap();
        let policy = policy();
        let tx = transaction(fresh.session(), 1, &policy);
        store
            .lock()
            .await
            .install(
                fresh,
                None,
                LaunchPolicy::from_wire(
                    Launch::from_wire(&tx.launch),
                    1,
                    tx.policy_digest.bytes(),
                    policy,
                )
                .unwrap(),
            )
            .unwrap();
        let lease = store
            .lock()
            .await
            .reserve_transport(RelayContext {
                fence: fresh,
                launch: Launch::from_wire(&tx.launch),
                revision: 1,
                digest: tx.policy_digest.bytes(),
                host: "git.example".into(),
                port: 22,
            })
            .unwrap();
        assert_eq!(
            retire_after(&broker, old, Duration::from_secs(1)).await,
            Ok(())
        );
        assert!(!lease.termination().is_terminated());
        assert!(store.lock().await.fence_for(fresh.session()).is_ok());
        assert!(store.lock().await.select_transport(&lease, "git").is_ok());
        store.lock().await.complete_transport(lease).unwrap();
        assert_eq!(
            retire_after(&broker, fresh, Duration::from_secs(1)).await,
            Ok(())
        );
    }

    #[test]
    fn configured_identity_encoding_cannot_relabel_separator_components() {
        let session = PolicyStore::new([2; 32], 1, 1)
            .unwrap()
            .connect([7; 32])
            .unwrap()
            .session();
        let a = transaction(session, 1, &policy()).launch;
        let mut b = a.clone();
        b.instance.workload.context = Some("context5:agent".into());
        b.instance.workload.name = "".into();
        assert_ne!(Launch::from_wire(&a), Launch::from_wire(&b));
        let mut c = a.clone();
        c.instance.workload.context = None;
        let mut d = c.clone();
        d.instance.workload.context = Some("".into());
        assert_ne!(Launch::from_wire(&c), Launch::from_wire(&d));
    }
}
