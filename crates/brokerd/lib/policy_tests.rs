use super::*;
use microsandbox_protocol::bootstrap::BrokerSshKey;

fn launch(name: &str, generation: u8) -> Launch {
    Launch {
        instance: name.into(),
        generation: [generation; 32],
    }
}

fn credential(name: &str, host: &str, user: &str, key: u8) -> Arc<ReadyCredential> {
    let material = Arc::new(
        BrokerKey::from_bootstrap(BrokerSshKey {
            key_type: "ed25519".into(),
            key_bytes: vec![key; 32],
        })
        .unwrap(),
    );
    ReadyCredential::new(
        CredentialRecord {
            name: name.into(),
            material: format!("owner/{name}"),
            binding: CredentialBinding::Broker,
            key_version: [key; 32],
            trust_version: [9; 32],
            host: host.into(),
            port: 22,
            user: user.into(),
            on_violation: "block".into(),
        },
        Arc::clone(&material),
        UpstreamPin {
            user: user.into(),
            expected: material.private_key().public_key().clone(),
        },
    )
    .unwrap()
}

fn policy(
    launch: Launch,
    revision: u64,
    credentials: Vec<Arc<ReadyCredential>>,
) -> Arc<LaunchPolicy> {
    LaunchPolicy::new(launch, revision, [revision as u8; 32], credentials).unwrap()
}

fn store() -> (PolicyStore, ManagementFence) {
    let mut store = PolicyStore::new([1; 32], 4, 8).unwrap();
    let fence = store.connect([2; 32]).unwrap();
    (store, fence)
}

fn admit(
    store: &mut PolicyStore,
    fence: ManagementFence,
    target: &Arc<LaunchPolicy>,
    host: &str,
    user: &str,
) -> Result<RelayAdmission, PolicyError> {
    store.admit(
        fence,
        &target.launch,
        target.revision,
        target.digest,
        host,
        22,
        user,
    )
}

fn context(fence: ManagementFence, target: &LaunchPolicy) -> RelayContext {
    RelayContext {
        fence,
        launch: target.launch.clone(),
        revision: target.revision,
        digest: target.digest,
        host: "git.example".into(),
        port: 22,
    }
}

fn wire_policy() -> wire::Policy {
    let key = credential("wire-key", "git.example", "git", 3);
    wire::Policy {
        destroyed: false,
        credentials: vec![wire::ReadyRecord {
            name: "wire-key".into(),
            material: "owner/wire-key".into(),
            binding: wire::Binding::Broker,
            key_version: wire::Id::from_bytes([3; 32]).unwrap(),
            trust_version: wire::Id::from_bytes([9; 32]).unwrap(),
            host: "git.example".into(),
            port: 22,
            user: "git".into(),
            on_violation: wire::Violation::Block,
            key_kind: wire::KeyKind::Ed25519Seed,
            key_bytes: wire::SecretBytes::new(vec![3; 32]),
            upstream_public_key: key.pin.expected.to_openssh().unwrap(),
        }],
        patterns: vec![wire::Pattern {
            credential_id: "wire-key".into(),
            decoder: microsandbox_scan::Decoder::Raw,
            bytes: wire::SecretBytes::new(b"synthetic-pattern".to_vec()),
            action: wire::PatternAction {
                enforce: Some(microsandbox_scan::Severity::Block),
                audit: false,
                count: true,
            },
        }],
    }
}

fn from_wire(input: wire::Policy, revision: u64) -> Arc<LaunchPolicy> {
    let digest = wire::policy_digest(&input).unwrap().bytes();
    LaunchPolicy::from_wire(launch("wire", 1), revision, digest, input).unwrap()
}

#[test]
fn wire_material_and_scanner_are_bound_to_the_same_transport_policy() {
    let (mut store, fence) = store();
    let p = from_wire(wire_policy(), 1);
    store.install(fence, None, Arc::clone(&p)).unwrap();
    let lease = store.reserve_transport(context(fence, &p)).unwrap();
    assert!(Arc::ptr_eq(&lease.library(), &p.library));
    let mut scan = microsandbox_scan::ScanState::new(&lease.library());
    let report = scan.scan_chunk(b"prefix synthetic-pattern suffix");
    assert!(!report.hits.is_empty());
    assert_eq!(
        report.strictest_action.unwrap().enforce,
        Some(microsandbox_scan::Severity::Block)
    );
    let selected = store.select_transport(&lease, "git").unwrap();
    assert_eq!(selected.record.material, "owner/wire-key");
    assert_eq!(
        selected.key.private_key().public_key().key_data(),
        credential("wire-key", "git.example", "git", 3)
            .key
            .private_key()
            .public_key()
            .key_data()
    );
    store.complete_transport(lease).unwrap();
}

#[test]
fn wire_changed_material_trust_or_pattern_cannot_reuse_digest_or_revision() {
    for change in 0..3 {
        let original = wire_policy();
        let digest = wire::policy_digest(&original).unwrap().bytes();
        let (mut store, fence) = store();
        let p = from_wire(original, 1);
        store.install(fence, None, Arc::clone(&p)).unwrap();
        let mutate = |mut candidate: wire::Policy| {
            match change {
                0 => candidate.credentials[0].key_bytes = wire::SecretBytes::new(vec![4; 32]),
                1 => {
                    candidate.credentials[0].trust_version = wire::Id::from_bytes([8; 32]).unwrap()
                }
                _ => {
                    candidate.patterns[0].bytes =
                        wire::SecretBytes::new(b"different-pattern".to_vec())
                }
            }
            candidate
        };
        assert!(matches!(
            LaunchPolicy::from_wire(p.launch.clone(), 1, digest, mutate(wire_policy())),
            Err(PolicyError::InvalidPolicy)
        ));
        let changed = from_wire(mutate(wire_policy()), 1);
        assert_eq!(
            store.install(fence, Some(1), changed),
            Err(PolicyError::StalePolicy)
        );
        assert!(store.reserve_transport(context(fence, &p)).is_ok());
    }
}

#[test]
fn wire_unparseable_pin_and_excluded_scanner_inputs_refuse_before_install() {
    for bad in 0..3 {
        let mut candidate = wire_policy();
        match bad {
            0 => candidate.credentials[0].upstream_public_key = "not-an-ssh-key".into(),
            1 => candidate.patterns[0].bytes = wire::SecretBytes::new(b"short".to_vec()),
            _ => {
                candidate.patterns[0].decoder = microsandbox_scan::Decoder::Base64;
                candidate.patterns[0].bytes = wire::SecretBytes::new(b"not%base64".to_vec());
            }
        }
        let digest = wire::policy_digest(&candidate).unwrap().bytes();
        assert!(matches!(
            LaunchPolicy::from_wire(launch("wire", 1), 1, digest, candidate),
            Err(PolicyError::InvalidPolicy)
        ));
    }
}

#[test]
fn current_and_pending_authored_patterns_share_one_budget_until_retirement() {
    let (mut store, fence) = store();
    // Model accounting at the limit without allocating a large synthetic secret.
    let mut p = from_wire(wire_policy(), 1);
    Arc::get_mut(&mut p).unwrap().pattern_bytes = MAX_HELD_PATTERN_BYTES - 32;
    store.install(fence, None, Arc::clone(&p)).unwrap();
    let lease = store.reserve_transport(context(fence, &p)).unwrap();
    let mut too_large = from_wire(wire_policy(), 2);
    Arc::get_mut(&mut too_large).unwrap().pattern_bytes = 33;
    assert_eq!(
        store.install(fence, Some(1), too_large),
        Err(PolicyError::Capacity)
    );
    assert!(
        !lease.termination.is_terminated(),
        "capacity refusal must not cancel current authority"
    );
    let mut next = from_wire(wire_policy(), 2);
    Arc::get_mut(&mut next).unwrap().pattern_bytes = 32;
    assert_eq!(
        store.install(fence, Some(1), Arc::clone(&next)),
        Ok(ApplyStatus::Pending)
    );
    let mut other = policy(launch("other", 1), 1, vec![]);
    Arc::get_mut(&mut other).unwrap().pattern_bytes = 1;
    assert_eq!(
        store.install(fence, None, Arc::clone(&other)),
        Err(PolicyError::Capacity)
    );
    store.complete_transport(lease).unwrap();
    assert_eq!(
        store.finish(fence, &next.launch, 2, next.digest),
        Ok(ApplyStatus::Applied)
    );
    assert_eq!(store.install(fence, None, other), Ok(ApplyStatus::Applied));
}

#[test]
fn global_pattern_count_bounds_small_pattern_metadata_before_cancellation() {
    let mut store = PolicyStore::new([1; 32], 32, 8).unwrap();
    let fence = store.connect([2; 32]).unwrap();
    let mut first = None;
    for index in 0..16 {
        let mut input = wire_policy();
        input.patterns = (0..256)
            .map(|_| wire::Pattern {
                credential_id: "wire-key".into(),
                decoder: microsandbox_scan::Decoder::Raw,
                bytes: wire::SecretBytes::new(b"synthetic-pattern".to_vec()),
                action: wire::PatternAction {
                    enforce: Some(microsandbox_scan::Severity::Block),
                    audit: false,
                    count: true,
                },
            })
            .collect();
        let mut p = from_wire(input, 1);
        Arc::get_mut(&mut p).unwrap().launch.instance = format!("wire-{index}");
        store.install(fence, None, Arc::clone(&p)).unwrap();
        if index == 0 {
            first = Some(p);
        }
    }
    let first = first.unwrap();
    let lease = store.reserve_transport(context(fence, &first)).unwrap();
    let mut next = from_wire(wire_policy(), 2);
    Arc::get_mut(&mut next).unwrap().launch = first.launch.clone();
    assert_eq!(
        store.install(fence, Some(1), next),
        Err(PolicyError::Capacity)
    );
    assert!(!lease.termination().is_terminated());
    let empty = LaunchPolicy::new(first.launch.clone(), 2, [8; 32], vec![]).unwrap();
    assert_eq!(
        store.install(fence, Some(1), Arc::clone(&empty)),
        Ok(ApplyStatus::Pending)
    );
    let mut other = from_wire(wire_policy(), 1);
    Arc::get_mut(&mut other).unwrap().launch.instance = "another".into();
    assert_eq!(
        store.install(fence, None, Arc::clone(&other)),
        Err(PolicyError::Capacity)
    );
    store.complete_transport(lease).unwrap();
    assert_eq!(
        store.finish(fence, &empty.launch, 2, empty.digest),
        Ok(ApplyStatus::Applied)
    );
    assert_eq!(store.install(fence, None, other), Ok(ApplyStatus::Applied));
}

#[test]
fn destroyed_generation_is_terminal_but_identical_ack_is_idempotent() {
    let (mut store, fence) = store();
    let p = from_wire(wire_policy(), 1);
    store.install(fence, None, Arc::clone(&p)).unwrap();
    let destroyed = from_wire(
        wire::Policy {
            destroyed: true,
            credentials: vec![],
            patterns: vec![],
        },
        2,
    );
    assert_eq!(
        store.install(fence, Some(1), Arc::clone(&destroyed)),
        Ok(ApplyStatus::Applied)
    );
    assert_eq!(
        store.install(fence, Some(1), Arc::clone(&destroyed)),
        Ok(ApplyStatus::Applied)
    );
    assert_eq!(
        store.install(fence, Some(2), from_wire(wire_policy(), 3)),
        Err(PolicyError::StalePolicy)
    );
    let mut fresh = from_wire(wire_policy(), 3);
    Arc::get_mut(&mut fresh).unwrap().launch.generation = [2; 32];
    assert_eq!(
        store.install(fence, Some(2), fresh),
        Ok(ApplyStatus::Applied)
    );
}

#[test]
fn preauth_transport_is_bounded_and_state_loss_waits_for_its_join() {
    let (mut store, fence) = store();
    let p = policy(
        launch("a", 1),
        1,
        vec![credential("key", "git.example", "git", 3)],
    );
    store.install(fence, None, Arc::clone(&p)).unwrap();
    let lease = store.reserve_transport(context(fence, &p)).unwrap();
    assert!(matches!(
        store.select_transport(&lease, "root"),
        Err(PolicyError::Unauthorized)
    ));
    assert!(store.select_transport(&lease, "git").is_ok());
    assert_eq!(store.state_lost(fence), Ok(ApplyStatus::Pending));
    assert!(lease.termination.is_terminated());
    assert!(store.select_transport(&lease, "git").is_err());
    assert_eq!(
        store.connect([3; 32]),
        Err(PolicyError::RetirementIncomplete)
    );
    store.complete_transport(lease).unwrap();
    let fresh = store.connect([3; 32]).unwrap();
    assert!(
        store.reserve_transport(context(fresh, &p)).is_err(),
        "reconnect requires reapply"
    );
    assert!(store.install(fence, None, Arc::clone(&p)).is_err());
    store.install(fresh, None, Arc::clone(&p)).unwrap();
    assert!(store.reserve_transport(context(fresh, &p)).is_ok());
}

#[test]
fn transport_rechecks_replacement_and_never_selects_an_ip_alias() {
    let (mut store, fence) = store();
    let p = policy(
        launch("a", 1),
        1,
        vec![credential("key", "git.example", "git", 3)],
    );
    store.install(fence, None, Arc::clone(&p)).unwrap();
    let mut wrong = context(fence, &p);
    wrong.host = "127.0.0.1".into();
    assert!(matches!(
        store.reserve_transport(wrong),
        Err(PolicyError::Unauthorized)
    ));
    assert!(store.relays.is_empty());
    let lease = store.reserve_transport(context(fence, &p)).unwrap();
    let next = policy(p.launch.clone(), 2, vec![]);
    assert_eq!(
        store.install(fence, Some(1), Arc::clone(&next)),
        Ok(ApplyStatus::Pending)
    );
    assert!(store.select_transport(&lease, "git").is_err());
    assert_eq!(
        store.finish(fence, &next.launch, 2, next.digest),
        Ok(ApplyStatus::Pending)
    );
    store.complete_transport(lease).unwrap();
    assert_eq!(
        store.finish(fence, &next.launch, 2, next.digest),
        Ok(ApplyStatus::Applied)
    );
}

#[test]
fn transport_wrong_store_and_capacity_cannot_release_other_ownership() {
    let (mut first, fence) = store();
    let (mut second, other_fence) = store();
    let p = policy(
        launch("a", 1),
        1,
        vec![credential("key", "git.example", "git", 3)],
    );
    first.install(fence, None, Arc::clone(&p)).unwrap();
    second.install(other_fence, None, Arc::clone(&p)).unwrap();
    let lease = first.reserve_transport(context(fence, &p)).unwrap();
    let other = second.reserve_transport(context(other_fence, &p)).unwrap();
    assert!(second.select_transport(&lease, "git").is_err());
    assert_eq!(
        second.complete_transport(lease),
        Err(PolicyError::StaleManagement)
    );
    assert_eq!(second.relays.len(), 1);
    second.max_relays = 1;
    assert!(matches!(
        second.reserve_transport(context(other_fence, &p)),
        Err(PolicyError::Capacity)
    ));
    second.complete_transport(other).unwrap();
}

#[test]
fn simultaneous_launches_select_their_own_complete_record() {
    let (mut store, fence) = store();
    let a = policy(
        launch("a", 1),
        1,
        vec![credential("a-key", "git.example", "git", 3)],
    );
    let b = policy(
        launch("b", 2),
        1,
        vec![credential("b-key", "git.example", "git", 4)],
    );
    store.install(fence, None, Arc::clone(&a)).unwrap();
    store.install(fence, None, Arc::clone(&b)).unwrap();
    let first = admit(&mut store, fence, &a, "git.example", "git").unwrap();
    let second = admit(&mut store, fence, &b, "git.example", "git").unwrap();
    assert_eq!(first.record().material, "owner/a-key");
    assert_eq!(second.record().key_version, [4; 32]);
    assert_ne!(
        first.material().0.private_key().public_key(),
        second.material().0.private_key().public_key()
    );
}

#[test]
fn fields_never_union_and_user_host_port_are_exact() {
    let (mut store, fence) = store();
    let p = policy(
        launch("a", 1),
        1,
        vec![
            credential("first", "one.example", "alice", 3),
            credential("second", "two.example", "bob", 4),
        ],
    );
    store.install(fence, None, Arc::clone(&p)).unwrap();
    for (host, user) in [
        ("one.example", "bob"),
        ("two.example", "alice"),
        ("one.example", "Alice"),
        ("one.example", "alice "),
        ("one.example", ""),
        ("ONE.example", "alice"),
        ("127.0.0.1", "alice"),
    ] {
        assert!(matches!(
            admit(&mut store, fence, &p, host, user),
            Err(PolicyError::Unauthorized)
        ));
    }
    assert!(matches!(
        store.admit(fence, &p.launch, 1, p.digest, "one.example", 2222, "alice"),
        Err(PolicyError::Unauthorized)
    ));
    assert!(
        store.relays.is_empty(),
        "denials must not acquire relay ownership"
    );
}

#[test]
fn ambiguous_keys_are_rejected_before_any_install_effect() {
    let (mut store, fence) = store();
    let p = policy(
        launch("a", 1),
        1,
        vec![credential("first", "one.example", "git", 3)],
    );
    store.install(fence, None, Arc::clone(&p)).unwrap();
    assert!(matches!(
        LaunchPolicy::new(
            p.launch.clone(),
            2,
            [2; 32],
            vec![
                credential("first", "one.example", "git", 3),
                credential("second", "one.example", "git", 4)
            ]
        ),
        Err(PolicyError::AmbiguousCredential)
    ));
    assert!(admit(&mut store, fence, &p, "one.example", "git").is_ok());
}

#[test]
fn unsupported_patterns_and_mismatched_upstream_user_refuse() {
    let good = credential("first", "one.example", "git", 3);
    for host in [
        "*.example",
        "one?example",
        "[::1]",
        "one.example\nother",
        "",
    ] {
        let mut record = good.record.clone();
        record.host = host.into();
        assert!(matches!(
            ReadyCredential::new(record, Arc::clone(&good.key), good.pin.clone()),
            Err(PolicyError::InvalidPolicy)
        ));
    }
    let mut pin = good.pin.clone();
    pin.user = "other".into();
    assert!(matches!(
        ReadyCredential::new(good.record.clone(), Arc::clone(&good.key), pin),
        Err(PolicyError::InvalidPolicy)
    ));
}

#[test]
fn replacement_waits_for_completion_not_just_cancellation_or_drop() {
    let (mut store, fence) = store();
    let p = policy(
        launch("a", 1),
        1,
        vec![credential("first", "one.example", "git", 3)],
    );
    store.install(fence, None, Arc::clone(&p)).unwrap();
    let relay = admit(&mut store, fence, &p, "one.example", "git").unwrap();
    let next = policy(p.launch.clone(), 2, Vec::new());
    assert_eq!(
        store.install(fence, Some(1), Arc::clone(&next)),
        Ok(ApplyStatus::Pending)
    );
    assert!(relay.termination().is_terminated());
    assert!(matches!(
        admit(&mut store, fence, &p, "one.example", "git"),
        Err(PolicyError::StalePolicy)
    ));
    assert_eq!(
        store.finish(fence, &next.launch, 2, next.digest),
        Ok(ApplyStatus::Pending)
    );
    drop(relay);
    assert_eq!(
        store.finish(fence, &next.launch, 2, next.digest),
        Ok(ApplyStatus::Pending)
    );
}

#[test]
fn completed_revocation_preserves_unrelated_session() {
    let (mut store, fence) = store();
    let a = policy(
        launch("a", 1),
        1,
        vec![credential("a", "one.example", "git", 3)],
    );
    let b = policy(
        launch("b", 2),
        1,
        vec![credential("b", "one.example", "git", 4)],
    );
    store.install(fence, None, Arc::clone(&a)).unwrap();
    store.install(fence, None, Arc::clone(&b)).unwrap();
    let first = admit(&mut store, fence, &a, "one.example", "git").unwrap();
    let second = admit(&mut store, fence, &b, "one.example", "git").unwrap();
    let revoked = policy(a.launch.clone(), 2, Vec::new());
    assert_eq!(
        store.install(fence, Some(1), Arc::clone(&revoked)),
        Ok(ApplyStatus::Pending)
    );
    assert!(first.termination().is_terminated());
    assert!(!second.termination().is_terminated());
    store.complete_relay(first).unwrap();
    assert_eq!(
        store.finish(fence, &revoked.launch, 2, revoked.digest),
        Ok(ApplyStatus::Applied)
    );
    assert!(matches!(
        admit(&mut store, fence, &revoked, "one.example", "git"),
        Err(PolicyError::Unauthorized)
    ));
    assert!(!second.termination().is_terminated());
}

#[test]
fn state_loss_invalidates_every_admission_and_old_transaction() {
    let (mut store, old) = store();
    let a = policy(
        launch("a", 1),
        1,
        vec![credential("a", "one.example", "git", 3)],
    );
    let b = policy(
        launch("b", 2),
        1,
        vec![credential("b", "one.example", "git", 4)],
    );
    store.install(old, None, Arc::clone(&a)).unwrap();
    store.install(old, None, Arc::clone(&b)).unwrap();
    let first = admit(&mut store, old, &a, "one.example", "git").unwrap();
    let second = admit(&mut store, old, &b, "one.example", "git").unwrap();
    assert_eq!(store.state_lost(old), Ok(ApplyStatus::Pending));
    assert!(first.termination().is_terminated() && second.termination().is_terminated());
    assert_eq!(
        store.install(old, None, Arc::clone(&a)),
        Err(PolicyError::StaleManagement)
    );
    assert_eq!(
        store.connect([2; 32]),
        Err(PolicyError::RetirementIncomplete)
    );
    store.complete_relay(first).unwrap();
    store.complete_relay(second).unwrap();
    let new = store.connect([2; 32]).unwrap();
    assert_ne!(old, new);
    assert!(matches!(
        admit(&mut store, new, &a, "one.example", "git"),
        Err(PolicyError::StalePolicy)
    ));
    assert_eq!(
        store.install(old, None, Arc::clone(&a)),
        Err(PolicyError::StaleManagement)
    );
    assert_eq!(store.state_lost(old), Err(PolicyError::StaleManagement));
    store.install(new, None, Arc::clone(&a)).unwrap();
    assert!(admit(&mut store, new, &a, "one.example", "git").is_ok());
    assert!(matches!(
        admit(&mut store, new, &b, "one.example", "git"),
        Err(PolicyError::StalePolicy)
    ));
}

#[test]
fn stale_generation_revision_and_digest_do_not_acquire_sessions() {
    let (mut store, fence) = store();
    let p = policy(
        launch("a", 1),
        2,
        vec![credential("a", "one.example", "git", 3)],
    );
    store.install(fence, None, Arc::clone(&p)).unwrap();
    for (target, revision, digest) in [
        (launch("a", 2), 2, p.digest),
        (p.launch.clone(), 1, p.digest),
        (p.launch.clone(), 2, [5; 32]),
    ] {
        assert!(matches!(
            store.admit(fence, &target, revision, digest, "one.example", 22, "git"),
            Err(PolicyError::StalePolicy)
        ));
    }
    assert!(store.relays.is_empty());
}

#[test]
fn identical_retry_is_idempotent_but_changed_key_or_trust_is_not() {
    let (mut store, fence) = store();
    let record = credential("a", "one.example", "git", 3);
    let p = policy(launch("a", 1), 1, vec![Arc::clone(&record)]);
    store.install(fence, None, Arc::clone(&p)).unwrap();
    let duplicate = policy(
        p.launch.clone(),
        1,
        vec![credential("a", "one.example", "git", 3)],
    );
    assert_eq!(
        store.install(fence, None, duplicate),
        Ok(ApplyStatus::Applied)
    );
    let other = credential("other", "other.example", "other", 4);
    for changed in [
        ReadyCredential::new(
            record.record.clone(),
            Arc::clone(&other.key),
            record.pin.clone(),
        )
        .unwrap(),
        ReadyCredential::new(
            record.record.clone(),
            Arc::clone(&record.key),
            UpstreamPin {
                user: "git".into(),
                expected: other.pin.expected.clone(),
            },
        )
        .unwrap(),
    ] {
        assert_eq!(
            store.install(fence, Some(1), policy(p.launch.clone(), 1, vec![changed])),
            Err(PolicyError::StalePolicy)
        );
    }
}

#[test]
fn replaced_generation_cannot_return_through_old_install_or_cleanup() {
    let (mut store, fence) = store();
    let old = policy(
        launch("a", 1),
        1,
        vec![credential("a", "one.example", "git", 3)],
    );
    let new = policy(
        launch("a", 2),
        1,
        vec![credential("a", "one.example", "git", 4)],
    );
    store.install(fence, None, Arc::clone(&old)).unwrap();
    assert_eq!(
        store.install(fence, Some(1), Arc::clone(&new)),
        Err(PolicyError::RetirementIncomplete)
    );
    let revoked = policy(old.launch.clone(), 2, Vec::new());
    store.install(fence, Some(1), Arc::clone(&revoked)).unwrap();
    store.install(fence, Some(2), Arc::clone(&new)).unwrap();
    assert_eq!(
        store.install(fence, Some(1), Arc::clone(&old)),
        Err(PolicyError::StalePolicy)
    );
    assert_eq!(
        store.finish(fence, &old.launch, 2, revoked.digest),
        Err(PolicyError::StalePolicy)
    );
    assert!(admit(&mut store, fence, &new, "one.example", "git").is_ok());
}

#[test]
fn foreign_completion_cannot_retire_same_numeric_relay_id() {
    let (mut one, first) = store();
    let (mut two, second) = store();
    let p = policy(
        launch("a", 1),
        1,
        vec![credential("a", "one.example", "git", 3)],
    );
    one.install(first, None, Arc::clone(&p)).unwrap();
    two.install(second, None, Arc::clone(&p)).unwrap();
    let a = admit(&mut one, first, &p, "one.example", "git").unwrap();
    let b = admit(&mut two, second, &p, "one.example", "git").unwrap();
    assert_eq!(one.complete_relay(b), Err(PolicyError::StaleManagement));
    assert_eq!(one.relays.len(), 1);
    assert_eq!(two.relays.len(), 1);
    one.complete_relay(a).unwrap();
    assert!(one.relays.is_empty());
}

#[test]
fn finite_capacity_refuses_without_replacing_existing_authority() {
    let mut store = PolicyStore::new([1; 32], 1, 1).unwrap();
    let fence = store.connect([2; 32]).unwrap();
    let p = policy(
        launch("a", 1),
        1,
        vec![credential("a", "one.example", "git", 3)],
    );
    store.install(fence, None, Arc::clone(&p)).unwrap();
    assert_eq!(
        store.install(fence, None, policy(launch("b", 2), 1, Vec::new())),
        Err(PolicyError::Capacity)
    );
    let _held = admit(&mut store, fence, &p, "one.example", "git").unwrap();
    assert!(matches!(
        admit(&mut store, fence, &p, "one.example", "git"),
        Err(PolicyError::Capacity)
    ));
    assert_eq!(store.connect([3; 32]), Err(PolicyError::StaleManagement));
}

#[tokio::test]
async fn actual_broker_owns_closed_managed_admission_and_fences_state_loss() {
    let broker = crate::Broker::new_managed(
        crate::BrokerConfig::default(),
        crate::ssh::build_server_config().unwrap(),
        [1; 32],
        4,
        8,
    )
    .unwrap();
    let mut store = broker.managed_policy().unwrap().lock().await;
    let old = store.connect([2; 32]).unwrap();
    let p = policy(
        launch("a", 1),
        1,
        vec![credential("a", "one.example", "git", 3)],
    );
    assert!(matches!(
        admit(&mut store, old, &p, "one.example", "git"),
        Err(PolicyError::StalePolicy)
    ));
    store.install(old, None, Arc::clone(&p)).unwrap();
    let relay = admit(&mut store, old, &p, "one.example", "git").unwrap();
    assert_eq!(store.state_lost(old), Ok(ApplyStatus::Pending));
    assert_eq!(
        store.install(old, None, Arc::clone(&p)),
        Err(PolicyError::StaleManagement)
    );
    store.complete_relay(relay).unwrap();
    let new = store.connect([2; 32]).unwrap();
    assert!(matches!(
        admit(&mut store, new, &p, "one.example", "git"),
        Err(PolicyError::StalePolicy)
    ));
    store.install(new, None, Arc::clone(&p)).unwrap();
    assert!(admit(&mut store, new, &p, "one.example", "git").is_ok());
}

#[test]
fn guest_binding_and_private_debug_data_are_not_admitted_or_exposed() {
    let good = credential("first", "one.example", "git", 3);
    let debug = format!("{good:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("OPENSSH PRIVATE KEY"));
    assert!(!debug.contains("Ed25519Keypair"));
    let mut record = good.record.clone();
    record.binding = CredentialBinding::Guest;
    assert!(matches!(
        ReadyCredential::new(record, Arc::clone(&good.key), good.pin.clone()),
        Err(PolicyError::InvalidPolicy)
    ));
}

#[test]
fn dropping_store_closes_owned_admission_but_does_not_report_cleanup() {
    let (mut store, fence) = store();
    let p = policy(
        launch("a", 1),
        1,
        vec![credential("a", "one.example", "git", 3)],
    );
    store.install(fence, None, Arc::clone(&p)).unwrap();
    let relay = admit(&mut store, fence, &p, "one.example", "git").unwrap();
    assert_eq!(
        store.finish(fence, &p.launch, p.revision, p.digest),
        Ok(ApplyStatus::Applied)
    );
    drop(store);
    assert!(relay.termination().is_terminated());
}

#[tokio::test]
async fn managed_broker_refuses_legacy_console_before_transport_io() {
    let broker = crate::Broker::new_managed(
        crate::BrokerConfig::default(),
        crate::ssh::build_server_config().unwrap(),
        [1; 32],
        4,
        8,
    )
    .unwrap();
    let err = broker
        .run(
            tempfile::tempfile().unwrap(),
            crate::console::BootConsole { input: vec![0xff] },
        )
        .await
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("managed broker refuses legacy console control")
    );
    assert!(
        crate::Broker::new_managed(
            crate::BrokerConfig::default(),
            Arc::new(russh::server::Config::default()),
            [1; 32],
            4,
            8
        )
        .is_err()
    );
}
