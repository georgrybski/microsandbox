//! Applied, launch-scoped custody state for the managed broker.
//!
//! These are in-process types, not a wire protocol or a source of desired
//! authority. The authenticated management adapter supplies verified launches
//! and parsed material. A transition closes admission before cancellation and
//! cannot complete until the owner reports every affected relay fully joined.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use thiserror::Error;

use microsandbox_protocol::{
    bootstrap::{BrokerSshKey, BrokerUpstreamHost},
    broker as wire,
};
use microsandbox_scan::{ActionSet, PatternLibrary, ScanPattern};

use crate::keys::BrokerKey;
use crate::ssh::{TerminationHandle, UpstreamPin, parse_upstream_pin};

/// Maximum authored pattern bytes held across current and pending policies.
const MAX_HELD_PATTERN_BYTES: usize = 16 * 1024 * 1024;
const MAX_HELD_PATTERNS: usize = 4096;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Opaque identity supplied by the trusted lifecycle/credential owner.
pub type Identity = [u8; 32];

/// Exact launch inside one controller's security domain; never guest-asserted.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Launch {
    /// Existing context/workload/instance identity, canonically encoded by the adapter.
    pub instance: String,
    /// Per-boot generation, not a sandbox name, CID or wall-clock timestamp.
    pub generation: Identity,
}

/// Store-issued fence for one authenticated management connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManagementFence {
    broker: Identity,
    controller: Identity,
    connection: u64,
}

impl ManagementFence {
    /// The broker-issued identity the authenticated controller must adopt.
    pub fn session(self) -> wire::BrokerSession {
        wire::BrokerSession {
            broker: wire::Id::from_bytes(self.broker).expect("validated broker identity"),
            controller: wire::Id::from_bytes(self.controller)
                .expect("validated controller identity"),
            connection: self.connection,
        }
    }
}

impl Launch {
    /// Collision-free length-delimited encoding of the configured identity.
    /// Separators inside one name cannot relabel another workload or context.
    pub fn from_wire(value: &wire::LaunchRef) -> Self {
        let workload = &value.instance.workload;
        let context = match &workload.context {
            Some(value) => format!("s{}:{value}", value.len()),
            None => "n".into(),
        };
        Self {
            instance: format!(
                "{context}{}:{}{}:{}",
                workload.name.len(),
                workload.name,
                value.instance.instance.len(),
                value.instance.instance
            ),
            generation: value.generation.bytes(),
        }
    }
}

/// Existing compiled custody distinction; managed admission accepts only Broker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialBinding {
    /// Key remains in the broker.
    Broker,
    /// Key is guest-held and is not admissible on this terminating path.
    Guest,
}

/// Complete exact-destination projection of one compiled credential record.
///
/// The adapter must retain the original record relationship when expanding an
/// existing policy. This initial subset refuses patterns rather than assigning
/// wildcard or DNS semantics here. Host text is not a resolved-IP alias.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialRecord {
    /// Catalog name within its owning configuration.
    pub name: String,
    /// Owner-qualified material reference; no secret bytes.
    pub material: String,
    /// Preserve custody from the original compiled record.
    pub binding: CredentialBinding,
    /// Immutable credential material version.
    pub key_version: Identity,
    /// Immutable independent upstream trust version.
    pub trust_version: Identity,
    /// Exact authorized original hostname or explicit IP literal.
    pub host: String,
    /// Exact upstream port.
    pub port: u16,
    /// Exact requested and upstream username, with no remapping.
    pub user: String,
    /// Existing compiled violation policy, retained without reinterpretation.
    pub on_violation: String,
}

/// Parsed key and independent host pin attached to one complete record.
/// Neither this type nor the policy store is serializable.
#[derive(Debug)]
pub struct ReadyCredential {
    record: CredentialRecord,
    key: Arc<BrokerKey>,
    pin: UpstreamPin,
}

/// Complete material-ready policy for one launch revision.
#[derive(Debug)]
pub struct LaunchPolicy {
    /// Exact verified target.
    launch: Launch,
    /// Positive desired revision supplied by the controller.
    revision: u64,
    /// Effective compiled policy, material and trust identity.
    digest: Identity,
    credentials: Vec<Arc<ReadyCredential>>,
    /// Scanner custody belongs to this exact effective transaction.
    library: Arc<PatternLibrary>,
    /// Admission accounting includes current and pending authored bytes.
    pattern_bytes: usize,
    /// Terminal for this launch generation, unlike an empty revocation.
    destroyed: bool,
}

/// A change is applied only when affected relay owners have finished cleanup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyStatus {
    /// No old relay remains and the complete new state is installed.
    Applied,
    /// Admission is closed; cancellation is requested but not yet completed.
    Pending,
}

/// Bounded, redacted admission/transition failures.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum PolicyError {
    /// No current authenticated session matches the supplied fence.
    #[error("management connection is not current")]
    StaleManagement,
    /// A retired relay still owns resources.
    #[error("relay retirement is incomplete")]
    RetirementIncomplete,
    /// A launch or policy revision is missing, superseded or pending.
    #[error("launch policy is not current")]
    StalePolicy,
    /// Malformed, unsupported or internally inconsistent policy.
    #[error("invalid or unsupported custody policy")]
    InvalidPolicy,
    /// Multiple complete records match the same principal/destination.
    #[error("ambiguous custody credential")]
    AmbiguousCredential,
    /// No complete record authorizes the request.
    #[error("custody request is not authorized")]
    Unauthorized,
    /// An identifier or configured finite store budget is exhausted.
    #[error("custody store capacity exhausted")]
    Capacity,
}

struct Slot {
    current: Arc<LaunchPolicy>,
    pending: Option<Arc<LaunchPolicy>>,
}

struct ActiveRelay {
    launch: Launch,
    termination: TerminationHandle,
}

/// Host-verified diversion identity; no field is taken from guest SSH input.
#[derive(Debug, Clone)]
pub struct RelayContext {
    /// Store-issued current authenticated connection.
    pub fence: ManagementFence,
    /// Host-correlated original native launch.
    pub launch: Launch,
    /// Exact current desired revision.
    pub revision: u64,
    /// Effective policy and material identity.
    pub digest: Identity,
    /// Authorized original destination text, never a DNS result substitution.
    pub host: String,
    /// Exact destination port.
    pub port: u16,
}

/// Transport ownership acquired before the guest SSH handshake. It contains no
/// selected key: the signed SSH username selects a whole record later, under
/// the same store lock and current-policy fence. Drop never acknowledges join.
pub(crate) struct TransportAdmission {
    owner: Arc<()>,
    id: u64,
    context: RelayContext,
    termination: TerminationHandle,
    library: Arc<PatternLibrary>,
}

/// Owned admission for one relay, deliberately not cloneable.
///
/// Dropping this value does NOT acknowledge termination. The task owner must
/// retain it across handshake, both SSH legs and child-task cleanup, then call
/// `PolicyStore::complete_relay` after joining that work. Losing the value leaves
/// retirement pending, rather than reporting an unobserved successful revoke.
pub struct RelayAdmission {
    owner: Arc<()>,
    id: u64,
    credential: Arc<ReadyCredential>,
    termination: TerminationHandle,
}

/// Bounded applied state owned by one managed Broker.
pub struct PolicyStore {
    owner: Arc<()>,
    broker: Identity,
    connection: u64,
    session: Option<ManagementFence>,
    slots: BTreeMap<String, Slot>,
    retired: BTreeSet<Launch>,
    relays: BTreeMap<u64, ActiveRelay>,
    next_relay: u64,
    max_launches: usize,
    max_relays: usize,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ReadyCredential {
    pub(crate) fn material(&self) -> (&BrokerKey, &UpstreamPin) {
        (&self.key, &self.pin)
    }

    /// Validate an exact record and move its already parsed material into custody.
    pub fn new(
        record: CredentialRecord,
        key: Arc<BrokerKey>,
        pin: UpstreamPin,
    ) -> Result<Arc<Self>, PolicyError> {
        if !valid_text(&record.name)
            || !valid_text(&record.material)
            || !valid_text(&record.host)
            || !valid_text(&record.user)
            || record
                .host
                .bytes()
                .any(|b| matches!(b, b'*' | b'?' | b'[' | b']'))
            || record.port == 0
            || record.binding != CredentialBinding::Broker
            || record.user != pin.user
            || record.key_version == [0; 32]
            || record.trust_version == [0; 32]
            || pin
                .expected
                .to_bytes()
                .map_or(true, |bytes| bytes.len() > 16 * 1024)
            || !matches!(
                record.on_violation.as_str(),
                "passthrough" | "block" | "block-and-log" | "block-and-terminate"
            )
        {
            return Err(PolicyError::InvalidPolicy);
        }
        Ok(Arc::new(Self { record, key, pin }))
    }

    fn same(&self, other: &Self) -> bool {
        self.record == other.record
            && self.pin.expected == other.pin.expected
            && self.key.private_key().public_key() == other.key.private_key().public_key()
    }
}

impl LaunchPolicy {
    /// Parse a complete wire policy before installation, verifying the digest
    /// over actual material, trust and pattern bytes. Unsupported scanner input
    /// is refused rather than silently excluded from a managed transaction.
    pub fn from_wire(
        launch: Launch,
        revision: u64,
        digest: Identity,
        policy: wire::Policy,
    ) -> Result<Arc<Self>, PolicyError> {
        if wire::policy_digest(&policy)
            .map_err(|_| PolicyError::InvalidPolicy)?
            .bytes()
            != digest
        {
            return Err(PolicyError::InvalidPolicy);
        }
        let wire::Policy {
            destroyed,
            credentials,
            patterns,
        } = policy;
        let pattern_bytes = patterns.iter().map(|p| p.bytes.as_slice().len()).sum();
        let credentials = credentials
            .into_iter()
            .map(|entry| {
                let wire::ReadyRecord {
                    name,
                    material,
                    binding: _,
                    key_version,
                    trust_version,
                    host,
                    port,
                    user,
                    on_violation,
                    key_kind: _,
                    key_bytes,
                    upstream_public_key,
                } = entry;
                let mut seed = key_bytes.into_zeroizing();
                let key = Arc::new(
                    BrokerKey::from_bootstrap(BrokerSshKey {
                        key_type: "ed25519".into(),
                        key_bytes: std::mem::take(&mut *seed),
                    })
                    .map_err(|_| PolicyError::InvalidPolicy)?,
                );
                let pin = parse_upstream_pin(&BrokerUpstreamHost {
                    host: host.clone(),
                    port,
                    user: user.clone(),
                    public_key: upstream_public_key,
                })
                .map_err(|_| PolicyError::InvalidPolicy)?;
                let action = match on_violation {
                    wire::Violation::Passthrough => "passthrough",
                    wire::Violation::Block => "block",
                    wire::Violation::BlockAndLog => "block-and-log",
                    wire::Violation::BlockAndTerminate => "block-and-terminate",
                };
                ReadyCredential::new(
                    CredentialRecord {
                        name,
                        material,
                        binding: CredentialBinding::Broker,
                        key_version: key_version.bytes(),
                        trust_version: trust_version.bytes(),
                        host,
                        port,
                        user,
                        on_violation: action.into(),
                    },
                    key,
                    pin,
                )
            })
            .collect::<Result<Vec<_>, PolicyError>>()?;
        let compiled = patterns
            .into_iter()
            .map(|pattern| {
                let wire::Pattern {
                    credential_id,
                    decoder,
                    bytes,
                    action,
                } = pattern;
                let mut bytes = bytes.into_zeroizing();
                ScanPattern::compile(
                    credential_id,
                    decoder,
                    std::mem::take(&mut *bytes),
                    ActionSet {
                        enforce: action.enforce,
                        audit: action.audit,
                        count: action.count,
                    },
                )
            })
            .collect();
        let (library, excluded) = PatternLibrary::new(compiled);
        if !excluded.is_empty() {
            return Err(PolicyError::InvalidPolicy);
        }
        let mut result = Self::new(launch, revision, digest, credentials)?;
        let result_mut = Arc::get_mut(&mut result).expect("new policy has one owner");
        result_mut.library = library;
        result_mut.pattern_bytes = pattern_bytes;
        result_mut.destroyed = destroyed;
        Ok(result)
    }

    /// Validate a bounded atomic policy, including an empty revocation policy.
    pub fn new(
        launch: Launch,
        revision: u64,
        digest: Identity,
        credentials: Vec<Arc<ReadyCredential>>,
    ) -> Result<Arc<Self>, PolicyError> {
        if !valid_text(&launch.instance)
            || launch.generation == [0; 32]
            || revision == 0
            || digest == [0; 32]
            || credentials.len() > 256
        {
            return Err(PolicyError::InvalidPolicy);
        }
        for (index, record) in credentials.iter().enumerate() {
            if credentials[..index].iter().any(|other| {
                other.record.host == record.record.host
                    && other.record.port == record.record.port
                    && other.record.user == record.record.user
            }) {
                return Err(PolicyError::AmbiguousCredential);
            }
        }
        Ok(Arc::new(Self {
            launch,
            revision,
            digest,
            credentials,
            library: PatternLibrary::empty(),
            pattern_bytes: 0,
            destroyed: false,
        }))
    }

    fn same(&self, other: &Self) -> bool {
        self.launch == other.launch
            && self.revision == other.revision
            && self.digest == other.digest
            && self.destroyed == other.destroyed
            && self.credentials.len() == other.credentials.len()
            && self
                .credentials
                .iter()
                .zip(&other.credentials)
                .all(|(a, b)| a.same(b))
    }
}

impl RelayAdmission {
    /// The complete selected record; never a union of fields from other records.
    pub fn record(&self) -> &CredentialRecord {
        &self.credential.record
    }

    /// Existing SSH teardown signal for this exact owned relay.
    pub fn termination(&self) -> TerminationHandle {
        self.termination.clone()
    }

    /// Parsed material for the owning SSH task. This is an internal trusted
    /// Rust seam, not a delegated signing API. The owner must honor termination
    /// throughout upstream setup and retain this admission until teardown joins.
    pub fn material(&self) -> (&BrokerKey, &UpstreamPin) {
        (&self.credential.key, &self.credential.pin)
    }
}

impl TransportAdmission {
    pub(crate) fn termination(&self) -> TerminationHandle {
        self.termination.clone()
    }

    pub(crate) fn library(&self) -> Arc<PatternLibrary> {
        Arc::clone(&self.library)
    }
}

impl PolicyStore {
    /// Resolve a host-authenticated diversion's exact current fence. Neither a
    /// caller-supplied transaction nor a resolved hostname creates authority.
    pub fn fence_for(&self, session: wire::BrokerSession) -> Result<ManagementFence, PolicyError> {
        self.session
            .filter(|fence| fence.session() == session)
            .ok_or(PolicyError::StaleManagement)
    }

    pub(crate) fn relays_retired(&self) -> bool {
        self.relays.is_empty()
    }

    /// A newer connection can have been issued only after all prior relays
    /// retired. Never confuse that new connection's work with old cleanup.
    /// The argument is the sealed store-issued Rust fence, not wire input.
    pub(crate) fn connection_retired(&self, fence: ManagementFence) -> Result<bool, PolicyError> {
        if fence.broker != self.broker
            || fence.connection == 0
            || fence.connection > self.connection
            || self.session == Some(fence)
        {
            return Err(PolicyError::StaleManagement);
        }
        Ok(self.connection > fence.connection || self.relays.is_empty())
    }

    /// Reserve bounded ownership even for an unauthenticated guest handshake.
    /// This is not permission to dial or use a key. State loss and replacement
    /// cancel this lease just like an authenticated session.
    pub(crate) fn reserve_transport(
        &mut self,
        context: RelayContext,
    ) -> Result<TransportAdmission, PolicyError> {
        let policy = self.current_policy(&context)?;
        if !policy.credentials.iter().any(|credential| {
            credential.record.host == context.host && credential.record.port == context.port
        }) {
            return Err(PolicyError::Unauthorized);
        }
        let library = Arc::clone(&policy.library);
        if self.relays.len() >= self.max_relays {
            return Err(PolicyError::Capacity);
        }
        let id = self
            .next_relay
            .checked_add(1)
            .ok_or(PolicyError::Capacity)?;
        self.next_relay = id;
        let termination = TerminationHandle::new();
        self.relays.insert(
            id,
            ActiveRelay {
                launch: context.launch.clone(),
                termination: termination.clone(),
            },
        );
        Ok(TransportAdmission {
            owner: Arc::clone(&self.owner),
            id,
            context,
            termination,
            library,
        })
    }

    /// Recheck immediately at unsigned offer and signed authentication. The
    /// caller may use returned material only after the latter proof succeeds.
    pub(crate) fn select_transport(
        &self,
        admission: &TransportAdmission,
        user: &str,
    ) -> Result<Arc<ReadyCredential>, PolicyError> {
        if !Arc::ptr_eq(&self.owner, &admission.owner)
            || !self.relays.contains_key(&admission.id)
            || admission.termination.is_terminated()
        {
            return Err(PolicyError::StalePolicy);
        }
        self.current_policy(&admission.context)?
            .credentials
            .iter()
            .find(|credential| {
                credential.record.host == admission.context.host
                    && credential.record.port == admission.context.port
                    && credential.record.user == user
            })
            .cloned()
            .ok_or(PolicyError::Unauthorized)
    }

    pub(crate) fn complete_transport(
        &mut self,
        admission: TransportAdmission,
    ) -> Result<(), PolicyError> {
        if !Arc::ptr_eq(&self.owner, &admission.owner) {
            return Err(PolicyError::StaleManagement);
        }
        self.relays.remove(&admission.id);
        Ok(())
    }

    fn current_policy(&self, context: &RelayContext) -> Result<&LaunchPolicy, PolicyError> {
        self.check(context.fence)?;
        let slot = self
            .slots
            .get(&context.launch.instance)
            .ok_or(PolicyError::StalePolicy)?;
        if slot.pending.is_some()
            || slot.current.launch != context.launch
            || slot.current.revision != context.revision
            || slot.current.digest != context.digest
        {
            return Err(PolicyError::StalePolicy);
        }
        Ok(&slot.current)
    }

    /// Start closed; no state or key is recovered by guessing existing workloads.
    pub fn new(
        broker: Identity,
        max_launches: usize,
        max_relays: usize,
    ) -> Result<Self, PolicyError> {
        if broker == [0; 32]
            || max_launches == 0
            || max_launches > 4096
            || max_relays == 0
            || max_relays > 4096
        {
            return Err(PolicyError::InvalidPolicy);
        }
        Ok(Self {
            owner: Arc::new(()),
            broker,
            connection: 0,
            session: None,
            slots: BTreeMap::new(),
            retired: BTreeSet::new(),
            relays: BTreeMap::new(),
            next_relay: 0,
            max_launches,
            max_relays,
        })
    }

    /// Called only after the transport authenticates a new controller connection.
    /// The old connection must first be fenced and its relays fully retired.
    pub fn connect(&mut self, controller: Identity) -> Result<ManagementFence, PolicyError> {
        if controller == [0; 32] {
            return Err(PolicyError::InvalidPolicy);
        }
        if self.session.is_some() {
            return Err(PolicyError::StaleManagement);
        }
        if !self.relays.is_empty() {
            return Err(PolicyError::RetirementIncomplete);
        }
        self.connection = self
            .connection
            .checked_add(1)
            .ok_or(PolicyError::Capacity)?;
        let fence = ManagementFence {
            broker: self.broker,
            controller,
            connection: self.connection,
        };
        self.session = Some(fence);
        Ok(fence)
    }

    /// Validate the entire replacement before retiring current authorization.
    /// `expected` is absent only for the first install on this connection.
    pub fn install(
        &mut self,
        fence: ManagementFence,
        expected: Option<u64>,
        policy: Arc<LaunchPolicy>,
    ) -> Result<ApplyStatus, PolicyError> {
        self.check(fence)?;
        if self.retired.contains(&policy.launch) {
            return Err(PolicyError::StalePolicy);
        }
        if let Some(slot) = self.slots.get(&policy.launch.instance) {
            let latest = slot.pending.as_ref().unwrap_or(&slot.current);
            if latest.same(&policy) {
                return Ok(if slot.pending.is_some() {
                    ApplyStatus::Pending
                } else {
                    ApplyStatus::Applied
                });
            }
            if !self.room_for(&policy) {
                return Err(PolicyError::Capacity);
            }
            if slot.pending.is_some() || expected != Some(slot.current.revision) {
                return Err(PolicyError::StalePolicy);
            }
            if slot.current.destroyed && policy.launch == slot.current.launch {
                return Err(PolicyError::StalePolicy);
            }
            if policy.launch != slot.current.launch {
                // A new boot can replace only a completely revoked old boot.
                if !slot.current.credentials.is_empty()
                    || self
                        .relays
                        .values()
                        .any(|relay| relay.launch == slot.current.launch)
                {
                    return Err(PolicyError::RetirementIncomplete);
                }
                if self.retired.len() >= 4096 {
                    return Err(PolicyError::Capacity);
                }
                self.retired.insert(slot.current.launch.clone());
                self.slots.insert(
                    policy.launch.instance.clone(),
                    Slot {
                        current: policy,
                        pending: None,
                    },
                );
                return Ok(ApplyStatus::Applied);
            }
            if policy.revision <= slot.current.revision {
                return Err(PolicyError::StalePolicy);
            }
            self.cancel_launch(&policy.launch);
            self.slots.get_mut(&policy.launch.instance).unwrap().pending =
                Some(Arc::clone(&policy));
            self.finish(fence, &policy.launch, policy.revision, policy.digest)
        } else {
            if expected.is_some() {
                return Err(PolicyError::StalePolicy);
            }
            if self.slots.len() >= self.max_launches || !self.room_for(&policy) {
                return Err(PolicyError::Capacity);
            }
            self.slots.insert(
                policy.launch.instance.clone(),
                Slot {
                    current: policy,
                    pending: None,
                },
            );
            Ok(ApplyStatus::Applied)
        }
    }

    /// Publish a pending transition only after every affected relay has completed.
    pub fn finish(
        &mut self,
        fence: ManagementFence,
        launch: &Launch,
        revision: u64,
        digest: Identity,
    ) -> Result<ApplyStatus, PolicyError> {
        self.check(fence)?;
        let slot = self
            .slots
            .get_mut(&launch.instance)
            .ok_or(PolicyError::StalePolicy)?;
        let target = slot.pending.as_ref().unwrap_or(&slot.current);
        if &target.launch != launch || target.revision != revision || target.digest != digest {
            return Err(PolicyError::StalePolicy);
        }
        if slot.pending.is_none() {
            return Ok(ApplyStatus::Applied);
        }
        if self.relays.values().any(|relay| &relay.launch == launch) {
            return Ok(ApplyStatus::Pending);
        }
        if let Some(next) = slot.pending.take() {
            slot.current = next;
        }
        Ok(ApplyStatus::Applied)
    }

    /// Select one complete record before any upstream dial or credential use.
    /// Username comes from SSH authentication, not the host diversion prelude.
    pub fn admit(
        &mut self,
        fence: ManagementFence,
        launch: &Launch,
        revision: u64,
        digest: Identity,
        host: &str,
        port: u16,
        user: &str,
    ) -> Result<RelayAdmission, PolicyError> {
        self.check(fence)?;
        let slot = self
            .slots
            .get(&launch.instance)
            .ok_or(PolicyError::StalePolicy)?;
        if slot.pending.is_some()
            || &slot.current.launch != launch
            || slot.current.revision != revision
            || slot.current.digest != digest
        {
            return Err(PolicyError::StalePolicy);
        }
        let credential = slot
            .current
            .credentials
            .iter()
            .find(|entry| {
                entry.record.host == host && entry.record.port == port && entry.record.user == user
            })
            .cloned()
            .ok_or(PolicyError::Unauthorized)?;
        if self.relays.len() >= self.max_relays {
            return Err(PolicyError::Capacity);
        }
        let id = self
            .next_relay
            .checked_add(1)
            .ok_or(PolicyError::Capacity)?;
        self.next_relay = id;
        let termination = TerminationHandle::new();
        self.relays.insert(
            id,
            ActiveRelay {
                launch: launch.clone(),
                termination: termination.clone(),
            },
        );
        Ok(RelayAdmission {
            owner: Arc::clone(&self.owner),
            id,
            credential,
            termination,
        })
    }

    /// Record joined relay cleanup. No management ACK or cancellation flag calls
    /// this automatically; the broker task owner holds the non-cloneable admission.
    pub fn complete_relay(&mut self, admission: RelayAdmission) -> Result<(), PolicyError> {
        if !Arc::ptr_eq(&self.owner, &admission.owner) {
            return Err(PolicyError::StaleManagement);
        }
        self.relays.remove(&admission.id);
        Ok(())
    }

    /// State loss and controller EOF share the same fail-closed transition.
    /// Invalid old notifications cannot poison a current authenticated session.
    pub fn state_lost(&mut self, fence: ManagementFence) -> Result<ApplyStatus, PolicyError> {
        self.check(fence)?;
        self.session = None;
        self.slots.clear();
        self.retired.clear();
        for relay in self.relays.values() {
            relay.termination.terminate();
        }
        Ok(if self.relays.is_empty() {
            ApplyStatus::Applied
        } else {
            ApplyStatus::Pending
        })
    }

    fn check(&self, fence: ManagementFence) -> Result<(), PolicyError> {
        if self.session == Some(fence) {
            Ok(())
        } else {
            Err(PolicyError::StaleManagement)
        }
    }

    fn room_for(&self, policy: &LaunchPolicy) -> bool {
        let held: usize = self
            .slots
            .values()
            .map(|slot| {
                slot.current.credentials.len()
                    + slot
                        .pending
                        .as_ref()
                        .map_or(0, |pending| pending.credentials.len())
            })
            .sum();
        let held_patterns = self.slots.values().try_fold(0usize, |sum, slot| {
            sum.checked_add(slot.current.pattern_bytes)?.checked_add(
                slot.pending
                    .as_ref()
                    .map_or(0, |pending| pending.pattern_bytes),
            )
        });
        let pattern_count: usize = self
            .slots
            .values()
            .map(|slot| {
                slot.current.library.len()
                    + slot
                        .pending
                        .as_ref()
                        .map_or(0, |pending| pending.library.len())
            })
            .sum();
        held + policy.credentials.len() <= 4096
            && pattern_count + policy.library.len() <= MAX_HELD_PATTERNS
            && held_patterns
                .and_then(|held| held.checked_add(policy.pattern_bytes))
                .is_some_and(|bytes| bytes <= MAX_HELD_PATTERN_BYTES)
    }

    fn cancel_launch(&self, launch: &Launch) {
        for relay in self.relays.values().filter(|relay| &relay.launch == launch) {
            relay.termination.terminate();
        }
    }
}

impl Drop for PolicyStore {
    fn drop(&mut self) {
        for relay in self.relays.values() {
            relay.termination.terminate();
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn valid_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && value
            .bytes()
            .all(|byte| !byte.is_ascii_whitespace() && !byte.is_ascii_control())
}

#[cfg(test)]
#[path = "policy_tests.rs"]
mod tests;
