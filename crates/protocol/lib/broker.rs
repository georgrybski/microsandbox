//! Direct broker-service protocol, separate from the agent console protocol.
//!
//! These frames travel only on an authenticated protected host transport. IDs
//! and headers are attribution, not bearer credentials. This module does not
//! authenticate a socket, resolve material, persist policy or execute commands.

use std::fmt;
use std::io::{Cursor, Write};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

/// Independent service protocol; never stamped onto agent-console messages.
pub const VERSION: u16 = 1;

/// Current-fence liveness lease. Expiry fences custody and retires relays.
pub const MANAGEMENT_LEASE_SECS: u64 = 30;
/// Controller cadence leaves room for transient scheduling/transport latency.
pub const MANAGEMENT_PROBE_SECS: u64 = 10;
/// Maximum encoded management payload, before its four-byte length prefix.
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
/// Maximum managed diversion header; SSH bytes follow this one frame.
pub const MAX_DIVERT_BYTES: usize = 8 * 1024;
/// Maximum number of complete credential records in one atomic policy.
pub const MAX_RECORDS: usize = 256;
/// Maximum number of scanner patterns in one atomic policy.
pub const MAX_PATTERNS: usize = 256;
/// Maximum total authored scanner bytes per policy.
pub const MAX_PATTERN_BYTES: usize = 512 * 1024;

/// Canonical nonzero 256-bit identity, encoded as lowercase hexadecimal.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Id([u8; 32]);

impl Id {
    /// Construct from an already authoritative identity, not an allocator.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, Error> {
        if bytes == [0; 32] {
            Err(Error::Invalid)
        } else {
            Ok(Self(bytes))
        }
    }
    /// Exact opaque bytes for an in-process fence.
    pub fn bytes(self) -> [u8; 32] {
        self.0
    }
    /// Canonical public representation.
    pub fn to_hex(self) -> String {
        const HEX: &[u8] = b"0123456789abcdef";
        self.0
            .iter()
            .flat_map(|b| {
                [
                    HEX[(b >> 4) as usize] as char,
                    HEX[(b & 15) as usize] as char,
                ]
            })
            .collect()
    }
}

impl fmt::Debug for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}
impl Serialize for Id {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}
impl<'de> Deserialize<'de> for Id {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        if encoded.len() != 64 {
            return Err(serde::de::Error::custom("invalid opaque identity"));
        }
        let mut bytes = [0; 32];
        for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
            let digit = |b| match b {
                b'0'..=b'9' => Some(b - b'0'),
                b'a'..=b'f' => Some(b - b'a' + 10),
                _ => None,
            };
            let (Some(high), Some(low)) = (digit(pair[0]), digit(pair[1])) else {
                return Err(serde::de::Error::custom("invalid opaque identity"));
            };
            bytes[index] = high * 16 + low;
        }
        Self::from_bytes(bytes).map_err(|_| serde::de::Error::custom("invalid opaque identity"))
    }
}

/// Move-only wire bytes, wiped on failure or after custody consumes them.
pub struct SecretBytes(Zeroizing<Vec<u8>>);
impl SecretBytes {
    /// Move resolved synthetic or real material into transport custody.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }
    /// Borrow only inside the trusted material parser/compiler.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
    /// Move directly into another zeroizing owner without cloning.
    pub fn into_zeroizing(mut self) -> Zeroizing<Vec<u8>> {
        std::mem::take(&mut self.0)
    }
}
impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}
impl Serialize for SecretBytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serde_bytes::serialize(self.as_slice(), serializer)
    }
}
impl<'de> Deserialize<'de> for SecretBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Bytes;
        impl<'de> serde::de::Visitor<'de> for Bytes {
            type Value = SecretBytes;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a bounded definite CBOR byte string")
            }
            fn visit_bytes<E: serde::de::Error>(self, value: &[u8]) -> Result<SecretBytes, E> {
                if value.len() > 64 * 1024 {
                    return Err(E::custom("oversized secret field"));
                }
                Ok(SecretBytes::new(value.to_vec()))
            }
        }
        // Ciborium's bytes path reads definite bytes directly into our supplied
        // zeroizing scratch. Its byte_buf path first builds an ordinary Vec,
        // which can escape wiping on truncated input. Arrays and indefinite
        // byte strings are intentionally unsupported alternate representations.
        deserializer.deserialize_bytes(Bytes)
    }
}

/// Existing configured workload identity, not a runtime transport name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadRef {
    /// Optional named configuration context.
    pub context: Option<String>,
    /// Configured workload name.
    pub name: String,
}
/// Instance identity inside its configured workload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceRef {
    /// Owning configured workload.
    pub workload: WorkloadRef,
    /// Existing instance name.
    pub instance: String,
}
/// One authoritative native launch; replacement changes generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchRef {
    /// Existing configured identity.
    pub instance: InstanceRef,
    /// Native launch generation verified by the host adapter.
    pub generation: Id,
}
/// Broker-issued fence for an authenticated management connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerSession {
    /// Authenticated controller process incarnation.
    pub controller: Id,
    /// Broker process incarnation.
    pub broker: Id,
    /// Positive broker-issued connection sequence.
    pub connection: u64,
}
/// Exact target of an applied-state operation or observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionRef {
    /// Current authenticated management fence.
    pub session: BrokerSession,
    /// Exact native launch.
    pub launch: LaunchRef,
    /// Positive desired revision.
    pub revision: u64,
    /// SHA-256 of the complete effective policy using [`policy_digest`].
    pub policy_digest: Id,
}

/// Explicit supported key encoding; no algorithm fallback or guessing.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyKind {
    /// Exactly 32 Ed25519 seed bytes, not PEM or an agent handle.
    Ed25519Seed,
}
/// Existing custody distinction. Guest-held keys are not accepted by this path.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Binding {
    /// Material remains inside broker custody.
    Broker,
    /// Unsupported on the managed terminating path; rejected before effects.
    Guest,
}
/// Existing violation actions, without a permissive unknown-value default.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Violation {
    /// Forward and apply the explicitly compiled audit/count policy.
    Passthrough,
    /// Close the affected channel.
    Block,
    /// Close and audit the affected channel.
    BlockAndLog,
    /// Terminate this relay session.
    BlockAndTerminate,
}

/// One complete compiled record, retaining all relationships to its material.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadyRecord {
    /// Credential catalog name.
    pub name: String,
    /// Owner-qualified material reference.
    pub material: String,
    /// Original custody binding.
    pub binding: Binding,
    /// Immutable material version.
    pub key_version: Id,
    /// Immutable independent upstream trust version.
    pub trust_version: Id,
    /// Original exact authorized hostname or explicit IP, not a DNS result alias.
    pub host: String,
    /// Exact upstream port.
    pub port: u16,
    /// Exact guest-requested and upstream username.
    pub user: String,
    /// Existing compiled violation policy.
    pub on_violation: Violation,
    /// Explicit key encoding.
    pub key_kind: KeyKind,
    /// Move-only material; never included in observations or logs.
    pub key_bytes: SecretBytes,
    /// Independent upstream host key as one authorized_keys line.
    pub upstream_public_key: String,
}

/// One scanner pattern whose bytes never belong in ordinary workload bootstrap.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pattern {
    /// Catalog identity retained for scanner audit attribution.
    pub credential_id: String,
    /// Exact authored encoding.
    pub decoder: microsandbox_scan::Decoder,
    /// Move-only authored bytes, compiled inside broker custody.
    pub bytes: SecretBytes,
    /// Explicit scanner actions; no default for omitted actions.
    pub action: PatternAction,
}
/// Strict scanner action shape; unknown fields cannot silently weaken policy.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatternAction {
    /// Existing scanner severity, absent only for explicitly non-enforcing rules.
    pub enforce: Option<microsandbox_scan::Severity>,
    /// Whether to emit existing redacted audit records.
    pub audit: bool,
    /// Whether to increment existing hit counters.
    pub count: bool,
}
/// Atomic material-ready policy. Collection order is meaningful and hashed.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Terminal destruction; it requires empty credential and pattern lists.
    pub destroyed: bool,
    /// Whole exact-destination records, never fieldwise unions.
    pub credentials: Vec<ReadyRecord>,
    /// Resolved scanner inputs owned only by this broker policy.
    pub patterns: Vec<Pattern>,
}

/// Versioned authenticated connection introduction.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    /// Supported direct-service version.
    pub version: u16,
    /// Authenticated controller incarnation, independently checked by transport.
    pub controller: Id,
}
/// Atomic replacement request; receiver parses everything before mutation.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Apply {
    /// Exact fence and desired target.
    pub transaction: TransactionRef,
    /// None only for the first policy on this authenticated connection.
    pub expected_revision: Option<u64>,
    /// Complete key, trust and scanner state.
    pub policy: Policy,
}
/// Closed operation set on the separate broker transport.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Request {
    /// Must be first; does not itself authenticate the socket.
    Hello(Hello),
    /// Renew only this authenticated management fence; not a policy ACK.
    Probe(BrokerSession),
    /// Atomically apply a complete policy after all validation succeeds.
    Apply(Apply),
    /// Poll actual retirement completion for an already accepted transaction.
    Finish(TransactionRef),
}
/// Readiness is distinct from acceptance or cancellation delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Admission closed; native resource owners are still retiring.
    Pending,
    /// Entire transaction and required retirement completed.
    Applied,
    /// Request refused without installing its proposed policy.
    Rejected,
    /// Entire authenticated management session was invalidated.
    StateLost,
}
/// Static safe diagnostics, never raw parser/credential/SSH errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    /// Complete material/policy was malformed or unsupported.
    InvalidPolicy,
    /// Required material was unavailable.
    MissingCredential,
    /// Independent upstream/server trust failed validation.
    InvalidHostTrust,
    /// Exact launch or revision was not current.
    StaleLaunch,
    /// A native relay task has not been observed joined.
    RetirementIncomplete,
    /// Transport or service is unavailable.
    Unavailable,
}
/// Nonsecret observation compatible with the controller's existing state model.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    /// Exact accepted transaction being reported.
    pub transaction: TransactionRef,
    /// Applied-state outcome, not a receipt-of-bytes acknowledgment.
    pub outcome: Outcome,
    /// Static diagnostic when needed.
    pub failure: Option<Failure>,
}
/// Successful introduction with a broker-issued session fence.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Welcome {
    /// Negotiated service version; currently exactly one is supported.
    pub version: u16,
    /// Authenticated connection identity to adopt, never locally forge.
    pub session: BrokerSession,
}

/// Fenced liveness response, deliberately without any policy readiness field.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Probe {
    /// Exact session that was probed.
    pub session: BrokerSession,
    /// True only for the currently authenticated session; never means Applied.
    pub current: bool,
}
/// Secret-free direct management responses.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reply {
    /// A new authenticated management connection is established.
    Hello(Welcome),
    /// Management liveness only; a stale probe cannot renew the current lease.
    Probe(Probe),
    /// State of one exact transaction.
    Observation(Observation),
}
/// Protected host diversion metadata, followed by unmodified guest SSH bytes.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedDivert {
    /// Exact service protocol version, never a legacy prelude fallback.
    pub version: u16,
    /// Host-verified launch and current applied policy.
    pub transaction: TransactionRef,
    /// Authorized original host text, not a rewritten DNS address.
    pub destination_host: String,
    /// Authorized original destination port.
    pub destination_port: u16,
}

/// Redacted framing/validation failures; parser details may contain material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Transport ended or failed while reading/writing a complete frame.
    #[error("broker transport unavailable")]
    Transport,
    /// Frame or field exceeds a fixed protocol bound.
    #[error("broker frame exceeds limit")]
    Limit,
    /// Unsupported, malformed, trailing or inconsistent input.
    #[error("invalid broker frame")]
    Invalid,
}

fn name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && !value
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
}
fn transaction(value: &TransactionRef) -> Result<(), Error> {
    let instance = &value.launch.instance;
    if value.revision == 0
        || value.session.connection == 0
        || !name(&instance.instance)
        || !name(&instance.workload.name)
        || instance.workload.context.as_ref().is_some_and(|v| !name(v))
    {
        return Err(Error::Invalid);
    }
    Ok(())
}
impl Policy {
    /// Validate finite exact-only support before parsing keys or changing state.
    pub fn validate(&self) -> Result<(), Error> {
        if self.credentials.len() > MAX_RECORDS || self.patterns.len() > MAX_PATTERNS {
            return Err(Error::Limit);
        }
        if self.destroyed && (!self.credentials.is_empty() || !self.patterns.is_empty()) {
            return Err(Error::Invalid);
        }
        for (index, record) in self.credentials.iter().enumerate() {
            if !name(&record.name)
                || !name(&record.material)
                || !name(&record.host)
                || !name(&record.user)
                || record
                    .host
                    .bytes()
                    .any(|b| matches!(b, b'*' | b'?' | b'[' | b']'))
                || record.port == 0
                || !matches!(record.binding, Binding::Broker)
                || record.key_bytes.as_slice().len() != 32
                || record.upstream_public_key.is_empty()
                || record.upstream_public_key.len() > 16 * 1024
                || record
                    .upstream_public_key
                    .bytes()
                    .any(|b| matches!(b, 0 | b'\r' | b'\n'))
                || self.credentials[..index].iter().any(|other| {
                    other.host == record.host
                        && other.port == record.port
                        && other.user == record.user
                })
            {
                return Err(Error::Invalid);
            }
        }
        let mut total = 0usize;
        for pattern in &self.patterns {
            total = total
                .checked_add(pattern.bytes.as_slice().len())
                .ok_or(Error::Limit)?;
            if !name(&pattern.credential_id)
                || pattern.bytes.as_slice().len() > 64 * 1024
                || total > MAX_PATTERN_BYTES
            {
                return Err(Error::Limit);
            }
        }
        Ok(())
    }
}
impl Request {
    /// Validate complete schema semantics and effective-policy digest.
    pub fn validate(&self) -> Result<(), Error> {
        match self {
            Self::Hello(hello) if hello.version == VERSION => Ok(()),
            Self::Hello(_) => Err(Error::Invalid),
            Self::Probe(session) => {
                if session.connection == 0 {
                    Err(Error::Invalid)
                } else {
                    Ok(())
                }
            }
            Self::Finish(target) => transaction(target),
            Self::Apply(apply) => {
                transaction(&apply.transaction)?;
                if apply.expected_revision == Some(0) {
                    return Err(Error::Invalid);
                }
                if policy_digest(&apply.policy)? != apply.transaction.policy_digest {
                    return Err(Error::Invalid);
                }
                Ok(())
            }
        }
    }
}

struct Limited<'a> {
    bytes: &'a mut Vec<u8>,
    limit: usize,
}
impl Write for Limited<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other("broker frame limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn payload<T: Serialize>(value: &T, limit: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut bytes = Zeroizing::new(Vec::new());
    ciborium::ser::into_writer(
        value,
        Limited {
            bytes: &mut bytes,
            limit,
        },
    )
    .map_err(|_| Error::Limit)?;
    Ok(bytes)
}

/// SHA-256 over domain separation plus deterministic typed CBOR field order.
/// Hashes actual seed, independent trust and scanner content as well as all
/// metadata; collection order is retained. Reordering is a distinct policy.
pub fn policy_digest(policy: &Policy) -> Result<Id, Error> {
    policy.validate()?;
    let encoded = payload(policy, MAX_FRAME_BYTES)?;
    let mut hash = Sha256::new();
    hash.update(b"microsandbox.broker.policy.v1\0");
    hash.update(&*encoded);
    Id::from_bytes(hash.finalize().into())
}

async fn read<T: serde::de::DeserializeOwned, R: AsyncRead + Unpin>(
    reader: &mut R,
    limit: usize,
) -> Result<T, Error> {
    let length = reader.read_u32().await.map_err(|_| Error::Transport)? as usize;
    if length == 0 || length > limit {
        return Err(Error::Limit);
    }
    let mut bytes = Zeroizing::new(vec![0u8; length]);
    reader
        .read_exact(&mut bytes)
        .await
        .map_err(|_| Error::Transport)?;
    let mut cursor = Cursor::new(&*bytes);
    let mut scratch = Zeroizing::new(vec![0u8; 64 * 1024]);
    let value = ciborium::de::from_reader_with_buffer(&mut cursor, &mut scratch)
        .map_err(|_| Error::Invalid)?;
    if cursor.position() != length as u64 {
        return Err(Error::Invalid);
    }
    Ok(value)
}
async fn write<T: Serialize, W: AsyncWrite + Unpin>(
    writer: &mut W,
    value: &T,
    limit: usize,
) -> Result<(), Error> {
    let bytes = payload(value, limit)?;
    writer
        .write_u32(bytes.len() as u32)
        .await
        .map_err(|_| Error::Transport)?;
    writer
        .write_all(&bytes)
        .await
        .map_err(|_| Error::Transport)?;
    writer.flush().await.map_err(|_| Error::Transport)
}
/// Read one whole validated management request; caller supplies its deadline.
pub async fn read_request<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Request, Error> {
    let value: Request = read(reader, MAX_FRAME_BYTES).await?;
    value.validate()?;
    Ok(value)
}
/// Encode a validated request without retaining plaintext frame buffers.
pub async fn write_request<W: AsyncWrite + Unpin>(
    writer: &mut W,
    value: &Request,
) -> Result<(), Error> {
    value.validate()?;
    write(writer, value, MAX_FRAME_BYTES).await
}
/// Read a secret-free response; authenticated-session equality is caller-owned.
pub async fn read_reply<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Reply, Error> {
    let reply: Reply = read(reader, MAX_FRAME_BYTES).await?;
    reply.validate()?;
    Ok(reply)
}
impl Reply {
    /// Match the controller's observation contract on both encoding and decode.
    pub fn validate(&self) -> Result<(), Error> {
        match self {
            Self::Hello(hello) if hello.version != VERSION || hello.session.connection == 0 => {
                Err(Error::Invalid)
            }
            Self::Hello(_) => Ok(()),
            Self::Probe(probe) => {
                if probe.session.connection == 0 {
                    Err(Error::Invalid)
                } else {
                    Ok(())
                }
            }
            Self::Observation(value) => {
                transaction(&value.transaction)?;
                if (value.outcome == Outcome::Rejected) != value.failure.is_some() {
                    return Err(Error::Invalid);
                }
                Ok(())
            }
        }
    }
}
/// Send only typed secret-free observations or a successful Hello.
pub async fn write_reply<W: AsyncWrite + Unpin>(
    writer: &mut W,
    value: &Reply,
) -> Result<(), Error> {
    value.validate()?;
    write(writer, value, MAX_FRAME_BYTES).await
}
/// Read one exact managed header. Legacy prelude shapes cannot decode here.
pub async fn read_divert<R: AsyncRead + Unpin>(reader: &mut R) -> Result<ManagedDivert, Error> {
    let value: ManagedDivert = read(reader, MAX_DIVERT_BYTES).await?;
    value.validate()?;
    Ok(value)
}
impl ManagedDivert {
    /// Validate representation only; protected transport still authenticates it.
    pub fn validate(&self) -> Result<(), Error> {
        transaction(&self.transaction)?;
        if self.version != VERSION || !name(&self.destination_host) || self.destination_port == 0 {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}
/// Write a managed header before any native SSH bytes on that connection.
pub async fn write_divert<W: AsyncWrite + Unpin>(
    writer: &mut W,
    value: &ManagedDivert,
) -> Result<(), Error> {
    value.validate()?;
    write(writer, value, MAX_DIVERT_BYTES).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> Id {
        Id::from_bytes([byte; 32]).unwrap()
    }
    fn policy() -> Policy {
        Policy {
            destroyed: false,
            credentials: vec![ReadyRecord {
                name: "git".into(),
                material: "owner/git".into(),
                binding: Binding::Broker,
                key_version: id(1),
                trust_version: id(2),
                host: "git.example".into(),
                port: 22,
                user: "git".into(),
                on_violation: Violation::Block,
                key_kind: KeyKind::Ed25519Seed,
                key_bytes: SecretBytes::new(vec![0x53; 32]),
                upstream_public_key: "ssh-ed25519 fixture-public-key".into(),
            }],
            patterns: vec![Pattern {
                credential_id: "git".into(),
                decoder: microsandbox_scan::Decoder::Raw,
                bytes: SecretBytes::new(b"synthetic-secret-pattern".to_vec()),
                action: PatternAction {
                    enforce: Some(microsandbox_scan::Severity::Block),
                    audit: true,
                    count: true,
                },
            }],
        }
    }
    fn apply() -> Request {
        let policy = policy();
        Request::Apply(Apply {
            transaction: TransactionRef {
                session: BrokerSession {
                    controller: id(3),
                    broker: id(4),
                    connection: 1,
                },
                launch: LaunchRef {
                    instance: InstanceRef {
                        workload: WorkloadRef {
                            context: None,
                            name: "worker".into(),
                        },
                        instance: "one".into(),
                    },
                    generation: id(5),
                },
                revision: 1,
                policy_digest: policy_digest(&policy).unwrap(),
            },
            expected_revision: None,
            policy,
        })
    }

    #[tokio::test]
    async fn fenced_probe_roundtrip_is_liveness_only_and_validated_both_ways() {
        let session = BrokerSession {
            controller: id(3),
            broker: id(4),
            connection: 1,
        };
        let mut bytes = Vec::new();
        write_request(&mut bytes, &Request::Probe(session))
            .await
            .unwrap();
        assert!(matches!(read_request(&mut bytes.as_slice()).await.unwrap(),
            Request::Probe(found) if found == session));
        for current in [false, true] {
            let reply = Reply::Probe(Probe { session, current });
            let mut bytes = Vec::new();
            write_reply(&mut bytes, &reply).await.unwrap();
            assert!(matches!(read_reply(&mut bytes.as_slice()).await.unwrap(),
                Reply::Probe(found) if found.session == session && found.current == current));
            let mut invalid = session;
            invalid.connection = 0;
            assert!(Request::Probe(invalid).validate().is_err());
            let invalid = Reply::Probe(Probe {
                session: invalid,
                current,
            });
            assert!(write_reply(&mut Vec::new(), &invalid).await.is_err());
            assert!(read_reply(&mut framed(&invalid).as_slice()).await.is_err());
        }
        assert_eq!(MANAGEMENT_LEASE_SECS, 30);
        assert_eq!(MANAGEMENT_PROBE_SECS, 10);
    }
    fn framed(value: &impl Serialize) -> Vec<u8> {
        let body = payload(value, MAX_FRAME_BYTES).unwrap();
        let mut result = (body.len() as u32).to_be_bytes().to_vec();
        result.extend_from_slice(&body);
        result
    }
    fn wire_value() -> ciborium::value::Value {
        ciborium::de::from_reader(payload(&apply(), MAX_FRAME_BYTES).unwrap().as_slice()).unwrap()
    }
    fn at<'a>(
        value: &'a mut ciborium::value::Value,
        path: &[&str],
    ) -> &'a mut ciborium::value::Value {
        use ciborium::value::Value;
        if path.is_empty() {
            return value;
        }
        match value {
            Value::Map(map) => {
                let child = map
                    .iter_mut()
                    .find(|(key, _)| matches!(key, Value::Text(text) if text == path[0]))
                    .unwrap();
                at(&mut child.1, &path[1..])
            }
            Value::Array(array) => at(&mut array[path[0].parse::<usize>().unwrap()], &path[1..]),
            _ => panic!("expected typed CBOR map or array"),
        }
    }
    fn add_unknown(value: &mut ciborium::value::Value, path: &[&str]) {
        let ciborium::value::Value::Map(map) = at(value, path) else {
            panic!("expected map")
        };
        map.push((
            ciborium::value::Value::Text("unknown_field".into()),
            ciborium::value::Value::Bool(true),
        ));
    }

    #[test]
    fn identifiers_are_exact_nonzero_lowercase_hex() {
        assert_eq!(
            serde_json::from_str::<Id>(&format!("\"{}\"", id(1).to_hex())).unwrap(),
            id(1)
        );
        for value in [
            "0".repeat(64),
            "A".repeat(64),
            "1".repeat(63),
            "g".repeat(64),
        ] {
            assert!(serde_json::from_str::<Id>(&format!("\"{value}\"")).is_err());
        }
    }

    #[test]
    fn digest_covers_whole_relationship_material_trust_patterns_and_actions() {
        let expected = policy_digest(&policy()).unwrap();
        for mutation in 0..13 {
            let mut value = policy();
            match mutation {
                0 => value.credentials[0].name.push('x'),
                1 => value.credentials[0].material.push('x'),
                2 => value.credentials[0].key_version = id(8),
                3 => value.credentials[0].trust_version = id(9),
                4 => value.credentials[0].host.push('x'),
                5 => value.credentials[0].port = 2222,
                6 => value.credentials[0].user.push('x'),
                7 => value.credentials[0].on_violation = Violation::BlockAndTerminate,
                8 => value.credentials[0].key_bytes = SecretBytes::new(vec![0x54; 32]),
                9 => value.credentials[0].upstream_public_key.push('x'),
                10 => {
                    value.patterns[0].bytes =
                        SecretBytes::new(b"another-synthetic-pattern".to_vec())
                }
                11 => value.patterns[0].action.audit = false,
                12 => value.patterns[0].credential_id.push('x'),
                _ => unreachable!(),
            }
            assert_ne!(
                policy_digest(&value).unwrap(),
                expected,
                "mutation {mutation}"
            );
        }
        assert_eq!(expected, policy_digest(&policy()).unwrap());
    }

    #[test]
    fn debug_never_displays_seed_or_pattern_content() {
        let formatted = format!("{:?}", apply());
        assert!(formatted.contains("<redacted>"));
        assert!(!formatted.contains("synthetic-secret-pattern"));
        assert!(!formatted.contains("83, 83"));
        assert!(!formatted.contains("SSSSSS"));
    }

    #[test]
    fn unsupported_or_ambiguous_records_refuse_before_installation() {
        let mut value = policy();
        value.credentials[0].host = "*.example".into();
        assert!(value.validate().is_err());
        let mut value = policy();
        value.credentials[0].binding = Binding::Guest;
        assert!(value.validate().is_err());
        let mut value = policy();
        value.credentials[0].key_bytes = SecretBytes::new(vec![1; 31]);
        assert!(value.validate().is_err());
        let mut value = policy();
        value.credentials.extend(policy().credentials);
        assert!(value.validate().is_err());
        let mut value = policy();
        value.destroyed = true;
        assert!(value.validate().is_err());
    }

    #[tokio::test]
    async fn request_roundtrip_preserves_whole_validated_policy() {
        let expected = apply();
        let mut bytes = Vec::new();
        write_request(&mut bytes, &expected).await.unwrap();
        let decoded = read_request(&mut bytes.as_slice()).await.unwrap();
        match (expected, decoded) {
            (Request::Apply(expected), Request::Apply(decoded)) => {
                assert_eq!(expected.transaction, decoded.transaction);
                assert_eq!(
                    policy_digest(&expected.policy).unwrap(),
                    policy_digest(&decoded.policy).unwrap()
                );
                assert_eq!(
                    decoded.policy.credentials[0].key_bytes.as_slice(),
                    &[0x53; 32]
                );
            }
            _ => panic!("wrong operation"),
        }
    }

    #[tokio::test]
    async fn unknown_versions_operations_and_nested_fields_refuse() {
        let bad = Request::Hello(Hello {
            version: VERSION + 1,
            controller: id(1),
        });
        assert!(read_request(&mut framed(&bad).as_slice()).await.is_err());
        let mut value = wire_value();
        assert!(
            read_request(&mut framed(&value).as_slice()).await.is_ok(),
            "CBOR byte-string representation must remain valid"
        );
        add_unknown(&mut value, &["apply", "policy", "credentials", "0"]);
        assert!(read_request(&mut framed(&value).as_slice()).await.is_err());
        let mut value = wire_value();
        add_unknown(&mut value, &["apply", "policy", "patterns", "0", "action"]);
        assert!(read_request(&mut framed(&value).as_slice()).await.is_err());
        let mut value = wire_value();
        *at(
            &mut value,
            &["apply", "policy", "credentials", "0", "key_kind"],
        ) = ciborium::value::Value::Text("rsa".into());
        assert!(read_request(&mut framed(&value).as_slice()).await.is_err());
        assert!(
            read_request(&mut framed(&serde_json::json!({"guest_exec": {}})).as_slice())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn changed_bytes_with_old_digest_and_zero_expected_revision_refuse() {
        let Request::Apply(mut value) = apply() else {
            unreachable!()
        };
        value.policy.credentials[0].key_bytes = SecretBytes::new(vec![1; 32]);
        assert!(
            read_request(&mut framed(&Request::Apply(value)).as_slice())
                .await
                .is_err()
        );
        let Request::Apply(mut value) = apply() else {
            unreachable!()
        };
        value.expected_revision = Some(0);
        assert!(
            read_request(&mut framed(&Request::Apply(value)).as_slice())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn frame_limit_truncation_trailing_data_and_legacy_header_fail_closed() {
        assert_eq!(
            read_request(&mut (MAX_FRAME_BYTES as u32 + 1).to_be_bytes().as_slice())
                .await
                .unwrap_err(),
            Error::Limit
        );
        let mut bytes = framed(&apply());
        bytes.pop();
        assert_eq!(
            read_request(&mut bytes.as_slice()).await.unwrap_err(),
            Error::Transport
        );
        let mut bytes = framed(&apply());
        bytes.push(0);
        let len = (bytes.len() - 4) as u32;
        bytes[..4].copy_from_slice(&len.to_be_bytes());
        assert_eq!(
            read_request(&mut bytes.as_slice()).await.unwrap_err(),
            Error::Invalid
        );
        let legacy = serde_json::json!({"dest_host":"git.example", "dest_port":22, "transport_cid":11, "epoch":12});
        assert!(read_divert(&mut framed(&legacy).as_slice()).await.is_err());
    }

    #[test]
    fn bounded_policy_counts_and_secret_sizes_refuse() {
        let mut value = policy();
        value.patterns[0].bytes = SecretBytes::new(vec![1; 64 * 1024 + 1]);
        assert_eq!(value.validate(), Err(Error::Limit));
        let mut value = policy();
        value.patterns = (0..MAX_PATTERNS + 1)
            .map(|_| policy().patterns.remove(0))
            .collect();
        assert_eq!(value.validate(), Err(Error::Limit));
        let mut value = policy();
        value.patterns = (0..9)
            .map(|_| {
                let mut pattern = policy().patterns.remove(0);
                pattern.bytes = SecretBytes::new(vec![1; 64 * 1024]);
                pattern
            })
            .collect();
        assert_eq!(value.validate(), Err(Error::Limit));
    }

    #[tokio::test]
    async fn secret_decode_accepts_only_bounded_definite_byte_strings() {
        let good = SecretBytes::new(vec![0x71; 64 * 1024]);
        let decoded: SecretBytes = read(&mut framed(&good).as_slice(), MAX_FRAME_BYTES)
            .await
            .unwrap();
        assert_eq!(decoded.as_slice(), good.as_slice());
        for body in [
            vec![0x83, 1, 2, 3],             // Integer arrays are not secret byte strings.
            vec![0x5f, 0x43, 1, 2, 3, 0xff], // Indefinite byte-string chunks.
            vec![0x48, 1, 2],                // Definite bytes truncated inside a complete frame.
            vec![0x5a, 0, 1, 0, 1],          // 64 KiB + 1 declaration, rejected before payload.
        ] {
            let mut bytes = (body.len() as u32).to_be_bytes().to_vec();
            bytes.extend_from_slice(&body);
            assert!(
                read::<SecretBytes, _>(&mut bytes.as_slice(), MAX_FRAME_BYTES)
                    .await
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn replies_validate_outcome_failure_and_session_on_both_sides() {
        let Request::Apply(value) = apply() else {
            unreachable!()
        };
        for outcome in [
            Outcome::Applied,
            Outcome::Pending,
            Outcome::Rejected,
            Outcome::StateLost,
        ] {
            for failure in [None, Some(Failure::Unavailable)] {
                let reply = Reply::Observation(Observation {
                    transaction: value.transaction.clone(),
                    outcome,
                    failure,
                });
                let valid = (outcome == Outcome::Rejected) == failure.is_some();
                assert_eq!(
                    read_reply(&mut framed(&reply).as_slice()).await.is_ok(),
                    valid
                );
                let mut output = Vec::new();
                assert_eq!(write_reply(&mut output, &reply).await.is_ok(), valid);
                if !valid {
                    assert!(output.is_empty(), "refusal precedes any frame bytes");
                }
            }
        }
        for (version, connection) in [(VERSION + 1, 1), (VERSION, 0)] {
            let reply = Reply::Hello(Welcome {
                version,
                session: BrokerSession {
                    controller: id(1),
                    broker: id(2),
                    connection,
                },
            });
            assert!(read_reply(&mut framed(&reply).as_slice()).await.is_err());
            assert!(write_reply(&mut Vec::new(), &reply).await.is_err());
        }
        let mut target = value.transaction;
        target.revision = 0;
        let reply = Reply::Observation(Observation {
            transaction: target,
            outcome: Outcome::Applied,
            failure: None,
        });
        assert!(read_reply(&mut framed(&reply).as_slice()).await.is_err());
        assert!(write_reply(&mut Vec::new(), &reply).await.is_err());
    }
}
