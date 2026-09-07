//! Sealed pattern types: identities, digests, and secret custody.
//!
//! [`SensitivePattern`] carries exactly an id, an authored [`Decoder`],
//! and sealed bytes. The id is the truncated SHA-256 over the credential
//! name, the decoder tag, and the authored bytes (each length-prefixed so
//! concatenations cannot collide across field boundaries). The hit-time
//! digest is the truncated SHA-256 over the resolved raw credential bytes.
//! Both truncate to [`ID_BYTES`] bytes: enough to correlate audit records,
//! too short to brute-force content from.
//!
//! [`SealedBytes`] holds secret material with broker-key custody idioms:
//! no `Clone`, no `Serialize`, zeroized on drop, and a redacting `Debug`.
//! It deliberately does not mirror the `Clone` + `Serialize` secret-entry
//! style used for host-side configuration: compiled patterns are
//! handoff-only and never re-serialized.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Truncated hash length for pattern ids and hit digests, in bytes.
pub const ID_BYTES: usize = 16;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Authored encoding of a pattern's bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decoder {
    /// Bytes are the literal credential bytes.
    Raw,

    /// Bytes are standard-base64 text decoding to the credential bytes.
    Base64,
}

/// Truncated SHA-256 over (credential id, decoder, authored bytes).
///
/// Safe to log: a hash over the pattern, never content.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PatternId([u8; ID_BYTES]);

/// Truncated SHA-256 over the resolved raw credential bytes.
///
/// Emitted at hit time for audit correlation; never content.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PatternDigest([u8; ID_BYTES]);

/// Secret bytes in sealed custody.
///
/// Moved (never cloned) from the bootstrap wire form into the compiled
/// pattern library, and wiped when the owning pattern drops. There is no
/// accessor outside this crate: matching runs inside the crate against
/// borrowed views.
pub struct SealedBytes(Zeroizing<Vec<u8>>);

/// One secret pattern: an id, its authored decoder, and sealed bytes.
///
/// Constructed with [`SensitivePattern::compile`], which seals the given
/// bytes without copying them further. Length and encoding thresholds are
/// applied later at library compile time (see [`PatternLibrary`](crate::library::PatternLibrary)),
/// so this type never needs to inspect — or reject — its bytes.
pub struct SensitivePattern {
    /// Pattern identity (hash, safe to log).
    id: PatternId,

    /// How the sealed bytes were authored.
    decoder: Decoder,

    /// The sealed credential bytes.
    bytes: SealedBytes,
}

/// One compiled pattern with its non-secret metadata.
///
/// The credential name and [`ActionSet`](crate::action::ActionSet) are
/// plain data: the name attributes audit records and the action feeds the
/// strictest-action reduction. Neither carries secret content.
pub struct ScanPattern {
    /// The sealed pattern.
    pattern: SensitivePattern,

    /// Credential name for audit attribution (never secret content).
    credential_id: String,

    /// Action contributed when this pattern hits.
    action: crate::action::ActionSet,
}

/// Why a compiled pattern was excluded from the match library.
///
/// Exclusions warn at compile time and are reported back to the caller;
/// they never fail closed — the remaining patterns still enforce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExclusionReason {
    /// The resolved raw credential is shorter than the minimum match
    /// length (too collision-prone to enforce).
    TooShort {
        /// Resolved raw length in bytes.
        len: usize,
    },

    /// A base64-authored pattern does not decode as standard base64.
    InvalidBase64,
}

/// A pattern excluded at library compile time, with its credential name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternExclusion {
    /// Credential name of the excluded pattern.
    pub credential_id: String,

    /// Why it was excluded.
    pub reason: ExclusionReason,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Decoder {
    /// Stable tag byte mixed into the pattern-id hash.
    fn tag(self) -> u8 {
        match self {
            Self::Raw => 0,
            Self::Base64 => 1,
        }
    }
}

impl PatternId {
    /// Derive the pattern id over length-prefixed fields.
    pub fn derive(credential_id: &str, decoder: Decoder, bytes: &[u8]) -> Self {
        let mut hash = Sha256::new();
        hash.update((credential_id.len() as u64).to_be_bytes());
        hash.update(credential_id.as_bytes());
        hash.update([decoder.tag()]);
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
        let digest = hash.finalize();
        let mut id = [0u8; ID_BYTES];
        id.copy_from_slice(&digest[..ID_BYTES]);
        Self(id)
    }

    /// Hex rendering for audit records and logs.
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

impl PatternDigest {
    /// Digest the resolved raw credential bytes at hit time.
    pub fn of_raw(bytes: &[u8]) -> Self {
        let mut hash = Sha256::new();
        hash.update(bytes);
        let digest = hash.finalize();
        let mut out = [0u8; ID_BYTES];
        out.copy_from_slice(&digest[..ID_BYTES]);
        Self(out)
    }

    /// Hex rendering for audit records and logs.
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

impl SealedBytes {
    /// Seal owned bytes without copying them further.
    pub fn seal(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Borrow the sealed bytes for in-crate matching.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl SensitivePattern {
    /// Seal authored bytes into a pattern, deriving its id.
    ///
    /// `credential_id` feeds only the id hash; it is not retained here
    /// (callers keep it in [`ScanPattern`] when audit attribution needs
    /// it). The bytes move into sealed custody with no further copies.
    pub fn compile(credential_id: &str, decoder: Decoder, bytes: Vec<u8>) -> Self {
        let id = PatternId::derive(credential_id, decoder, &bytes);
        Self {
            id,
            decoder,
            bytes: SealedBytes::seal(bytes),
        }
    }

    /// Pattern identity (hash, safe to log).
    pub fn id(&self) -> PatternId {
        self.id
    }

    /// How the sealed bytes were authored.
    pub fn decoder(&self) -> Decoder {
        self.decoder
    }

    /// Borrow the sealed bytes for in-crate library compilation.
    pub(crate) fn sealed(&self) -> &[u8] {
        self.bytes.as_bytes()
    }
}

impl ScanPattern {
    /// Seal authored bytes with audit metadata and the contributed action.
    pub fn compile(
        credential_id: String,
        decoder: Decoder,
        bytes: Vec<u8>,
        action: crate::action::ActionSet,
    ) -> Self {
        let pattern = SensitivePattern::compile(&credential_id, decoder, bytes);
        Self {
            pattern,
            credential_id,
            action,
        }
    }

    /// The sealed pattern.
    pub fn pattern(&self) -> &SensitivePattern {
        &self.pattern
    }

    /// Credential name for audit attribution.
    pub fn credential_id(&self) -> &str {
        &self.credential_id
    }

    /// Action contributed when this pattern hits.
    pub fn action(&self) -> crate::action::ActionSet {
        self.action
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Display for PatternId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for PatternId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PatternId").field(&self.to_hex()).finish()
    }
}

impl fmt::Display for PatternDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for PatternDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PatternDigest")
            .field(&self.to_hex())
            .finish()
    }
}

impl fmt::Debug for SealedBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedBytes")
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl fmt::Debug for SensitivePattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SensitivePattern")
            .field("id", &self.id)
            .field("decoder", &self.decoder)
            .field("bytes", &self.bytes)
            .finish()
    }
}

impl fmt::Debug for ScanPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScanPattern")
            .field("pattern", &self.pattern)
            .field("credential_id", &self.credential_id)
            .field("action", &self.action)
            .finish()
    }
}

impl fmt::Display for ExclusionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { len } => write!(
                f,
                "resolved credential is {len} bytes, below the minimum match length"
            ),
            Self::InvalidBase64 => f.write_str("base64-authored bytes do not decode"),
        }
    }
}

impl fmt::Display for PatternExclusion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "credential '{}': {}", self.credential_id, self.reason)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Zeroize a moved wire byte vector without logging it.
///
/// Splits the drop-and-wipe idiom out for the brokerd ingest path, which
/// destructures bootstrap wire patterns field by field: bytes that never
/// reach sealed custody are wiped here instead of dropped in the clear.
pub fn wipe_wire_bytes(mut bytes: Vec<u8>) {
    bytes.zeroize();
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::ActionSet;

    #[test]
    fn pattern_id_binds_credential_decoder_and_bytes() {
        let bytes = b"credential-bytes-001".to_vec();
        let raw = PatternId::derive("cred-a", Decoder::Raw, &bytes);
        // Different credential names diverge.
        assert_ne!(raw, PatternId::derive("cred-b", Decoder::Raw, &bytes));
        // Different authored decoders diverge over identical bytes.
        assert_ne!(raw, PatternId::derive("cred-a", Decoder::Base64, &bytes));
        // Different bytes diverge.
        assert_ne!(
            raw,
            PatternId::derive("cred-a", Decoder::Raw, b"credential-bytes-002")
        );
        // Same inputs are stable.
        assert_eq!(raw, PatternId::derive("cred-a", Decoder::Raw, &bytes));
        assert_eq!(raw.to_hex().len(), ID_BYTES * 2);
    }

    #[test]
    fn pattern_id_uses_length_prefixing() {
        // Without length prefixes, ("ab", "c") and ("a", "bc") would hash
        // the same credential stream. The u64 prefixes keep them apart.
        let left = PatternId::derive("ab", Decoder::Raw, b"c");
        let right = PatternId::derive("a", Decoder::Raw, b"bc");
        assert_ne!(left, right);
    }

    #[test]
    fn digest_is_stable_and_truncated() {
        let digest = PatternDigest::of_raw(b"credential-bytes-001");
        assert_eq!(digest, PatternDigest::of_raw(b"credential-bytes-001"));
        assert_ne!(digest, PatternDigest::of_raw(b"credential-bytes-002"));
        assert_eq!(digest.to_hex().len(), ID_BYTES * 2);
    }

    #[test]
    fn debug_impls_never_carry_secret_bytes() {
        let secret = b"super-secret-credential-value".to_vec();
        let sealed = SealedBytes::seal(secret.clone());
        let rendered = format!("{sealed:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("super-secret"));

        let pattern = SensitivePattern::compile("cred-a", Decoder::Raw, secret.clone());
        let rendered = format!("{pattern:?}");
        assert!(!rendered.contains("super-secret"));
        assert!(rendered.contains(&pattern.id().to_hex()));

        let scanned = ScanPattern::compile(
            "cred-a".to_string(),
            Decoder::Raw,
            secret,
            ActionSet::passthrough(),
        );
        let rendered = format!("{scanned:?}");
        assert!(!rendered.contains("super-secret"));
        assert!(rendered.contains("cred-a"));
    }
}
