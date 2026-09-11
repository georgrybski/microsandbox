//! Compiled pattern library: one-time needle derivation, shared across sessions.
//!
//! [`PatternLibrary::new`] resolves each [`ScanPattern`] to raw credential
//! bytes (base64-decoding base64-authored patterns), applies the length
//! thresholds, and derives the literal needles matched on the stream:
//!
//! - raw: the credential bytes themselves, kept when raw is at least
//!   [`MIN_RAW_BYTES`] (8) else the pattern is EXCLUDED with a compile-time
//!   warning and a [`PatternExclusion`] coverage note — never fail-closed;
//! - hex: lowercase and uppercase hex of the raw bytes, derived only when
//!   raw is at least [`MIN_HEX_RAW_BYTES`] (12);
//! - base64: standard-base64 text of the raw bytes (padded and unpadded
//!   forms), derived when raw is at least [`MIN_BASE64_RAW_BYTES`] (8).
//!
//! The library owns every needle in zeroizing buffers and is shared across
//! relay sessions by `Arc`; per-session [`ScanState`](crate::scan::ScanState)
//! holds only tails and decoder state. Redacting `Debug` impls cover the
//! library and its entries: needles never render.

use std::fmt;
use std::sync::Arc;

use zeroize::Zeroizing;

use crate::action::ActionSet;
use crate::decode::{base64_needle, decode_authored_base64, max_encoded_detection_len};
use crate::pattern::{
    Decoder, ExclusionReason, PatternDigest, PatternExclusion, PatternId, ScanPattern,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Minimum raw credential length kept for matching, in bytes.
///
/// Shorter patterns are excluded at compile time with a warning: below 8
/// bytes literal matches are too collision-prone for binary SSH streams.
pub const MIN_RAW_BYTES: usize = 8;

/// Minimum raw credential length that derives hex needles, in bytes.
pub const MIN_HEX_RAW_BYTES: usize = 12;

/// Minimum raw credential length that derives base64 needles, in bytes.
pub const MIN_BASE64_RAW_BYTES: usize = 8;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Compiled, shareable match library for one pattern group.
///
/// Built once from bootstrap patterns and shared across relay sessions by
/// `Arc`. An empty library (including all-patterns-excluded) matches
/// nothing and never fails: sessions relay unchanged.
pub struct PatternLibrary {
    /// Compiled entries in admission order (hit order is deterministic).
    entries: Vec<CompiledPattern>,

    /// Longest raw credential length; sizes the raw tail.
    max_raw_len: usize,

    /// Longest derived literal needle; informational (the encoded tail
    /// covers every derived needle via the 6x bound — see below).
    max_direct_len: usize,
}

/// One compiled pattern: resolved raw bytes plus derived literal needles.
///
/// Needles live in zeroizing buffers and wipe on drop with the library.
/// The `Debug` impl shows the credential name and needle lengths only.
pub(crate) struct CompiledPattern {
    /// Pattern identity for hit attribution.
    id: PatternId,

    /// Credential name for audit attribution.
    credential_id: String,

    /// Authored decoder, reported on hits.
    decoder: Decoder,

    /// Hit-time digest over the raw bytes.
    digest: PatternDigest,

    /// Action contributed when this pattern hits.
    action: ActionSet,

    /// Raw credential bytes (the parity core with the HTTP detector).
    raw: Zeroizing<Vec<u8>>,

    /// Lowercase hex literal, when the raw length qualifies.
    hex_lower: Option<Zeroizing<Vec<u8>>>,

    /// Uppercase hex literal, when the raw length qualifies. Mixed-case
    /// hex is a P0 gap: only the uniform cases derive.
    hex_upper: Option<Zeroizing<Vec<u8>>>,

    /// Standard-base64 literal with padding, when the raw length qualifies.
    base64_padded: Option<Zeroizing<Vec<u8>>>,

    /// Standard-base64 literal without padding, when it differs.
    base64_unpadded: Option<Zeroizing<Vec<u8>>>,
}

/// Non-secret match metadata for audit attribution.
#[derive(Debug, Clone, Copy)]
pub struct PatternMeta<'a> {
    /// Credential name (never secret content).
    pub credential_id: &'a str,

    /// Authored decoder, reported on hits.
    pub decoder: Decoder,

    /// Hit-time digest over the raw bytes.
    pub digest: PatternDigest,

    /// Action contributed when this pattern hits.
    pub action: ActionSet,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PatternLibrary {
    /// Compile patterns into a shareable library.
    ///
    /// Returns the library plus one [`PatternExclusion`] per skipped
    /// pattern; each skip also emits a compile-time warning naming only
    /// the credential and the reason. Skips never fail closed.
    pub fn new(patterns: Vec<ScanPattern>) -> (Arc<Self>, Vec<PatternExclusion>) {
        let mut entries = Vec::with_capacity(patterns.len());
        let mut excluded = Vec::new();
        let mut max_raw_len = 0;
        let mut max_direct_len = 0;

        for input in patterns {
            let credential_id = input.credential_id().to_string();
            let decoder = input.pattern().decoder();
            let action = input.action();
            let id = input.pattern().id();
            let authored = input.pattern().sealed().to_vec();
            // The input drops here; its sealed bytes wipe on drop.
            drop(input);

            let raw = match decoder {
                Decoder::Raw => authored,
                Decoder::Base64 => match decode_authored_base64(&authored) {
                    Some(raw) => raw,
                    None => {
                        warn_excluded(&credential_id, &ExclusionReason::InvalidBase64);
                        excluded.push(PatternExclusion {
                            credential_id,
                            reason: ExclusionReason::InvalidBase64,
                        });
                        continue;
                    }
                },
            };
            if raw.len() < MIN_RAW_BYTES {
                let reason = ExclusionReason::TooShort { len: raw.len() };
                warn_excluded(&credential_id, &reason);
                excluded.push(PatternExclusion {
                    credential_id,
                    reason,
                });
                continue;
            }

            let digest = PatternDigest::of_raw(&raw);
            max_raw_len = max_raw_len.max(raw.len());
            let mut direct = raw.len();

            let (hex_lower, hex_upper) = if raw.len() >= MIN_HEX_RAW_BYTES {
                let lower = Zeroizing::new(hex::encode(&raw).into_bytes());
                let upper = Zeroizing::new(hex::encode(&raw).to_uppercase().into_bytes());
                direct = direct.max(lower.len());
                (Some(lower), Some(upper))
            } else {
                (None, None)
            };
            let (base64_padded, base64_unpadded) = if raw.len() >= MIN_BASE64_RAW_BYTES {
                let padded_bytes = base64_needle(&raw);
                direct = direct.max(padded_bytes.len());
                let pad = padded_bytes
                    .iter()
                    .rev()
                    .take_while(|b| **b == b'=')
                    .count();
                let unpadded = if pad > 0 {
                    Some(Zeroizing::new(
                        padded_bytes[..padded_bytes.len() - pad].to_vec(),
                    ))
                } else {
                    None
                };
                (Some(Zeroizing::new(padded_bytes)), unpadded)
            } else {
                (None, None)
            };
            max_direct_len = max_direct_len.max(direct);

            entries.push(CompiledPattern {
                id,
                credential_id,
                decoder,
                digest,
                action,
                raw: Zeroizing::new(raw),
                hex_lower,
                hex_upper,
                base64_padded,
                base64_unpadded,
            });
        }

        (
            Arc::new(Self {
                entries,
                max_raw_len,
                max_direct_len,
            }),
            excluded,
        )
    }

    /// An empty library (no patterns admitted).
    pub fn empty() -> Arc<Self> {
        Arc::new(Self {
            entries: Vec::new(),
            max_raw_len: 0,
            max_direct_len: 0,
        })
    }

    /// Number of admitted patterns.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no pattern was admitted.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Longest raw credential length (sizes the raw tail).
    pub fn max_raw_len(&self) -> usize {
        self.max_raw_len
    }

    /// Longest derived literal needle (informational; the encoded tail
    /// covers every derived needle via the 6x bound).
    pub fn max_direct_len(&self) -> usize {
        self.max_direct_len
    }

    /// Raw-tail capacity: `max_raw_len - 1`.
    ///
    /// A raw needle of length L split across chunks needs its first L-1
    /// bytes retained, so one less than the longest raw needle suffices.
    pub(crate) fn raw_tail_cap(&self) -> usize {
        self.max_raw_len.saturating_sub(1)
    }

    /// Encoded-tail capacity: `6 * max_raw_len - 1`.
    ///
    /// Ports the detector's 6x bound (percent `%XX` is 3x, JSON `\uXXXX`
    /// is 6x). The same tail backs the derived literal needles — hex (2x)
    /// and base64 (4/3x) both fit inside the 6x bound — and the
    /// percent/JSON decode views.
    pub(crate) fn encoded_tail_cap(&self) -> usize {
        max_encoded_detection_len(self.max_raw_len).saturating_sub(1)
    }

    /// Iterate admitted entries for matching.
    pub(crate) fn entries(&self) -> &[CompiledPattern] {
        &self.entries
    }

    /// Resolve a hit pattern id to audit metadata, if still present.
    pub fn lookup(&self, id: &PatternId) -> Option<PatternMeta<'_>> {
        self.entries
            .iter()
            .find(|entry| entry.id == *id)
            .map(|entry| PatternMeta {
                credential_id: &entry.credential_id,
                decoder: entry.decoder,
                digest: entry.digest,
                action: entry.action,
            })
    }
}

impl CompiledPattern {
    /// Raw credential bytes (parity core with the HTTP detector).
    pub(crate) fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// Match `f` against each derived literal needle (hex, base64 forms).
    pub(crate) fn for_each_derived(&self, mut f: impl FnMut(&[u8])) {
        if let Some(needle) = self.hex_lower.as_deref() {
            f(needle);
        }
        if let Some(needle) = self.hex_upper.as_deref() {
            f(needle);
        }
        if let Some(needle) = self.base64_padded.as_deref() {
            f(needle);
        }
        if let Some(needle) = self.base64_unpadded.as_deref() {
            f(needle);
        }
    }

    /// Pattern identity for hit attribution.
    pub(crate) fn id(&self) -> PatternId {
        self.id
    }

    /// Authored decoder, reported on hits.
    pub(crate) fn decoder(&self) -> Decoder {
        self.decoder
    }

    /// Hit-time digest over the raw bytes.
    pub(crate) fn digest(&self) -> PatternDigest {
        self.digest
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Debug for CompiledPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompiledPattern")
            .field("id", &self.id)
            .field("credential_id", &self.credential_id)
            .field("decoder", &self.decoder)
            .field("digest", &self.digest)
            .field("action", &self.action)
            .field("raw_len", &self.raw.len())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for PatternLibrary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PatternLibrary")
            .field("entries", &self.entries)
            .field("max_raw_len", &self.max_raw_len)
            .field("max_direct_len", &self.max_direct_len)
            .finish()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Compile-time warning for an excluded pattern: credential name and
/// reason only, never bytes.
fn warn_excluded(credential_id: &str, reason: &ExclusionReason) {
    eprintln!("scan: excluding DLP pattern for credential '{credential_id}': {reason}");
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::ActionSet;

    fn pattern(credential_id: &str, decoder: Decoder, bytes: &[u8]) -> ScanPattern {
        ScanPattern::compile(
            credential_id.to_string(),
            decoder,
            bytes.to_vec(),
            ActionSet::passthrough(),
        )
    }

    #[test]
    fn short_raw_patterns_are_excluded_with_a_coverage_note() {
        let (library, excluded) = PatternLibrary::new(vec![
            pattern("short", Decoder::Raw, b"1234567"),
            pattern("ok", Decoder::Raw, b"12345678"),
        ]);
        assert_eq!(library.len(), 1);
        assert_eq!(excluded.len(), 1);
        assert_eq!(excluded[0].credential_id, "short");
        assert_eq!(excluded[0].reason, ExclusionReason::TooShort { len: 7 });
        // Exclusion never fails closed: the admitted pattern still compiles.
        assert_eq!(library.max_raw_len(), 8);
    }

    #[test]
    fn hex_derives_only_from_twelve_bytes_up() {
        let (library, _) = PatternLibrary::new(vec![
            pattern("eleven", Decoder::Raw, b"12345678901"),
            pattern("twelve", Decoder::Raw, b"123456789012"),
        ]);
        let entries = library.entries();
        assert!(entries[0].hex_lower.is_none());
        assert!(entries[1].hex_lower.is_some());
        assert_eq!(
            entries[1].hex_lower.as_deref().unwrap().as_slice(),
            b"313233343536373839303132"
        );
        assert_eq!(
            entries[1].hex_upper.as_deref().unwrap().as_slice(),
            b"313233343536373839303132".to_ascii_uppercase().as_slice()
        );
    }

    #[test]
    fn base64_derives_from_eight_bytes_up_with_padding_variants() {
        let (library, excluded) = PatternLibrary::new(vec![
            pattern("seven", Decoder::Raw, b"1234567"),
            pattern("eight", Decoder::Raw, b"12345678"),
        ]);
        assert_eq!(excluded.len(), 1);
        let entries = library.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].base64_padded.as_deref().unwrap(),
            b"MTIzNDU2Nzg="
        );
        assert_eq!(
            entries[0].base64_unpadded.as_deref().unwrap(),
            b"MTIzNDU2Nzg"
        );
    }

    #[test]
    fn base64_authored_patterns_resolve_then_threshold() {
        let raw = b"credential-bytes-001";
        let encoded = base64_needle(raw);
        let (library, excluded) = PatternLibrary::new(vec![
            pattern("b64", Decoder::Base64, &encoded),
            pattern("bad", Decoder::Base64, b"!!!not-base64!!!"),
            pattern("tiny", Decoder::Base64, b"QUJD"),
        ]);
        assert_eq!(library.len(), 1);
        assert_eq!(library.entries()[0].raw(), raw);
        assert_eq!(excluded.len(), 2);
        assert!(
            excluded
                .iter()
                .any(|e| e.reason == ExclusionReason::InvalidBase64)
        );
        assert!(
            excluded
                .iter()
                .any(|e| e.reason == ExclusionReason::TooShort { len: 3 })
        );
    }

    #[test]
    fn lookup_resolves_ids_for_audit() {
        let (library, _) = PatternLibrary::new(vec![pattern("cred-a", Decoder::Raw, b"12345678")]);
        let id = library.entries()[0].id();
        let meta = library.lookup(&id).expect("admitted pattern resolves");
        assert_eq!(meta.credential_id, "cred-a");
        assert_eq!(meta.decoder, Decoder::Raw);
        assert_eq!(meta.digest, PatternDigest::of_raw(b"12345678"));
    }

    #[test]
    fn debug_impls_never_carry_needles() {
        let (library, _) =
            PatternLibrary::new(vec![pattern("cred-a", Decoder::Raw, b"needle-bytes-001")]);
        let rendered = format!("{library:?}");
        assert!(!rendered.contains("needle-bytes-001"));
        assert!(!rendered.contains(&hex::encode(b"needle-bytes-001")));
        assert!(rendered.contains("cred-a"));
    }

    #[test]
    fn tail_caps_follow_the_documented_derivation() {
        let (library, _) =
            PatternLibrary::new(vec![pattern("cred-a", Decoder::Raw, b"123456789012")]);
        assert_eq!(library.raw_tail_cap(), 11);
        assert_eq!(library.encoded_tail_cap(), 6 * 12 - 1);
        let (empty, _) = PatternLibrary::new(Vec::new());
        assert_eq!(empty.raw_tail_cap(), 0);
        assert_eq!(empty.encoded_tail_cap(), 0);
    }
}
