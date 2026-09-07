//! Streaming scan state: per-direction chunk matching over a shared library.
//!
//! [`ScanState`] borrows a compiled [`PatternLibrary`] by `Arc` and holds
//! only streaming state: a raw tail, an encoded tail, and the incremental
//! base64 decoder. One `ScanState` serves one direction of one session —
//! tails must never stitch across directions, so request and response legs
//! each own one.
//!
//! Each [`ScanState::scan_chunk`] runs four views in order over the new
//! bytes stitched to their tails:
//!
//! 1. raw view: raw needles matched literally;
//! 2. encoded-literal view: derived hex/base64 needles matched literally
//!    on the encoded tail (both fit inside the 6x bound);
//! 3. percent/JSON views: the stitched bytes decoded first (matching the
//!    HTTP detector's decode-then-scan), raw needles only;
//! 4. base64-stream view: the stream itself incrementally base64-decoded,
//!    raw needles matched in decoded space.
//!
//! Raw-view matches are exactly-once across chunks (matches fully inside
//! the carried tail do not re-report). Decode views subtract a slop of one
//! needle length from the tail boundary so escapes split across the seam
//! cannot hide a match; a seam-adjacent match may rarely report twice,
//! which audit counting tolerates but evasion must not exploit. Hits
//! dedupe by pattern id within a chunk (first view wins), and the report's
//! strictest action folds contributing actions with
//! [`ActionSet::strictest`].

use std::sync::Arc;

use crate::action::ActionSet;
use crate::decode::{
    Base64StreamDecoder, json_unescaped_view, matches_new_bytes, percent_decoded_view,
    update_tail_buffer,
};
use crate::library::PatternLibrary;
use crate::pattern::{Decoder, PatternDigest, PatternId};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One streaming direction of one relay session.
///
/// Created per direction from the shared library; tails and decoder state
/// evolve with each [`ScanState::scan_chunk`] call.
pub struct ScanState {
    /// Shared compiled needles (immutable, zeroized with the library).
    library: Arc<PatternLibrary>,

    /// Trailing raw bytes (`max_raw_len - 1`) for raw-needle stitching.
    raw_tail: Vec<u8>,

    /// Trailing raw bytes (`6 * max_raw_len - 1`) backing the derived
    /// literal needles and the percent/JSON decode views.
    encoded_tail: Vec<u8>,

    /// Incremental base64-stream decoder state.
    base64: Base64StreamDecoder,

    /// Trailing decoded bytes (`max_raw_len - 1`) for base64-view stitching.
    base64_tail: Vec<u8>,
}

/// One pattern hit: identities only, never content.
///
/// `decoder` is the matched pattern's authored decoder; `digest` is the
/// hit-time digest over its raw bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScanHit {
    /// Which pattern matched.
    pub pattern_id: PatternId,

    /// The matched pattern's authored decoder.
    pub decoder: Decoder,

    /// Hit-time digest over the pattern's raw bytes.
    pub digest: PatternDigest,
}

/// Matches from one chunk plus the reduced action.
///
/// `strictest_action` is `None` when nothing hit; otherwise it folds every
/// hit's contributed action with [`ActionSet::strictest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanReport {
    /// Hits in library admission order (deduped by pattern id).
    pub hits: Vec<ScanHit>,

    /// Reduced action over the hits, if any.
    pub strictest_action: Option<ActionSet>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ScanState {
    /// Create per-direction streaming state over the shared library.
    ///
    /// The spec's `ScanState::new(patterns)` shape is split in two on
    /// purpose: sealed patterns cannot clone per session, so compilation
    /// ([`PatternLibrary::new`]) happens once and each session direction
    /// borrows the result here.
    pub fn new(library: &Arc<PatternLibrary>) -> Self {
        Self {
            library: Arc::clone(library),
            raw_tail: Vec::new(),
            encoded_tail: Vec::new(),
            base64: Base64StreamDecoder::new(),
            base64_tail: Vec::new(),
        }
    }

    /// Scan one chunk, advancing tails and decoder state.
    pub fn scan_chunk(&mut self, chunk: &[u8]) -> ScanReport {
        let mut hits: Vec<ScanHit> = Vec::new();

        self.scan_raw_view(chunk, &mut hits);
        self.scan_derived_view(chunk, &mut hits);
        self.scan_decoded_views(chunk, &mut hits);
        self.scan_base64_view(chunk, &mut hits);

        let strictest_action = hits.iter().fold(None, |action, hit| {
            let contributed = self.library.lookup(&hit.pattern_id).map(|meta| meta.action);
            match (action, contributed) {
                (None, contributed) => contributed,
                (action, None) => action,
                (Some(a), Some(b)) => Some(ActionSet::strictest(a, b)),
            }
        });

        self.advance_tails(chunk);

        ScanReport {
            hits,
            strictest_action,
        }
    }

    /// Raw view: raw needles over `raw_tail + chunk`.
    fn scan_raw_view(&self, chunk: &[u8], hits: &mut Vec<ScanHit>) {
        let boundary = self.raw_tail.len();
        let mut stitched = Vec::with_capacity(boundary + chunk.len());
        stitched.extend_from_slice(&self.raw_tail);
        stitched.extend_from_slice(chunk);
        for entry in self.library.entries() {
            if matches_new_bytes(&stitched, entry.raw(), boundary) {
                self.push_hit(hits, entry.id(), entry.decoder(), entry.digest());
            }
        }
    }

    /// Derived-literal view: hex/base64 needles over `encoded_tail + chunk`.
    fn scan_derived_view(&self, chunk: &[u8], hits: &mut Vec<ScanHit>) {
        let boundary = self.encoded_tail.len();
        let mut stitched = Vec::with_capacity(boundary + chunk.len());
        stitched.extend_from_slice(&self.encoded_tail);
        stitched.extend_from_slice(chunk);
        for entry in self.library.entries() {
            let mut matched = false;
            entry.for_each_derived(|needle| {
                if !matched && matches_new_bytes(&stitched, needle, boundary) {
                    matched = true;
                }
            });
            if matched {
                self.push_hit(hits, entry.id(), entry.decoder(), entry.digest());
            }
        }
    }

    /// Decode views: percent-decode and JSON-unescape the stitched bytes,
    /// then match raw needles (the detector's decode-then-scan parity core).
    fn scan_decoded_views(&self, chunk: &[u8], hits: &mut Vec<ScanHit>) {
        let mut stitched = Vec::with_capacity(self.encoded_tail.len() + chunk.len());
        stitched.extend_from_slice(&self.encoded_tail);
        stitched.extend_from_slice(chunk);
        // One needle length of slop covers escapes split across the seam:
        // the tail-only decode and the stitched decode can disagree exactly
        // at the boundary, and a miss there would be an evasion hole.
        let slop = self.library.max_raw_len();
        if let Some(decoded) = percent_decoded_view(&stitched) {
            let tail_decoded_len = percent_decoded_view(&self.encoded_tail)
                .map(|tail| tail.len())
                .unwrap_or(self.encoded_tail.len());
            self.scan_decoded_into(&decoded, tail_decoded_len.saturating_sub(slop), hits);
        }
        if let Some(decoded) = json_unescaped_view(&stitched) {
            let tail_decoded_len = json_unescaped_view(&self.encoded_tail)
                .map(|tail| tail.len())
                .unwrap_or(self.encoded_tail.len());
            self.scan_decoded_into(&decoded, tail_decoded_len.saturating_sub(slop), hits);
        }
    }

    /// Match raw needles in one decoded buffer past `boundary`.
    fn scan_decoded_into(&self, decoded: &[u8], boundary: usize, hits: &mut Vec<ScanHit>) {
        for entry in self.library.entries() {
            if matches_new_bytes(decoded, entry.raw(), boundary) {
                self.push_hit(hits, entry.id(), entry.decoder(), entry.digest());
            }
        }
    }

    /// Base64-stream view: incrementally decode the chunk and match raw
    /// needles in decoded space, stitched to the decoded tail.
    fn scan_base64_view(&mut self, chunk: &[u8], hits: &mut Vec<ScanHit>) {
        let mut run = Vec::new();
        self.base64.feed(chunk, &mut run);
        if run.is_empty() {
            return;
        }
        let boundary = self.base64_tail.len();
        let mut stitched = Vec::with_capacity(boundary + run.len());
        stitched.extend_from_slice(&self.base64_tail);
        stitched.extend_from_slice(&run);
        for entry in self.library.entries() {
            if matches_new_bytes(&stitched, entry.raw(), boundary) {
                self.push_hit(hits, entry.id(), entry.decoder(), entry.digest());
            }
        }
        update_tail_buffer(&mut self.base64_tail, &run, self.library.raw_tail_cap());
    }

    /// Advance the raw and encoded tails past this chunk.
    fn advance_tails(&mut self, chunk: &[u8]) {
        update_tail_buffer(&mut self.raw_tail, chunk, self.library.raw_tail_cap());
        update_tail_buffer(
            &mut self.encoded_tail,
            chunk,
            self.library.encoded_tail_cap(),
        );
    }

    /// Record a hit unless the pattern already hit in this chunk.
    fn push_hit(
        &self,
        hits: &mut Vec<ScanHit>,
        pattern_id: PatternId,
        decoder: Decoder,
        digest: PatternDigest,
    ) {
        if hits.iter().any(|hit| hit.pattern_id == pattern_id) {
            return;
        }
        hits.push(ScanHit {
            pattern_id,
            decoder,
            digest,
        });
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::base64_needle;
    use crate::pattern::ScanPattern;

    /// Fixed test-only credential bytes (never real secrets).
    fn credential(n: u8) -> Vec<u8> {
        format!("test-credential-{n:04}-value").into_bytes()
    }

    fn library_for(count: u8) -> Arc<PatternLibrary> {
        let patterns = (0..count)
            .map(|n| {
                ScanPattern::compile(
                    format!("cred-{n}"),
                    Decoder::Raw,
                    credential(n),
                    ActionSet::passthrough(),
                )
            })
            .collect();
        let (library, excluded) = PatternLibrary::new(patterns);
        assert!(excluded.is_empty());
        library
    }

    fn scan_whole(library: &Arc<PatternLibrary>, input: &[u8]) -> ScanReport {
        ScanState::new(library).scan_chunk(input)
    }

    fn scan_split(library: &Arc<PatternLibrary>, input: &[u8], split: usize) -> Vec<ScanReport> {
        let mut state = ScanState::new(library);
        vec![
            state.scan_chunk(&input[..split]),
            state.scan_chunk(&input[split..]),
        ]
    }

    fn hit_credentials(library: &Arc<PatternLibrary>, report: &ScanReport) -> Vec<String> {
        report
            .hits
            .iter()
            .map(|hit| {
                library
                    .lookup(&hit.pattern_id)
                    .expect("hit resolves")
                    .credential_id
                    .to_string()
            })
            .collect()
    }

    //------------------------------------------------------------------------------------------
    // Parity: decode-then-scan agrees with the ported kernel on whole buffers.
    //------------------------------------------------------------------------------------------

    /// Oracle replicating the detector's decode-then-scan kernel directly:
    /// raw match, else percent-decoded match, else JSON-unescaped match.
    fn oracle_contains(input: &[u8], needle: &[u8]) -> bool {
        use crate::decode::{contains_bytes, json_unescape};
        if contains_bytes(input, needle) {
            return true;
        }
        if input.contains(&b'%') {
            let decoded: Vec<u8> = percent_encoding::percent_decode(input).collect();
            if contains_bytes(&decoded, needle) {
                return true;
            }
        }
        if input.windows(2).any(|w| w == b"\\u") {
            let decoded = json_unescape(input);
            if contains_bytes(&decoded, needle) {
                return true;
            }
        }
        false
    }

    /// Percent-encode every byte (fully-encoded form, the hardest case).
    fn percent_encode_all(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(bytes.len() * 3);
        for &b in bytes {
            out.extend_from_slice(format!("%{b:02X}").as_bytes());
        }
        out
    }

    /// JSON-escape every byte as `\u00XX`.
    fn json_escape_all(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(bytes.len() * 6);
        for &b in bytes {
            out.extend_from_slice(format!("\\u00{b:02x}").as_bytes());
        }
        out
    }

    #[test]
    fn parity_with_detector_kernel_on_shared_decoders() {
        let library = library_for(4);
        let needles: Vec<Vec<u8>> = (0..4).map(credential).collect();
        let mut inputs: Vec<Vec<u8>> = vec![b"entirely benign traffic".to_vec()];
        for needle in &needles {
            let mut raw = b"prefix ".to_vec();
            raw.extend_from_slice(needle);
            raw.extend_from_slice(b" suffix");
            inputs.push(raw);
            inputs.push(percent_encode_all(needle));
            inputs.push(json_escape_all(needle));
            // Mixed framing: encoded marker inside benign text.
            let mut mixed = b"GET /q=".to_vec();
            mixed.extend_from_slice(&percent_encode_all(needle));
            mixed.extend_from_slice(b" HTTP/1.1");
            inputs.push(mixed);
        }
        for input in &inputs {
            let report = scan_whole(&library, input);
            for (n, needle) in needles.iter().enumerate() {
                let expected = oracle_contains(input, needle);
                let got = report.hits.iter().any(|hit| {
                    library
                        .lookup(&hit.pattern_id)
                        .expect("hit resolves")
                        .credential_id
                        == format!("cred-{n}")
                });
                assert_eq!(
                    got,
                    expected,
                    "parity mismatch for cred-{n} in {}",
                    String::from_utf8_lossy(input)
                );
            }
        }
    }

    //------------------------------------------------------------------------------------------
    // Split battery: markers split at every offset, 1-byte dribble.
    //------------------------------------------------------------------------------------------

    #[test]
    fn split_battery_raw_markers_hit_at_every_offset() {
        let library = library_for(2);
        for n in 0..2 {
            let mut input = b"xx".to_vec();
            input.extend_from_slice(&credential(n));
            input.extend_from_slice(b"yy");
            for split in 0..=input.len() {
                let reports = scan_split(&library, &input, split);
                let total: usize = reports.iter().map(|r| r.hits.len()).sum();
                assert_eq!(
                    total, 1,
                    "raw marker cred-{n} split at {split}: exactly-once, got {total}"
                );
            }
        }
    }

    #[test]
    fn split_battery_base64_and_hex_markers_hit_at_every_offset() {
        let raw = credential(1);
        let markers = vec![
            base64_needle(&raw),
            hex::encode(&raw).into_bytes(),
            hex::encode(&raw).to_uppercase().into_bytes(),
        ];
        // A 20-byte credential derives hex (raw >= 12).
        assert!(raw.len() >= 12);
        let library = library_for(2);
        for marker in &markers {
            let mut input = b"xx".to_vec();
            input.extend_from_slice(marker);
            input.extend_from_slice(b"yy");
            for split in 0..=input.len() {
                let reports = scan_split(&library, &input, split);
                let found = reports.iter().any(|report| {
                    hit_credentials(&library, report).contains(&"cred-1".to_string())
                });
                assert!(
                    found,
                    "derived marker split at {split} must hit at least once: {}",
                    String::from_utf8_lossy(marker)
                );
            }
        }
    }

    #[test]
    fn dribble_battery_one_byte_chunks_find_raw_and_base64() {
        let raw = credential(0);
        let library = library_for(1);
        for input in [raw.clone(), base64_needle(&raw)] {
            let mut state = ScanState::new(&library);
            let mut total = 0;
            for byte in input.chunks(1) {
                total += state.scan_chunk(byte).hits.len();
            }
            assert!(
                total >= 1,
                "1-byte dribble must surface the marker: {}",
                String::from_utf8_lossy(&input)
            );
        }
    }

    #[test]
    fn split_battery_percent_and_json_markers_hit_at_every_offset() {
        let raw = credential(2);
        let library = library_for(3);
        for marker in [percent_encode_all(&raw), json_escape_all(&raw)] {
            let mut input = b"xx".to_vec();
            input.extend_from_slice(&marker);
            input.extend_from_slice(b"yy");
            for split in 0..=input.len() {
                let reports = scan_split(&library, &input, split);
                let found = reports.iter().any(|report| {
                    hit_credentials(&library, report).contains(&"cred-2".to_string())
                });
                assert!(
                    found,
                    "encoded marker split at {split} must hit at least once"
                );
            }
        }
    }

    #[test]
    fn base64_stream_view_finds_encoded_appearances_split_anywhere() {
        // The stream carries base64 text; the decoder view must surface the
        // raw credential even though no literal needle appears... except the
        // base64-literal needle also matches: dedupe keeps exactly one hit.
        let raw = credential(3);
        let library = library_for(4);
        let encoded = base64_needle(&raw);
        for split in 0..=encoded.len() {
            let reports = scan_split(&library, &encoded, split);
            let total: usize = reports.iter().map(|r| r.hits.len()).sum();
            assert!(
                (1..=2).contains(&total),
                "base64 stream split at {split}: one hit per view at most, got {total}"
            );
            assert!(
                reports.iter().any(|report| {
                    hit_credentials(&library, report).contains(&"cred-3".to_string())
                }),
                "base64 stream split at {split} must hit"
            );
        }
    }

    //------------------------------------------------------------------------------------------
    // Negatives, direction isolation, audit content, strictest action.
    //------------------------------------------------------------------------------------------

    #[test]
    fn benign_binary_negatives_do_not_hit() {
        let library = library_for(4);
        let benign: Vec<Vec<u8>> = vec![
            vec![0u8; 256],
            (0..=255u8).cycle().take(512).collect(),
            b"\xff\xfe\x00\x01 binary \x00\x01\x02 noise".to_vec(),
            format!("test-credential-9999-value").into_bytes(),
            // Truncated credential prefix: below-length fragments must not hit.
            credential(0)[..8].to_vec(),
        ];
        for input in &benign {
            let report = scan_whole(&library, input);
            assert!(
                report.hits.is_empty(),
                "benign input must not hit: {}",
                String::from_utf8_lossy(input)
            );
        }
    }

    #[test]
    fn truncated_fragments_below_threshold_never_hit() {
        let library = library_for(1);
        let raw = credential(0);
        // Every strict prefix shorter than the full credential misses when
        // fed whole (the full 22-byte marker is the only needle).
        for len in [7, 8, 15, raw.len() - 1] {
            let report = scan_whole(&library, &raw[..len]);
            assert!(report.hits.is_empty(), "prefix of {len} bytes must not hit");
        }
        assert_eq!(scan_whole(&library, &raw).hits.len(), 1);
    }

    #[test]
    fn cross_direction_states_do_not_stitch() {
        // Two directions each see half the marker: neither may hit, proving
        // tails never cross between ScanStates.
        let library = library_for(1);
        let raw = credential(0);
        let split = raw.len() / 2;
        let mut request = ScanState::new(&library);
        let mut response = ScanState::new(&library);
        assert!(request.scan_chunk(&raw[..split]).hits.is_empty());
        assert!(response.scan_chunk(&raw[split..]).hits.is_empty());
        // And the halves in the wrong order still miss on a fresh state.
        let mut fresh = ScanState::new(&library);
        assert!(fresh.scan_chunk(&raw[split..]).hits.is_empty());
        assert!(fresh.scan_chunk(&raw[..split]).hits.is_empty());
    }

    #[test]
    fn audit_records_carry_ids_and_digests_never_content() {
        let raw = credential(1);
        let library = library_for(2);
        let report = scan_whole(&library, &raw);
        assert_eq!(report.hits.len(), 1);
        let hit = report.hits[0];
        let meta = library.lookup(&hit.pattern_id).expect("hit resolves");
        assert_eq!(meta.credential_id, "cred-1");
        assert_eq!(hit.digest, crate::pattern::PatternDigest::of_raw(&raw));
        // Render everything a log line could carry; the secret must not appear.
        let rendered = format!(
            "{} {} {} {:?} {:?}",
            hit.pattern_id, hit.digest, meta.credential_id, hit.decoder, report.strictest_action
        );
        assert!(!rendered.contains(&*String::from_utf8_lossy(&raw)));
        assert!(rendered.contains(&hit.pattern_id.to_hex()));
    }

    #[test]
    fn strictest_action_folds_contributing_actions() {
        use crate::pattern::ScanPattern;
        let blocking = ActionSet {
            enforce: Some(crate::action::Severity::Block),
            audit: false,
            count: true,
        };
        let logging = ActionSet {
            enforce: Some(crate::action::Severity::BlockAndLog),
            audit: true,
            count: false,
        };
        let patterns = vec![
            ScanPattern::compile("a".to_string(), Decoder::Raw, credential(0), blocking),
            ScanPattern::compile("b".to_string(), Decoder::Raw, credential(1), logging),
        ];
        let (library, _) = PatternLibrary::new(patterns);
        let mut input = credential(0);
        input.extend_from_slice(&credential(1));
        let report = scan_whole(&library, &input);
        assert_eq!(report.hits.len(), 2);
        let strictest = report.strictest_action.expect("hits reduce to an action");
        // Block outranks block-and-log; flags union.
        assert_eq!(strictest.enforce, Some(crate::action::Severity::Block));
        assert!(strictest.audit);
        assert!(strictest.count);
    }

    #[test]
    fn empty_report_carries_no_action() {
        let library = library_for(1);
        let report = scan_whole(&library, b"benign");
        assert!(report.hits.is_empty());
        assert_eq!(report.strictest_action, None);
    }
}
