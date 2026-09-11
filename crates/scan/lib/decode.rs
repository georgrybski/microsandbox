//! Ported detection primitives and streaming base64 decoding.
//!
//! `contains_bytes`, `update_tail_buffer`, the 6x encoded-expansion bound,
//! percent decoding, and `json_unescape` are faithful ports of the HTTP
//! secret-substitution detector's kernel
//! (`crates/network/lib/secrets/handler.rs`). [`Base64StreamDecoder`]
//! adds the incremental base64 view the detector has no equivalent for:
//! SSH byte streams have no message framing to decode inside, so secrets
//! that arrive base64-encoded are caught by decoding the stream itself.

use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STD};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Incremental base64-stream decoder: 4-character alignment plus padding state.
///
/// Holds at most three pending alphabet characters between chunks; each
/// complete quartet decodes immediately into the caller's output. Any byte
/// outside the base64 alphabet (and misplaced padding) ends the current
/// run: the partial quartet is undecodable and dropped, and alignment
/// restarts after the break. A padded quartet always ends its run, so
/// fresh alphabet characters after padding start a new run.
#[derive(Debug, Default)]
pub struct Base64StreamDecoder {
    /// Pending alphabet characters toward the next quartet.
    quad: [u8; 4],

    /// How many of `quad` are filled (0..4, never 4 across calls).
    quad_len: u8,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Base64StreamDecoder {
    /// Create an empty decoder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one chunk, appending newly decoded bytes to `out`.
    pub fn feed(&mut self, chunk: &[u8], out: &mut Vec<u8>) {
        for &byte in chunk {
            if byte == b'=' {
                self.feed_padding(out);
            } else if decode_char(byte).is_some() {
                self.feed_alphabet(byte, out);
            } else {
                // Outside the alphabet: the run ends and the partial
                // quartet is undecodable, so alignment restarts clean.
                self.quad_len = 0;
            }
        }
    }

    /// Feed one alphabet character (padding handled separately).
    fn feed_alphabet(&mut self, byte: u8, out: &mut Vec<u8>) {
        let len = self.quad_len as usize;
        debug_assert!(len < 4);
        self.quad[len] = byte;
        self.quad_len += 1;
        if self.quad_len == 4 {
            // A complete quartet holds no padding (padding arrives via
            // `feed_padding`), so all four characters map to sextets.
            let sextets = [
                decode_char(self.quad[0]).unwrap_or(0),
                decode_char(self.quad[1]).unwrap_or(0),
                decode_char(self.quad[2]).unwrap_or(0),
                decode_char(self.quad[3]).unwrap_or(0),
            ];
            out.push((sextets[0] << 2) | (sextets[1] >> 4));
            out.push((sextets[1] << 4) | (sextets[2] >> 2));
            out.push((sextets[2] << 6) | sextets[3]);
            self.quad_len = 0;
        }
    }

    /// Feed one padding character: only valid closing a quartet.
    ///
    /// `XX==` decodes to one byte and `XXX=` to two; anything else is a
    /// misplaced pad, so the run is dropped. Padding always ends the run.
    fn feed_padding(&mut self, out: &mut Vec<u8>) {
        let len = self.quad_len as usize;
        self.quad[len] = b'=';
        self.quad_len += 1;
        if self.quad_len < 2 {
            // Padding in the first two quartet positions can never close a
            // quantum; drop the run.
            self.quad_len = 0;
            return;
        }
        if self.quad_len == 4 {
            let (a, b, c, d) = (self.quad[0], self.quad[1], self.quad[2], self.quad[3]);
            if c == b'=' && d == b'=' {
                if let (Some(a), Some(b)) = (decode_char(a), decode_char(b)) {
                    out.push((a << 2) | (b >> 4));
                }
            } else if d == b'='
                && c != b'='
                && let (Some(a), Some(b), Some(c)) =
                    (decode_char(a), decode_char(b), decode_char(c))
            {
                out.push((a << 2) | (b >> 4));
                out.push((b << 4) | (c >> 2));
            }
            // Whether or not the pad closed a valid quantum, the run ends
            // here: fresh alphabet characters start a new run.
            self.quad_len = 0;
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Byte-slice substring check (port of the detector's `contains_bytes`).
pub(crate) fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// True when `haystack` holds `needle` with a match ending past `boundary`.
///
/// `boundary` is the length of the carried tail inside `haystack`; matches
/// fully inside the tail were already reported on an earlier chunk, so only
/// matches touching new bytes report. This is what makes streaming
/// detection exactly-once per view.
pub(crate) fn matches_new_bytes(haystack: &[u8], needle: &[u8], boundary: usize) -> bool {
    if !contains_bytes(haystack, needle) {
        return false;
    }
    haystack
        .windows(needle.len())
        .enumerate()
        .any(|(pos, w)| w == needle && pos + needle.len() > boundary)
}

/// Longest encoded representation the detector may need to carry across
/// chunk boundaries for a raw credential of `raw_len` bytes.
///
/// Port of the detector's `max_placeholder_detection_len`: percent
/// encoding expands one byte to three (`%XX`) and JSON unicode escaping
/// expands one byte to six (`\u00XX`), so six is the governing bound. The
/// same bound covers the derived literal needles (hex at 2x, base64 at
/// 4/3x), which is why the encoded tail backs those views too.
pub(crate) fn max_encoded_detection_len(raw_len: usize) -> usize {
    raw_len.saturating_mul(6)
}

/// Slide the carry window: keep the last `tail_size` bytes of `tail + data`.
///
/// Port of the detector's `update_tail_buffer`.
pub(crate) fn update_tail_buffer(tail: &mut Vec<u8>, data: &[u8], tail_size: usize) {
    if tail_size == 0 {
        tail.clear();
        return;
    }
    if data.len() >= tail_size {
        tail.clear();
        tail.extend_from_slice(&data[data.len() - tail_size..]);
        return;
    }
    tail.extend_from_slice(data);
    let overflow = tail.len().saturating_sub(tail_size);
    if overflow > 0 {
        tail.drain(..overflow);
    }
}

/// Percent-decode `bytes` when it may hold `%XX` escapes.
///
/// Returns `None` without allocating when there is no `%`, mirroring the
/// detector's `.contains(&b'%').then(...)` gate.
pub(crate) fn percent_decoded_view(bytes: &[u8]) -> Option<Vec<u8>> {
    bytes
        .contains(&b'%')
        .then(|| percent_encoding::percent_decode(bytes).collect::<Vec<u8>>())
}

/// JSON-unescape `bytes` when it may hold `\uXXXX` escapes.
///
/// Returns `None` without allocating when there is no `\u`, mirroring the
/// detector's window gate.
pub(crate) fn json_unescaped_view(bytes: &[u8]) -> Option<Vec<u8>> {
    bytes
        .windows(2)
        .any(|window| window == b"\\u")
        .then(|| json_unescape(bytes))
}

/// Decode JSON `\uXXXX` escapes in a byte slice.
///
/// Port of the detector's `json_unescape`: only `\uXXXX` escapes expand
/// (sufficient for ASCII credentials hidden via unicode escapes); other
/// JSON escapes pass through.
pub(crate) fn json_unescape(haystack: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::with_capacity(haystack.len());
    let mut i = 0;
    while i < haystack.len() {
        if haystack[i] == b'\\'
            && i + 5 < haystack.len()
            && haystack[i + 1] == b'u'
            && let (Some(a), Some(b), Some(c), Some(d)) = (
                hex_digit(haystack[i + 2]),
                hex_digit(haystack[i + 3]),
                hex_digit(haystack[i + 4]),
                hex_digit(haystack[i + 5]),
            )
        {
            let cp = ((a as u32) << 12) | ((b as u32) << 8) | ((c as u32) << 4) | (d as u32);
            if let Some(ch) = char::from_u32(cp) {
                let mut buf = [0u8; 4];
                decoded.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
            }
            i += 6;
            continue;
        }
        decoded.push(haystack[i]);
        i += 1;
    }
    decoded
}

/// One hexadecimal digit value (port of the detector's `hex_digit`).
pub(crate) fn hex_digit(b: u8) -> Option<u8> {
    (b as char).to_digit(16).map(|d| d as u8)
}

/// Standard-base64 encode raw credential bytes into a literal needle.
pub(crate) fn base64_needle(raw: &[u8]) -> Vec<u8> {
    BASE64_STD.encode(raw).into_bytes()
}

/// Decode base64-authored pattern bytes into raw credential bytes.
pub(crate) fn decode_authored_base64(bytes: &[u8]) -> Option<Vec<u8>> {
    BASE64_STD.decode(bytes).ok()
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// One base64 sextet value, or `None` outside the alphabet.
fn decode_char(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tail_buffer_keeps_the_trailing_window() {
        let mut tail = Vec::new();
        update_tail_buffer(&mut tail, b"abcdef", 3);
        assert_eq!(tail, b"def");
        update_tail_buffer(&mut tail, b"gh", 3);
        assert_eq!(tail, b"fgh");
        update_tail_buffer(&mut tail, b"", 3);
        assert_eq!(tail, b"fgh");
        update_tail_buffer(&mut tail, b"anything", 0);
        assert!(tail.is_empty());
    }

    #[test]
    fn matches_new_bytes_suppresses_tail_only_hits() {
        let haystack = b"xxSECRETxx";
        assert!(matches_new_bytes(haystack, b"SECRET", 0));
        assert!(matches_new_bytes(haystack, b"SECRET", 2));
        // A match fully inside the 8-byte tail does not re-report.
        assert!(!matches_new_bytes(haystack, b"SECRET", 8));
        // A match straddling the seam still reports.
        assert!(matches_new_bytes(haystack, b"SECRET", 7));
        assert!(!matches_new_bytes(haystack, b"MISSING", 0));
        assert!(!matches_new_bytes(b"short", b"much-longer-needle", 0));
    }

    #[test]
    fn encoded_bound_is_six_times_raw() {
        assert_eq!(max_encoded_detection_len(8), 48);
        assert_eq!(max_encoded_detection_len(0), 0);
    }

    #[test]
    fn percent_view_gates_on_percent_and_decodes() {
        assert!(percent_decoded_view(b"plain").is_none());
        assert_eq!(percent_decoded_view(b"%41%42"), Some(b"AB".to_vec()));
        // Invalid escapes pass through, mirroring the detector.
        assert!(percent_decoded_view(b"100%").is_some());
    }

    #[test]
    fn json_view_gates_on_backslash_u_and_unescapes() {
        assert!(json_unescaped_view(b"plain").is_none());
        assert_eq!(json_unescaped_view(b"\\u0041\\u0042"), Some(b"AB".to_vec()));
        assert_eq!(
            json_unescaped_view(b"a\\nTab\\u0041"),
            Some(b"a\\nTabA".to_vec())
        );
    }

    #[test]
    fn base64_stream_decoder_handles_alignment_and_padding() {
        // "credential-1" split at every 4-char alignment offset.
        let encoded = BASE64_STD.encode(b"credential-1").into_bytes();
        for split in 0..encoded.len() {
            let mut decoder = Base64StreamDecoder::new();
            let mut out = Vec::new();
            decoder.feed(&encoded[..split], &mut out);
            decoder.feed(&encoded[split..], &mut out);
            assert_eq!(out, b"credential-1", "split at {split}");
        }
    }

    #[test]
    fn base64_stream_decoder_dribbles_one_byte_at_a_time() {
        let encoded = BASE64_STD.encode(b"credential-1").into_bytes();
        let mut decoder = Base64StreamDecoder::new();
        let mut out = Vec::new();
        for byte in &encoded {
            decoder.feed(std::slice::from_ref(byte), &mut out);
        }
        assert_eq!(out, b"credential-1");
    }

    #[test]
    fn base64_stream_decoder_resets_runs_on_non_alphabet_bytes() {
        // base64("cred") is "Y3JlZA==": "Y3Jl" decodes to "cre" before the
        // space, the space ends the run, and "ZA==" decodes to "d" after it.
        assert_eq!(BASE64_STD.encode(b"cred"), "Y3JlZA==");
        let mut decoder = Base64StreamDecoder::new();
        let mut out = Vec::new();
        decoder.feed(b"Y3Jl ZA==", &mut out);
        assert_eq!(out, b"cred");
        // A partial quartet dropped at the break never decodes.
        let mut decoder = Base64StreamDecoder::new();
        let mut out = Vec::new();
        decoder.feed(b"Y3 JlZA==", &mut out);
        assert_ne!(out, b"cred");
    }

    #[test]
    fn base64_stream_decoder_handles_padding_split_across_chunks() {
        // 13 raw bytes encode to 20 chars ending in "=="; split everywhere.
        let encoded = BASE64_STD.encode(b"thirteen-byte").into_bytes();
        assert!(encoded.ends_with(b"=="));
        for split in 0..encoded.len() {
            let mut decoder = Base64StreamDecoder::new();
            let mut out = Vec::new();
            decoder.feed(&encoded[..split], &mut out);
            decoder.feed(&encoded[split..], &mut out);
            assert_eq!(out, b"thirteen-byte", "padding split at {split}");
        }
    }

    #[test]
    fn base64_stream_decoder_handles_single_pad_quantum() {
        // 8 raw bytes encode to 12 chars ending in one pad.
        let encoded = BASE64_STD.encode(b"12345678").into_bytes();
        assert!(encoded.ends_with(b"=") && !encoded.ends_with(b"=="));
        let mut decoder = Base64StreamDecoder::new();
        let mut out = Vec::new();
        decoder.feed(&encoded[..11], &mut out);
        decoder.feed(&encoded[11..], &mut out);
        assert_eq!(out, b"12345678");
    }
}
