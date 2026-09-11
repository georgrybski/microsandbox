//! Streaming SSH identification-string classifier.
//!
//! Recognizes plaintext SSH banners (`SSH-2.0-...`, `SSH-1.99-...`) as
//! exchanged before key exchange (RFC 4253 section 4.2), tolerating TCP
//! segmentation. Feed guest first-flight bytes or the server banner in
//! arrival order; the classifier buffers a bounded prefix and reports
//! [`SshClassification::Ssh`] as soon as a line-start banner completes.
//!
//! ## Limits
//!
//! This classifier only sees plaintext identification strings. It cannot
//! detect SSH inside encrypted or tunneled payloads (TLS records, HTTP
//! CONNECT tunnels, or the encrypted key-exchange and session that
//! follow the banner). Callers must feed the pre-key-exchange bytes;
//! ciphertext after key exchange never matches and stays
//! [`SshClassification::NotSsh`] or
//! [`SshClassification::NeedMoreData`].
//!
//! Banner matching is anchored to line starts: a banner counts only when
//! `SSH-2.0-` or `SSH-1.99-` opens a line (stream start or immediately
//! after `\n`). An `SSH-2.0-` substring inside another line never
//! classifies as SSH.

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Bounded buffer for the streaming matcher.
///
/// Covers a few comment lines plus the identification string (which is at
/// most 255 bytes including `CRLF` per RFC 4253 section 4.2). Once the
/// buffer would exceed this, the classifier decides
/// [`SshClassification::NotSsh`] rather than growing without bound.
pub const MAX_SSH_CLASSIFIER_BYTES: usize = 1024;

/// Maximum complete non-banner lines tolerated before deciding
/// [`SshClassification::NotSsh`].
///
/// Counts only lines that are not accepted banners: up to eight comment
/// lines may precede the banner, so a banner on the ninth line still
/// classifies as SSH. The ninth non-banner line decides `NotSsh`.
/// This bounds how long plain HTTP and other text protocols stay in
/// [`SshClassification::NeedMoreData`].
pub const MAX_SSH_PRELUDE_LINES: usize = 8;

/// Maximum bytes for a single line (excluding the terminating `\n`).
///
/// Longer lines cannot be SSH banners or short comments; they decide
/// [`SshClassification::NotSsh`].
pub const MAX_SSH_LINE_BYTES: usize = 512;

/// Accepted banner prefix for SSH 2.0.
const SSH_20_PREFIX: &[u8] = b"SSH-2.0-";

/// Accepted banner prefix for compatibility-mode servers.
const SSH_199_PREFIX: &[u8] = b"SSH-1.99-";

/// Generic SSH line marker, used to fail unsupported versions fast.
const SSH_PREFIX: &[u8] = b"SSH-";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Outcome of an SSH banner evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshClassification {
    /// A line-start `SSH-2.0-...` or `SSH-1.99-...` banner completed.
    Ssh,
    /// The buffered prefix cannot become an SSH banner.
    NotSsh,
    /// The buffered prefix is still compatible with a future banner;
    /// feed more bytes (or treat as unclassified on timeout).
    NeedMoreData,
}

/// Incremental matcher for SSH identification strings.
///
/// Buffers up to [`MAX_SSH_CLASSIFIER_BYTES`] and evaluates after each
/// [`SshClassifier::feed`]. Decisions are sticky: once
/// [`SshClassification::Ssh`] or [`SshClassification::NotSsh`] is
/// reached, later feeds return the same value so a mid-stream
/// `SSH-2.0-` substring cannot flip the verdict.
///
/// One instance classifies one direction of one connection: create a fresh
/// [`SshClassifier`] per direction (guest flight and server banner get
/// separate instances fed in arrival order) and do not reuse an instance
/// across connections. [`SshClassifier::reset`] exists only for tests that
/// recycle an instance; production code constructs a new classifier per
/// direction per connection so buffered bytes and sticky verdicts never
/// leak across flows.
#[derive(Debug, Clone, Default)]
pub struct SshClassifier {
    buf: Vec<u8>,
    decided: Option<SshClassification>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SshClassification {
    /// Returns `true` when the flow is classified as SSH.
    pub fn is_ssh(self) -> bool {
        matches!(self, SshClassification::Ssh)
    }

    /// Returns `true` when the classifier reached a terminal verdict
    /// ([`SshClassification::Ssh`] or [`SshClassification::NotSsh`]).
    pub fn is_decided(self) -> bool {
        matches!(self, SshClassification::Ssh | SshClassification::NotSsh)
    }
}

impl SshClassifier {
    /// Create an empty classifier.
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed the next chunk in arrival order and return the current verdict.
    ///
    /// Chunk boundaries do not matter: a banner split across TCP
    /// segments (for example `"SSH-2.0-O"` followed by `"penSSH_9..."`)
    /// classifies once the banner line completes. Sticky decisions
    /// mean a later `SSH-2.0-` substring cannot override an earlier
    /// [`SshClassification::NotSsh`].
    pub fn feed(&mut self, chunk: &[u8]) -> SshClassification {
        if let Some(decided) = self.decided {
            return decided;
        }
        let remaining = MAX_SSH_CLASSIFIER_BYTES.saturating_sub(self.buf.len());
        if chunk.len() > remaining {
            self.buf.extend_from_slice(&chunk[..remaining]);
            self.decided = Some(SshClassification::NotSsh);
            return SshClassification::NotSsh;
        }
        self.buf.extend_from_slice(chunk);
        let verdict = evaluate_buffer(&self.buf);
        if verdict.is_decided() {
            self.decided = Some(verdict);
        }
        verdict
    }

    /// Re-evaluate the buffered prefix without adding bytes.
    ///
    /// Useful on timeout or EOF: a lingering
    /// [`SshClassification::NeedMoreData`] means the banner never
    /// completed, and the caller should treat the flow as unclassified
    /// (fall back to the generic egress policy).
    pub fn classification(&self) -> SshClassification {
        if let Some(decided) = self.decided {
            return decided;
        }
        evaluate_buffer(&self.buf)
    }

    /// Clear buffered bytes and any sticky verdict for reuse.
    ///
    /// Production code prefers a fresh [`SshClassifier`] per direction per
    /// connection; reuse via `reset` is a test convenience. A reset
    /// instance must still serve only one direction of one connection at
    /// a time, since buffered bytes and the sticky verdict are
    /// direction-specific.
    pub fn reset(&mut self) {
        self.buf.clear();
        self.decided = None;
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// One-shot helper for complete buffers.
///
/// Equivalent to feeding `data` to a fresh [`SshClassifier`] once.
/// Chunked streams should use [`SshClassifier::feed`] instead.
pub fn classify_ssh_bytes(data: &[u8]) -> SshClassification {
    let mut classifier = SshClassifier::new();
    classifier.feed(data)
}

/// Returns `true` when the trailing line fragment could still grow into
/// a line-start SSH banner.
///
/// Holds the peek only while the whole buffer is still
/// [`SshClassification::NeedMoreData`] and the bytes after the last `\n`
/// stay banner-compatible: either a strict prefix of `SSH_20_PREFIX` or
/// `SSH_199_PREFIX` (for example `SSH-2.0-O` split across TCP segments)
/// or one of those prefixes followed by printable banner bytes (a banner
/// split past the prefix). A completed first line, binary bytes, or a
/// diverged prefix (`SSH-foo`) fall through immediately. The proxy uses
/// this so a segmented client banner still settles instead of falling
/// through on the first chunk, without stalling non-SSH flows.
pub fn trailing_fragment_is_banner_prefix(buf: &[u8]) -> bool {
    if evaluate_buffer(buf) != SshClassification::NeedMoreData {
        return false;
    }
    let fragment = match buf.iter().rposition(|b| *b == b'\n') {
        Some(pos) => &buf[pos + 1..],
        None => buf,
    };
    if fragment.is_empty() {
        return false;
    }
    if SSH_20_PREFIX.starts_with(fragment) || SSH_199_PREFIX.starts_with(fragment) {
        return true;
    }
    [SSH_20_PREFIX, SSH_199_PREFIX].iter().any(|prefix| {
        fragment.len() > prefix.len()
            && fragment.starts_with(prefix)
            && fragment[prefix.len()..]
                .iter()
                .all(|b| (0x20..=0x7e).contains(b))
    })
}

/// Evaluate the buffered prefix.
fn evaluate_buffer(buf: &[u8]) -> SshClassification {
    if buf.is_empty() {
        return SshClassification::NeedMoreData;
    }
    if buf.contains(&0x00) {
        return SshClassification::NotSsh;
    }
    if starts_with_http_or_tls_magic(buf) {
        return SshClassification::NotSsh;
    }
    if buf.len() > MAX_SSH_CLASSIFIER_BYTES {
        return SshClassification::NotSsh;
    }

    // Count only non-banner complete lines: the banner itself never counts
    // toward the prelude budget, so eight comment lines plus a banner on
    // the ninth line still classifies as SSH.
    let mut non_banner_lines = 0usize;
    let mut start = 0usize;
    while let Some(rel) = buf[start..].iter().position(|b| *b == b'\n') {
        let line = &buf[start..start + rel];
        let line = strip_cr(line);
        if line.len() > MAX_SSH_LINE_BYTES {
            return SshClassification::NotSsh;
        }
        if line_is_ssh_banner(line) {
            return SshClassification::Ssh;
        }
        non_banner_lines += 1;
        if non_banner_lines > MAX_SSH_PRELUDE_LINES {
            return SshClassification::NotSsh;
        }
        if line_starts_with(line, SSH_PREFIX) {
            return SshClassification::NotSsh;
        }
        start += rel + 1;
    }

    let trailing = &buf[start..];
    if !trailing.is_empty() {
        if trailing.len() > MAX_SSH_LINE_BYTES {
            return SshClassification::NotSsh;
        }
        if line_starts_with(strip_cr(trailing), SSH_PREFIX)
            && !is_prefix_of_ssh_banner(strip_cr(trailing))
            && trailing.contains(&b'\r')
        {
            return SshClassification::NotSsh;
        }
    }

    SshClassification::NeedMoreData
}

/// Returns `true` when `line` (without its `\n`) is an accepted banner.
fn line_is_ssh_banner(line: &[u8]) -> bool {
    let banner = line_starts_with(line, SSH_20_PREFIX) || line_starts_with(line, SSH_199_PREFIX);
    if !banner {
        return false;
    }
    let prefix_len = if line_starts_with(line, SSH_20_PREFIX) {
        SSH_20_PREFIX.len()
    } else {
        SSH_199_PREFIX.len()
    };
    let rest = &line[prefix_len..];
    if rest.is_empty() {
        return false;
    }
    rest.iter().all(|b| (0x20..=0x7e).contains(b))
}

/// Returns `true` when `line` could still grow into an accepted banner.
///
/// Used only for the trailing incomplete fragment so a split prefix
/// such as `SSH-2.0-O` stays [`SshClassification::NeedMoreData`].
fn is_prefix_of_ssh_banner(fragment: &[u8]) -> bool {
    SSH_20_PREFIX.starts_with(fragment) || SSH_199_PREFIX.starts_with(fragment)
}

/// Strip a single trailing `\r` for `CRLF` tolerance.
fn strip_cr(line: &[u8]) -> &[u8] {
    if line.last() == Some(&b'\r') {
        &line[..line.len() - 1]
    } else {
        line
    }
}

/// Byte-prefix check without allocating.
fn line_starts_with(line: &[u8], prefix: &[u8]) -> bool {
    line.len() >= prefix.len() && &line[..prefix.len()] == prefix
}

/// Early bail for definitive non-SSH first flights.
///
/// TLS handshakes start with `0x16` and plain HTTP starts with a
/// request method or `HTTP/`; neither can become a line-start SSH
/// banner. Partial prefixes such as `GE` stay
/// [`SshClassification::NeedMoreData`] until they resolve or diverge.
fn starts_with_http_or_tls_magic(buf: &[u8]) -> bool {
    if buf.first() == Some(&0x16) {
        return true;
    }
    const METHODS: &[&[u8]] = &[
        b"GET ",
        b"POST ",
        b"PUT ",
        b"DELETE ",
        b"HEAD ",
        b"OPTIONS ",
        b"PATCH ",
        b"TRACE ",
        b"CONNECT ",
        b"HTTP/",
    ];
    METHODS.iter().any(|m| line_starts_with(buf, m))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn feed_chunks(chunks: &[&[u8]]) -> SshClassification {
        let mut classifier = SshClassifier::new();
        let mut verdict = SshClassification::NeedMoreData;
        for chunk in chunks {
            verdict = classifier.feed(chunk);
        }
        verdict
    }

    #[test]
    fn exact_banner_classifies_as_ssh() {
        assert_eq!(
            classify_ssh_bytes(b"SSH-2.0-OpenSSH_9.6\r\n"),
            SshClassification::Ssh
        );
        assert_eq!(
            classify_ssh_bytes(b"SSH-1.99-OpenSSH_9.6\r\n"),
            SshClassification::Ssh
        );
    }

    #[test]
    fn banner_without_cr_classifies_as_ssh() {
        assert_eq!(
            classify_ssh_bytes(b"SSH-2.0-OpenSSH_9.6\n"),
            SshClassification::Ssh
        );
    }

    #[test]
    fn chunked_banner_two_way_split_classifies() {
        assert_eq!(
            feed_chunks(&[b"SSH-2.0-O", b"penSSH_9.6\r\n"]),
            SshClassification::Ssh
        );
    }

    #[test]
    fn chunked_banner_three_way_split_classifies() {
        assert_eq!(
            feed_chunks(&[b"SSH-", b"2.0-Open", b"SSH_9.6\r\n"]),
            SshClassification::Ssh
        );
    }

    #[test]
    fn chunked_banner_five_way_split_classifies() {
        assert_eq!(
            feed_chunks(&[b"S", b"S", b"H-2.0-", b"OpenSSH", b"_9.6\r\n"]),
            SshClassification::Ssh
        );
    }

    #[test]
    fn partial_banner_stays_need_more_data() {
        let mut classifier = SshClassifier::new();
        assert_eq!(
            classifier.feed(b"SSH-2.0-O"),
            SshClassification::NeedMoreData
        );
        assert_eq!(classifier.feed(b"penSSH_9.6\r\n"), SshClassification::Ssh);
    }

    #[test]
    fn banner_with_comment_lines_classifies_as_ssh() {
        assert_eq!(
            classify_ssh_bytes(b"Welcome to the server\r\nSSH-2.0-OpenSSH_9.6\r\n"),
            SshClassification::Ssh
        );
    }

    #[test]
    fn banner_with_split_comment_lines_classifies() {
        assert_eq!(
            feed_chunks(&[b"Welcome\r\nSSH-2.0-", b"OpenSSH_9.6\r\n"]),
            SshClassification::Ssh
        );
    }

    #[test]
    fn mid_line_prefix_does_not_false_positive() {
        let verdict = classify_ssh_bytes(b"HELLO SSH-2.0-OpenSSH_9.6\r\n");
        assert!(
            !verdict.is_ssh(),
            "mid-line SSH- prefix must not classify as SSH, got {verdict:?}"
        );
    }

    #[test]
    fn http_first_flight_is_not_ssh() {
        assert_eq!(
            classify_ssh_bytes(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
            SshClassification::NotSsh
        );
    }

    #[test]
    fn tls_first_flight_is_not_ssh() {
        assert_eq!(
            classify_ssh_bytes(&[0x16, 0x03, 0x01, 0x00, 0x05, 0x01]),
            SshClassification::NotSsh
        );
    }

    #[test]
    fn unsupported_ssh_version_is_not_ssh() {
        assert_eq!(
            classify_ssh_bytes(b"SSH-1.5-OpenSSH_9.6\r\n"),
            SshClassification::NotSsh
        );
    }

    #[test]
    fn incomplete_banner_without_newline_needs_more_data() {
        assert_eq!(
            classify_ssh_bytes(b"SSH-2.0-OpenSSH_9.6"),
            SshClassification::NeedMoreData
        );
        assert_eq!(classify_ssh_bytes(b""), SshClassification::NeedMoreData);
        assert_eq!(
            classify_ssh_bytes(b"SSH-2.0-"),
            SshClassification::NeedMoreData
        );
    }

    #[test]
    fn sticky_not_ssh_ignores_later_banner() {
        let mut classifier = SshClassifier::new();
        assert_eq!(
            classifier.feed(b"GET / HTTP/1.1\r\n"),
            SshClassification::NotSsh
        );
        assert_eq!(
            classifier.feed(b"SSH-2.0-OpenSSH_9.6\r\n"),
            SshClassification::NotSsh,
            "mid-stream banner after a decided verdict must not flip to Ssh"
        );
    }

    #[test]
    fn oversized_buffer_is_not_ssh() {
        let big = vec![b'A'; MAX_SSH_CLASSIFIER_BYTES + 1];
        assert_eq!(classify_ssh_bytes(&big), SshClassification::NotSsh);
    }

    #[test]
    fn eight_comment_lines_then_banner_still_classifies_as_ssh() {
        let mut buf = Vec::new();
        for i in 0..MAX_SSH_PRELUDE_LINES {
            buf.extend_from_slice(format!("comment-{i}\r\n").as_bytes());
        }
        buf.extend_from_slice(b"SSH-2.0-OpenSSH_9.6\r\n");
        assert_eq!(
            classify_ssh_bytes(&buf),
            SshClassification::Ssh,
            "eight non-banner lines plus a banner must still classify as SSH"
        );
    }

    #[test]
    fn ninth_non_banner_line_decides_not_ssh() {
        let mut buf = Vec::new();
        for i in 0..=MAX_SSH_PRELUDE_LINES {
            buf.extend_from_slice(format!("comment-{i}\r\n").as_bytes());
        }
        buf.extend_from_slice(b"SSH-2.0-OpenSSH_9.6\r\n");
        assert_eq!(
            classify_ssh_bytes(&buf),
            SshClassification::NotSsh,
            "nine non-banner lines exhaust the prelude budget before the banner"
        );
    }

    #[test]
    fn trailing_banner_prefix_holds_only_partial_prefixes() {
        assert!(trailing_fragment_is_banner_prefix(b"SSH-2.0-O"));
        assert!(trailing_fragment_is_banner_prefix(b"S"));
        assert!(trailing_fragment_is_banner_prefix(b"SSH-1.99"));
        assert!(trailing_fragment_is_banner_prefix(b"SSH-2.0-OpenSSH_9.6"));
        // Decided buffers never hold the peek, even with a banner-like tail.
        assert!(!trailing_fragment_is_banner_prefix(b""));
        assert!(!trailing_fragment_is_banner_prefix(
            b"SSH-2.0-OpenSSH_9.6\r\n"
        ));
        assert!(!trailing_fragment_is_banner_prefix(b"PING\r\n"));
        assert!(!trailing_fragment_is_banner_prefix(b"SSH-foo"));
        assert!(!trailing_fragment_is_banner_prefix(b"GET / HTTP/1.1\r\n"));
        assert!(!trailing_fragment_is_banner_prefix(&[0x01, 0x02, 0x03]));
        // A completed line followed by a fresh partial prefix still holds:
        // only the trailing fragment matters.
        assert!(trailing_fragment_is_banner_prefix(b"comment\r\nSSH-2.0-"));
    }

    #[test]
    fn reset_clears_sticky_verdict_for_test_reuse() {
        let mut classifier = SshClassifier::new();
        assert_eq!(
            classifier.feed(b"GET / HTTP/1.1\r\n"),
            SshClassification::NotSsh
        );
        classifier.reset();
        assert_eq!(
            classifier.feed(b"SSH-2.0-OpenSSH_9.6\r\n"),
            SshClassification::Ssh,
            "reset must clear the sticky verdict so a recycled test instance behaves fresh"
        );
    }
}
