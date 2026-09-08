//! Realistic-corpus false-positive battery for credential matching.
//!
//! [`battery_library`] enrolls 32-byte test-only credentials (raw,
//! base64-authored, and hex-text forms) plus length-boundary tokens at the
//! admission threshold, all with enforcing actions. [`fixtures`] holds
//! everyday SSH channel content — shell transcripts, tool output,
//! base64/PEM-adjacent text, binary payloads, and percent/JSON/base64
//! encoded traffic — scanned through fresh per-direction [`ScanState`]s
//! whole and midpoint-split. The battery asserts the enrolled credentials
//! never hit benign traffic while still detecting their own forms, pinning
//! the evidence behind keeping response-side enforcement audit-only by
//! default.
//!
//! [`ScanState`]: crate::scan::ScanState

use std::sync::Arc;

use crate::action::{ActionSet, Severity};
use crate::decode::base64_needle;
use crate::library::{MIN_RAW_BYTES, PatternLibrary};
use crate::pattern::{Decoder, ExclusionReason, PatternExclusion, ScanPattern};
use crate::scan::{ScanReport, ScanState};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Fixed test-only credential bytes (never real secrets).
const TEST_KEY: [u8; 32] = [0x42; 32];

/// Token exactly at the admission threshold (8 bytes).
const MIN_TOKEN: &[u8] = b"Zq#41!xL";

/// Short admitted token (10 bytes): the false-positive-risk class.
const SHORT_TOKEN: &[u8] = b"K7#mQ2!xZ9";

/// Token one byte below the admission threshold (7 bytes): excluded.
const TINY_TOKEN: &[u8] = b"tiny-07";

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Enforcing action shared by every enrolled battery pattern.
fn enforcing_action() -> ActionSet {
    ActionSet {
        enforce: Some(Severity::BlockAndLog),
        audit: true,
        count: true,
    }
}

/// Enroll the battery patterns: three 32-byte credential forms, two
/// admitted short tokens, and one below-threshold token for exclusion.
fn battery_library() -> (Arc<PatternLibrary>, Vec<PatternExclusion>) {
    let action = enforcing_action();
    let key_hex = hex::encode(TEST_KEY);
    PatternLibrary::new(vec![
        ScanPattern::compile(
            "battery-ed25519-raw".to_string(),
            Decoder::Raw,
            TEST_KEY.to_vec(),
            action,
        ),
        ScanPattern::compile(
            "battery-ed25519-base64".to_string(),
            Decoder::Base64,
            base64_needle(&TEST_KEY),
            action,
        ),
        ScanPattern::compile(
            "battery-ed25519-hextext".to_string(),
            Decoder::Raw,
            key_hex.into_bytes(),
            action,
        ),
        ScanPattern::compile(
            "battery-token-min".to_string(),
            Decoder::Raw,
            MIN_TOKEN.to_vec(),
            action,
        ),
        ScanPattern::compile(
            "battery-token-short".to_string(),
            Decoder::Raw,
            SHORT_TOKEN.to_vec(),
            action,
        ),
        ScanPattern::compile(
            "battery-token-tiny".to_string(),
            Decoder::Raw,
            TINY_TOKEN.to_vec(),
            action,
        ),
    ])
}

/// Everyday SSH channel content as deterministic byte fixtures (no
/// network, no real secrets).
fn fixtures() -> Vec<Vec<u8>> {
    vec![
        // Shell transcripts and listings.
        b"$ ls -la\ntotal 48\ndrwxr-xr-x  6 alice alice 4096 Sep  7 09:12 .\ndrwxr-xr-x 18 alice alice 4096 Sep  6 18:02 ..\n-rw-r--r--  1 alice alice  220 Sep  6 18:02 .bash_logout\n-rw-r--r--  1 alice alice 3771 Sep  6 18:02 .bashrc\n-rwxr-xr-x  1 alice alice  856 Sep  7 09:11 run.sh\ndrwxr-xr-x  3 alice alice 4096 Sep  7 09:12 src\n".to_vec(),
        b"3f9a2c1e7b4d4f6a8c0e2d5b7a9c1e3f5a7b9d1 (HEAD -> main)\nAuthor: Alice <alice@example.com>\nDate:   Sun Sep 7 09:12:44 2026 +0000\n\n    fix retry backoff in egress dial\n\na1b2c3d4 docs: refresh sandbox quickstart\n".to_vec(),
        b" M src/main.rs\n M crates/net/Cargo.toml\n?? crates/scan/lib/false_positives.rs\n?? /tmp/scratch notes.txt\n".to_vec(),
        b"diff --git a/src/main.rs b/src/main.rs\nindex 3f9a2c1..a1b2c3d 100644\n--- a/src/main.rs\n+++ b/src/main.rs\n@@ -12,7 +12,7 @@ fn main() {\n-    let backoff = 100;\n+    let backoff = 250;\n     retry(connect, backoff);\n }\n".to_vec(),
        b"# sshd_config shipped with the image\nPort 22\nPermitRootLogin no\nPasswordAuthentication no\nChallengeResponseAuthentication no\nX11Forwarding no\nAcceptEnv LANG LC_*\nSubsystem sftp /usr/lib/openssh/sftp-server\n".to_vec(),
        b"\"~/.viminfo\" 184L, 9120B\n# Registers:\n\"a\t cumbersome window layout state\n\"b\t :%s/foo/bar/g<CR>\n# File marks:\n'0  42  7  ~/.bashrc\n'1  10  0  /etc/hosts\n".to_vec(),
        b"[0] 0:bash* 1:vim- 2:ssh   09:12 07-Sep-26  temp=41C  load=0.42\n".to_vec(),
        // Base64 blob as `base64 < file` would print it.
        base64_needle(
            b"The quick brown fox jumps over the lazy dog. Pack my box with five dozen liquor jugs. ",
        ),
        // PEM-adjacent text without any key material.
        b"-----BEGIN OPENSSH PRIVATE KEY-----\n[redacted: key material withheld]\n-----END OPENSSH PRIVATE KEY-----\ndebug1: Server host key: ssh-ed25519 SHA256:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCD\n".to_vec(),
        // Binary-ish payloads: color escapes and NUL bytes.
        b"\x1b[01;34mDocuments\x1b[0m  \x1b[01;32mrun.sh\x1b[0m  \x1b[00mnotes.txt\x1b[0m\r\n\x1b[01;34msrc\x1b[0m\r\n".to_vec(),
        b"bin\x00ary\x00\x01\x02payload\xff\xfe\x00end of segment\x00\n".to_vec(),
        // Common tool outputs.
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 48\r\nX-Request-Id: 9f2c-41aa-bb07\r\n\r\n{\"status\":\"ok\",\"region\":\"iad\",\"replicas\":3}\n".to_vec(),
        b"CONTAINER ID   IMAGE          COMMAND       CREATED        STATUS\n9f2c41aa07bb   redis:7        \"redis-server\"  2 hours ago    Up 2 hours\n41aa07bb9f2c   postgres:16    \"postgres\"      3 hours ago    Up 3 hours\n".to_vec(),
        b"NAME                     READY   STATUS    RESTARTS   AGE\napi-7d9c4f6b9d-x2kqz   1/1     Running   0          12m\nworker-5b8d2f1a4c-m7p1v  2/2     Running   1          12m\n".to_vec(),
        b"npm sill logfile done cleaning log files\nnpm http fetch GET 200 https://registry.npmjs.org/lodash 88ms\nadded 142 packages in 3s\n12 packages are looking for funding\n".to_vec(),
        b"=========================== test session starts ============================\ncollected 24 items\ntests/test_proxy.py ............                                     [ 50%]\ntests/test_egress.py ............                                     [100%]\n============================ 24 passed in 0.42s =============================\n".to_vec(),
        b"debug1: Connecting to example.com [93.184.216.34] port 22.\ndebug1: Connection established.\ndebug1: identity file /home/alice/.ssh/id_ed25519 type 3\ndebug1: Server host key: ssh-ed25519 SHA256:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCD\ndebug1: Authentication succeeded (publickey).\n".to_vec(),
        b"alice@dev:~$ cat /etc/motd\nWelcome to Ubuntu 24.04.1 LTS (GNU/Linux 6.8.0-41-generic x86_64)\nalice@dev:~$ grep -r \"TODO\" src/ | head -3\nsrc/main.rs:12:    // TODO: bound the retry queue\nsrc/net.rs:88:    // TODO: ipv6 pool\nalue@dev:~$ echo $?\n0\n".to_vec(),
        b"127.0.0.1 localhost\n::1 localhost ip6-localhost ip6-loopback\nnameserver 1.1.1.1\nnameserver 8.8.8.8\noptions edns0 trust-ad\n".to_vec(),
        b"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nHOME=/home/alice\nLANG=C.UTF-8\nSHELL=/bin/bash\nTERM=xterm-256color\n".to_vec(),
        b"Sep  7 09:12:01 dev systemd[1]: Started Daily apt download activities.\nSep  7 09:12:44 dev sshd[4242]: Accepted publickey for alice from 10.0.2.15 port 52344 ssh2\nSep  7 09:13:02 dev kernel: [424242.0] eth0: link up (10000Mbps full duplex)\n".to_vec(),
        // Encoded benign traffic: percent, JSON-escaped, base64-stream, hex views.
        b"GET /search?q=%48%65%6c%6c%6f%20world&lang=en HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec(),
        br#"{"service": "thumbor", "msg": "caf\u00e9 \u0041\u0042 ready", "ok": true}"#.to_vec(),
        b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c\n".to_vec(),
        b"00000000: 5468 6520 7175 6963 6b20 6272 6f77 6e20  The quick brown \n00000010: 666f 7820 6a75 6d70 7320 6f76 6572 2074  fox jumps over t\n".to_vec(),
    ]
}

/// Credential names hit in `report`, resolved through `library`.
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

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enrolled_credential_forms_still_detect() {
        let (library, excluded) = battery_library();
        assert_eq!(excluded.len(), 1, "only the tiny token excludes");
        let expected_action = Some(enforcing_action());

        // Raw credential bytes hit both patterns sharing the raw needle.
        let report = ScanState::new(&library).scan_chunk(&TEST_KEY);
        let mut names = hit_credentials(&library, &report);
        names.sort();
        assert_eq!(names, vec!["battery-ed25519-base64", "battery-ed25519-raw"]);
        assert_eq!(report.strictest_action, expected_action);

        // Standard-base64 text hits through the derived-literal view.
        let encoded = base64_needle(&TEST_KEY);
        let report = ScanState::new(&library).scan_chunk(&encoded);
        let mut names = hit_credentials(&library, &report);
        names.sort();
        assert_eq!(names, vec!["battery-ed25519-base64", "battery-ed25519-raw"]);

        // Hex text hits the raw/base64 patterns via hex needles plus the
        // hex-text pattern via its literal raw needle.
        let hextext = hex::encode(TEST_KEY).into_bytes();
        let report = ScanState::new(&library).scan_chunk(&hextext);
        let mut names = hit_credentials(&library, &report);
        names.sort();
        assert_eq!(
            names,
            vec![
                "battery-ed25519-base64",
                "battery-ed25519-hextext",
                "battery-ed25519-raw"
            ]
        );
        assert_eq!(report.strictest_action, expected_action);
    }

    #[test]
    fn realistic_corpus_reports_no_hits_in_either_direction() {
        let (library, _) = battery_library();
        let fixtures = fixtures();
        let mut chunks: u64 = 0;
        let mut ed25519_hits: u64 = 0;
        let mut token_hits: u64 = 0;

        for fixture in &fixtures {
            // Fresh per-direction states: tails must never cross legs, and
            // both legs must agree on benign traffic.
            for _leg in ["request", "response"] {
                let mut reports = Vec::with_capacity(3);
                let mut whole = ScanState::new(&library);
                reports.push(whole.scan_chunk(fixture));
                chunks += 1;
                let mut split = ScanState::new(&library);
                let mid = fixture.len() / 2;
                reports.push(split.scan_chunk(&fixture[..mid]));
                reports.push(split.scan_chunk(&fixture[mid..]));
                chunks += 2;
                for report in &reports {
                    assert!(
                        report.hits.is_empty(),
                        "benign fixture must not hit: {}",
                        String::from_utf8_lossy(fixture)
                    );
                    assert_eq!(report.strictest_action, None);
                    for hit in &report.hits {
                        let name = library
                            .lookup(&hit.pattern_id)
                            .expect("hit resolves")
                            .credential_id;
                        if name.starts_with("battery-ed25519") {
                            ed25519_hits += 1;
                        } else {
                            token_hits += 1;
                        }
                    }
                }
            }
        }

        // Every fixture ran whole plus midpoint-split on both legs.
        assert_eq!(chunks, fixtures.len() as u64 * 6);
        let total_hits = ed25519_hits + token_hits;
        let per_thousand = total_hits as f64 / chunks as f64 * 1000.0;
        assert_eq!(ed25519_hits, 0, "32-byte credential class must not hit");
        assert_eq!(token_hits, 0, "short-token class must not hit");
        assert_eq!(per_thousand, 0.0);
    }

    #[test]
    fn threshold_boundaries_admit_at_minimum_and_exclude_below() {
        assert_eq!(MIN_TOKEN.len(), MIN_RAW_BYTES);
        assert_eq!(TINY_TOKEN.len(), MIN_RAW_BYTES - 1);
        let (library, excluded) = battery_library();
        assert_eq!(library.len(), 5, "five patterns admit");
        assert_eq!(excluded.len(), 1);
        assert_eq!(excluded[0].credential_id, "battery-token-tiny");
        assert_eq!(
            excluded[0].reason,
            ExclusionReason::TooShort {
                len: TINY_TOKEN.len()
            }
        );

        // The at-minimum token enforces on its literal bytes.
        let report = ScanState::new(&library).scan_chunk(MIN_TOKEN);
        assert!(
            hit_credentials(&library, &report).contains(&"battery-token-min".to_string()),
            "8-byte token at the threshold admits and matches"
        );
        assert_eq!(report.strictest_action, Some(enforcing_action()));

        // The short admitted token stays quiet on the realistic corpus.
        let fixtures = fixtures();
        let mut hits = 0;
        for fixture in &fixtures {
            hits += ScanState::new(&library)
                .scan_chunk(fixture)
                .hits
                .iter()
                .filter(|hit| {
                    library
                        .lookup(&hit.pattern_id)
                        .expect("hit resolves")
                        .credential_id
                        == "battery-token-short"
                })
                .count();
        }
        assert_eq!(hits, 0, "admitted short token is clean on this corpus");
    }

    #[test]
    fn dribbled_credentials_still_detect_exactly_once() {
        let (library, _) = battery_library();
        // Raw bytes surface through the raw view only: exactly one hit per
        // pattern sharing the needle.
        let mut state = ScanState::new(&library);
        let mut total = 0;
        for byte in TEST_KEY.chunks(1) {
            total += state.scan_chunk(byte).hits.len();
        }
        assert_eq!(total, 2, "1-byte dribble of raw bytes hits exactly once");

        // Base64 text additionally surfaces through the base64-stream view,
        // whose seam-adjacent matches may report twice (tolerated by audit
        // counting): both patterns still surface, at most once per view.
        let encoded = base64_needle(&TEST_KEY);
        let mut state = ScanState::new(&library);
        let mut total = 0;
        let mut names = Vec::new();
        for byte in encoded.chunks(1) {
            let report = state.scan_chunk(byte);
            total += report.hits.len();
            names.extend(hit_credentials(&library, &report));
        }
        names.sort();
        names.dedup();
        assert_eq!(names, vec!["battery-ed25519-base64", "battery-ed25519-raw"]);
        assert!(
            (2..=4).contains(&total),
            "1-byte dribble of base64 text hits once per view at most, got {total}"
        );
    }
}
