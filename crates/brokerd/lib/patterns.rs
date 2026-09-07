//! Bootstrap DLP pattern ingest for the broker VM.
//!
//! Converts the additive-optional bootstrap wire patterns into the shared
//! sealed match library. Each wire entry is destructured field by field —
//! never cloned — so the pattern bytes move into sealed scan custody with
//! no second copy; entries that fail admission are wiped on drop by the
//! scan crate. `None` (a host that predates the field) compiles to an
//! empty library, and relayed sessions pass through unchanged.

use std::sync::Arc;

use microsandbox_protocol::bootstrap::{BrokerPattern, BrokerPatterns};
use microsandbox_scan::{PatternLibrary, ScanPattern};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Move bootstrap wire patterns into a shared sealed match library.
///
/// Ingest runs once at startup; enforcement holds the result until
/// process exit. Pattern content is never persisted or logged — only
/// pattern ids and digests reach audit records.
pub fn ingest_bootstrap_patterns(patterns: Option<BrokerPatterns>) -> Arc<PatternLibrary> {
    let Some(patterns) = patterns else {
        return PatternLibrary::empty();
    };
    let BrokerPatterns { patterns } = patterns;
    let inputs = patterns
        .into_iter()
        .map(|entry| {
            let BrokerPattern {
                credential_id,
                decoder,
                bytes,
                action,
            } = entry;
            ScanPattern::compile(credential_id, decoder, bytes, action)
        })
        .collect();
    let (library, _excluded) = PatternLibrary::new(inputs);
    library
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use microsandbox_scan::{ActionSet, Decoder};

    fn wire_pattern(credential_id: &str, bytes: &[u8]) -> BrokerPattern {
        BrokerPattern {
            credential_id: credential_id.to_string(),
            decoder: Decoder::Raw,
            bytes: bytes.to_vec(),
            action: ActionSet::passthrough(),
        }
    }

    #[test]
    fn absent_patterns_ingest_to_an_empty_library() {
        let library = ingest_bootstrap_patterns(None);
        assert!(library.is_empty());
    }

    #[test]
    fn admitted_patterns_resolve_for_audit() {
        let library = ingest_bootstrap_patterns(Some(BrokerPatterns {
            patterns: vec![wire_pattern("api-key", b"test-only-pattern-bytes")],
        }));
        assert_eq!(library.len(), 1);
        let report = {
            let mut state = microsandbox_scan::ScanState::new(&library);
            state.scan_chunk(b"leak: test-only-pattern-bytes!")
        };
        assert_eq!(report.hits.len(), 1);
        let meta = library.lookup(&report.hits[0].pattern_id).unwrap();
        assert_eq!(meta.credential_id, "api-key");
    }

    #[test]
    fn excluded_wire_patterns_still_relay_clean() {
        // A below-threshold pattern is excluded at compile time; ingest
        // stays pass-through instead of failing closed.
        let library = ingest_bootstrap_patterns(Some(BrokerPatterns {
            patterns: vec![wire_pattern("tiny", b"short")],
        }));
        assert!(library.is_empty());
    }
}
