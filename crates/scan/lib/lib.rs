//! Transport-agnostic streaming secret matcher.
//!
//! [`PatternLibrary`] compiles sealed [`SensitivePattern`]s into literal
//! needles (raw, hex, base64) once; [`ScanState`] streams arbitrary byte
//! chunks through raw, percent-decoded, JSON-unescaped, and incrementally
//! base64-decoded views and reports [`ScanReport`]s carrying pattern ids
//! and digests — never secret content.
//!
//! Detection primitives ([`decode`](crate::decode) internals) are faithful
//! ports of the HTTP secret-substitution detector's kernel
//! (`crates/network/lib/secrets/handler.rs`: `contains_bytes`,
//! `update_tail_buffer`, the 6x encoded-expansion bound, percent decoding,
//! `json_unescape`, and the strictest-action reduction). The HTTP proxies
//! keep their own framing in P0 and are not rewired onto this crate; the
//! parity tests in [`scan`](crate::scan) pin the shared kernel so a future
//! rewiring stays consistent with the detector.
//!
//! Custody: pattern bytes live in [`SealedBytes`] (no `Clone`, no
//! `Serialize`, zeroized on drop, redacting `Debug`), mirroring the broker
//! key custody idioms. Auditable values — pattern ids, digests, credential
//! names, actions — are plain data safe to log.

#![warn(missing_docs)]

pub mod action;
pub mod decode;
#[cfg(test)]
mod false_positives;
pub mod library;
pub mod pattern;
pub mod scan;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use action::{ActionSet, Severity};
pub use decode::Base64StreamDecoder;
pub use library::PatternLibrary;
pub use pattern::{
    Decoder, ExclusionReason, PatternDigest, PatternExclusion, PatternId, ScanPattern, SealedBytes,
    SensitivePattern,
};
pub use scan::{ScanHit, ScanReport, ScanState};
