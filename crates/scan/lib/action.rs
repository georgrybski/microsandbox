//! Coalesced enforcement actions for secret matches.
//!
//! [`Severity`] orders enforcement strength as specified: block-and-log is
//! less severe than block, which is less severe than block-and-terminate.
//! Passthrough (forward unchanged) is not a severity level; it is the
//! absence of enforcement (`enforce: None`).
//!
//! Note on ordering: the HTTP secret-substitution detector ranks silent
//! block below block-and-log in its internal priority. This crate follows
//! the broker enforcement ordering instead (block-and-log below block),
//! so strictest-action results can differ between the two when both a
//! block and a block-and-log policy contribute. The reduction shape —
//! maximum severity wins, audit/count union — is identical.

use std::fmt;

use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Enforcement strength for a secret match, weakest to strongest.
///
/// Declaration order is the severity order; see [`Severity::priority`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    /// Close the offending channel and emit an audit record.
    #[default]
    BlockAndLog,

    /// Close the offending channel without an audit record.
    Block,

    /// Tear down the whole relay session and emit an audit record.
    BlockAndTerminate,
}

/// Coalesced action for a group of contributing policies.
///
/// Reduction rule: the maximum [`Severity`] over the contributors wins,
/// and `audit`/`count` are the OR-union over the contributors. A
/// passthrough policy contributes `{ enforce: None, audit: false,
/// count: true }` — no enforcement, still counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ActionSet {
    /// Strongest enforcement to apply, or `None` to forward unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforce: Option<Severity>,

    /// Whether matches under this action emit audit records.
    #[serde(default)]
    pub audit: bool,

    /// Whether matches under this action increment leak counters.
    #[serde(default)]
    pub count: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Severity {
    /// Severity rank: higher wins the strictest reduction.
    ///
    /// Passthrough (no enforcement) ranks 0; block-and-log ranks below
    /// block per the broker enforcement ordering.
    pub fn priority(self) -> u8 {
        match self {
            Self::BlockAndLog => 1,
            Self::Block => 2,
            Self::BlockAndTerminate => 3,
        }
    }
}

impl ActionSet {
    /// The passthrough action: forward unchanged, still counted.
    pub fn passthrough() -> Self {
        Self {
            enforce: None,
            audit: false,
            count: true,
        }
    }
    /// Reduce two contributing actions: maximum severity wins, and
    /// `audit`/`count` are the OR-union.
    ///
    /// This ports the strictest-violation reduction kernel of the HTTP
    /// secret-substitution detector to [`ActionSet`].
    pub fn strictest(first: Self, second: Self) -> Self {
        let enforce = match (first.enforce, second.enforce) {
            (None, None) => None,
            (Some(action), None) | (None, Some(action)) => Some(action),
            (Some(a), Some(b)) => Some(if a.priority() >= b.priority() { a } else { b }),
        };
        Self {
            enforce,
            audit: first.audit || second.audit,
            count: first.count || second.count,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for ActionSet {
    /// The wire default is passthrough: forward unchanged, still counted.
    fn default() -> Self {
        Self::passthrough()
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::BlockAndLog => "block-and-log",
            Self::Block => "block",
            Self::BlockAndTerminate => "block-and-terminate",
        };
        f.write_str(value)
    }
}

impl fmt::Display for ActionSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.enforce {
            Some(severity) => write!(f, "{severity}"),
            None => f.write_str("passthrough"),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_order_matches_the_spec_lattice() {
        assert!(Severity::BlockAndLog.priority() < Severity::Block.priority());
        assert!(Severity::Block.priority() < Severity::BlockAndTerminate.priority());
    }

    #[test]
    fn passthrough_counts_without_enforcing_or_auditing() {
        let action = ActionSet::passthrough();
        assert_eq!(action.enforce, None);
        assert!(!action.audit);
        assert!(action.count);
        assert_eq!(action.to_string(), "passthrough");
    }

    #[test]
    fn strictest_takes_max_severity_and_unions_flags() {
        let log = ActionSet {
            enforce: Some(Severity::BlockAndLog),
            audit: true,
            count: false,
        };
        let block = ActionSet {
            enforce: Some(Severity::Block),
            audit: false,
            count: true,
        };
        let reduced = ActionSet::strictest(log, block);
        assert_eq!(reduced.enforce, Some(Severity::Block));
        assert!(reduced.audit);
        assert!(reduced.count);
    }

    #[test]
    fn strictest_keeps_terminate_over_block() {
        let terminate = ActionSet {
            enforce: Some(Severity::BlockAndTerminate),
            audit: true,
            count: true,
        };
        let block = ActionSet {
            enforce: Some(Severity::Block),
            audit: false,
            count: false,
        };
        assert_eq!(
            ActionSet::strictest(terminate, block).enforce,
            Some(Severity::BlockAndTerminate)
        );
        assert_eq!(
            ActionSet::strictest(block, terminate).enforce,
            Some(Severity::BlockAndTerminate)
        );
    }

    #[test]
    fn strictest_with_passthrough_keeps_enforcement_and_count() {
        let reduced = ActionSet::strictest(
            ActionSet::passthrough(),
            ActionSet {
                enforce: Some(Severity::BlockAndLog),
                audit: true,
                count: false,
            },
        );
        assert_eq!(reduced.enforce, Some(Severity::BlockAndLog));
        assert!(reduced.audit);
        assert!(reduced.count);
    }

    #[test]
    fn action_set_round_trips_serde() {
        let action = ActionSet {
            enforce: Some(Severity::BlockAndTerminate),
            audit: true,
            count: true,
        };
        let json = serde_json::to_string(&action).unwrap();
        assert_eq!(serde_json::from_str::<ActionSet>(&json).unwrap(), action);
        let passthrough = ActionSet::passthrough();
        let json = serde_json::to_string(&passthrough).unwrap();
        assert_eq!(
            serde_json::from_str::<ActionSet>(&json).unwrap(),
            passthrough
        );
    }
}
