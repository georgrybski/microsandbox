//! Pure compiled mount path-policy types and evaluator (spec 22).

mod lexical;
mod pattern;
mod program;
mod rule;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use lexical::{LexicalPath, LexicalPathError};
pub use pattern::{LiteralPrefix, Pattern, PatternError, PatternErrorKind};
pub use program::{
    CaseSensitivity, CompiledRuleSet, Decision, Explained, MountPolicyProgram, RuleMatch,
    WriteDecision, WritePolicy, WriteRuleEffect, WriteRuleMatch,
};
pub use rule::{PathPolicyRule, RuleEffect, RuleOrigin, ScopeKind};
