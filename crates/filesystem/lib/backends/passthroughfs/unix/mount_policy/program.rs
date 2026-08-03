//! Compiled mount policy program and pure evaluator (spec 22 §§4, 7, 10, 12, 13).

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::fmt;

use super::{LexicalPath, PathPolicyRule, PatternError, RuleEffect, RuleOrigin};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Visibility decision for a path under a mount path policy.
///
/// `Visible` paths are exposed to the guest; `Masked` paths are hidden and
/// their alias tags are honored; `TraversalOnly` directories are included in
/// readdir results so guests can discover unmasked descendants, while their
/// masked contents remain filtered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Visible,
    Masked,
    TraversalOnly,
}

/// Write-admission decision for a path under a mount path policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteDecision {
    Allow,
    Deny,
}

/// Effect of a write-policy rule on a path's write admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteRuleEffect {
    Allow,
    Deny,
    Protect,
}

/// A compiled set of allow/deny rules used for write admission.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct CompiledRuleSet {
    pub allow: Vec<PathPolicyRule>,
    pub deny: Vec<PathPolicyRule>,
}
/// Alias for the write-admission rule set of a mount policy program.
pub type WritePolicy = CompiledRuleSet;

/// Case sensitivity for pattern matching in a mount path policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CaseSensitivity {
    #[default]
    Sensitive,
    Insensitive,
}

/// A single rule that matched during a [`MountPolicyProgram::decide`] evaluation.
#[derive(Debug, Clone, PartialEq)]
pub struct RuleMatch {
    pub rule_index: usize,
    pub effect: RuleEffect,
    pub terminal: bool,
    pub origin: RuleOrigin,
    pub frozen_out: bool,
}

/// A single rule that matched during a [`MountPolicyProgram::decide_write`] evaluation.
#[derive(Debug, Clone, PartialEq)]
pub struct WriteRuleMatch {
    pub rule_index: usize,
    pub effect: WriteRuleEffect,
    pub terminal: bool,
    pub origin: RuleOrigin,
    pub frozen_out: bool,
}

/// The result of a policy evaluation: the decision plus the matched rules and
/// provenance of any terminal freeze.
#[derive(Debug, Clone, PartialEq)]
pub struct Explained<T, M = RuleMatch> {
    pub decision: T,
    pub matches: Vec<M>,
    pub frozen_by: Option<RuleOrigin>,
    pub fail_closed_non_utf8: bool,
}

/// A compiled mount path-policy program (spec 22 §§4, 7, 10, 12, 13).
///
/// Holds the ordered mask/unmask rules, protected paths, write-admission
/// policy, and case sensitivity. Evaluation is pure and fail-closed for
/// non-UTF-8 paths.
#[derive(Debug, Clone, PartialEq)]
pub struct MountPolicyProgram {
    pub version: u32,
    pub rules: Vec<PathPolicyRule>,
    pub protect: Vec<PathPolicyRule>,
    pub writes: WritePolicy,
    pub case_sensitivity: CaseSensitivity,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MountPolicyProgramWire {
    version: Option<u32>,
    rules: Vec<PathPolicyRule>,
    protect: Vec<PathPolicyRule>,
    writes: WritePolicy,
    case_sensitivity: CaseSensitivity,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl MountPolicyProgram {
    fn recompile_patterns(&mut self) -> Result<(), PatternError> {
        let case_insensitive = self.case_sensitivity == CaseSensitivity::Insensitive;
        for rule in self
            .rules
            .iter_mut()
            .chain(self.protect.iter_mut())
            .chain(self.writes.allow.iter_mut())
            .chain(self.writes.deny.iter_mut())
        {
            rule.pattern.set_case_insensitive(case_insensitive)?;
        }
        Ok(())
    }

    /// Evaluate the visibility decision for a lexical path.
    ///
    /// Protected paths always mask. Otherwise rules are applied in order; the
    /// last non-frozen rule wins, and a masked directory whose descendant may be
    /// unmasked becomes [`Decision::TraversalOnly`]. Non-UTF-8 paths mask
    /// fail-closed.
    pub fn decide(&self, path: &LexicalPath) -> Explained<Decision> {
        let Some(text) = path.as_str() else {
            return Explained {
                decision: Decision::Masked,
                matches: Vec::new(),
                frozen_by: None,
                fail_closed_non_utf8: true,
            };
        };
        let protected: Vec<_> = self
            .protect
            .iter()
            .enumerate()
            .filter(|(_, r)| r.pattern.matches_unknown(text))
            .collect();
        if !protected.is_empty() {
            return Explained {
                decision: Decision::Masked,
                matches: protected
                    .into_iter()
                    .map(|(rule_index, rule)| RuleMatch {
                        rule_index,
                        effect: RuleEffect::Mask,
                        terminal: rule.is_terminal(),
                        origin: rule.origin.clone(),
                        frozen_out: false,
                    })
                    .collect(),
                frozen_by: self
                    .protect
                    .iter()
                    .find(|r| r.is_terminal() && r.pattern.matches_unknown(text))
                    .map(|r| r.origin.clone()),
                fail_closed_non_utf8: false,
            };
        }
        let mut matches = Vec::new();
        let mut current = None;
        let mut frozen_by = None;
        for (rule_index, rule) in self.rules.iter().enumerate() {
            if !rule.pattern.matches_unknown(text) {
                continue;
            }
            let frozen_out = frozen_by.is_some();
            matches.push(RuleMatch {
                rule_index,
                effect: rule.effect,
                terminal: rule.is_terminal(),
                origin: rule.origin.clone(),
                frozen_out,
            });
            if frozen_out {
                continue;
            }
            current = Some(match rule.effect {
                RuleEffect::Mask => Decision::Masked,
                RuleEffect::Unmask => Decision::Visible,
            });
            if rule.is_terminal() {
                frozen_by = Some(rule.origin.clone());
            }
        }
        let mut decision = current.unwrap_or(Decision::Visible);
        if decision == Decision::Masked && self.may_unmask_descendant(path) {
            decision = Decision::TraversalOnly;
        }
        Explained {
            decision,
            matches,
            frozen_by,
            fail_closed_non_utf8: false,
        }
    }

    /// Evaluate the write-admission decision for a lexical path.
    ///
    /// Protected paths deny. Otherwise the write allow/deny rules are applied in
    /// order; the last non-frozen rule wins. Non-UTF-8 paths deny fail-closed.
    pub fn decide_write(&self, path: &LexicalPath) -> Explained<WriteDecision, WriteRuleMatch> {
        let Some(text) = path.as_str() else {
            return Explained {
                decision: WriteDecision::Deny,
                matches: Vec::new(),
                frozen_by: None,
                fail_closed_non_utf8: true,
            };
        };
        let mut matches = Vec::new();
        let mut protected = false;
        let mut frozen_by = None;
        for (index, rule) in self.protect.iter().enumerate() {
            if !rule.pattern.matches_unknown(text) {
                continue;
            }
            let frozen_out = frozen_by.is_some();
            matches.push(WriteRuleMatch {
                rule_index: index,
                effect: WriteRuleEffect::Protect,
                terminal: rule.is_terminal(),
                origin: rule.origin.clone(),
                frozen_out,
            });
            if !frozen_out {
                protected = true;
                if rule.is_terminal() {
                    frozen_by = Some(rule.origin.clone());
                }
            }
        }
        let mut decision = if protected {
            WriteDecision::Deny
        } else {
            WriteDecision::Allow
        };
        let mut ordered = Vec::new();
        for (bucket, rules) in [
            (WriteRuleEffect::Allow, &self.writes.allow),
            (WriteRuleEffect::Deny, &self.writes.deny),
        ] {
            for (index, rule) in rules.iter().enumerate() {
                ordered.push((rule.origin.scope_kind.authority(), bucket, index, rule));
            }
        }
        ordered.sort_by_key(|(authority, bucket, index, _)| {
            (
                *authority,
                if *bucket == WriteRuleEffect::Allow {
                    0
                } else {
                    1
                },
                *index,
            )
        });
        for (_, bucket, index, rule) in ordered {
            if !rule.pattern.matches_unknown(text) {
                continue;
            }
            let frozen_out = frozen_by.is_some();
            // rule_index reflects the rule's position within its original
            // allow/deny bucket (pre-authority-sort), not its post-sort order;
            // it identifies the rule for explanation, not the evaluation order.
            let rule_index = self.protect.len()
                + if bucket == WriteRuleEffect::Deny {
                    self.writes.allow.len() + index
                } else {
                    index
                };
            matches.push(WriteRuleMatch {
                rule_index,
                effect: bucket,
                terminal: rule.is_terminal(),
                origin: rule.origin.clone(),
                frozen_out,
            });
            if frozen_out || protected {
                continue;
            }
            if bucket == WriteRuleEffect::Deny {
                decision = WriteDecision::Deny;
                if rule.is_terminal() {
                    frozen_by = Some(rule.origin.clone());
                }
            }
        }
        Explained {
            decision,
            matches,
            frozen_by,
            fail_closed_non_utf8: false,
        }
    }

    /// Whether any protect rule matches the given path.
    pub fn is_protected(&self, path: &LexicalPath) -> bool {
        self.protect.iter().any(|rule| {
            path.as_str()
                .is_some_and(|text| rule.pattern.matches_unknown(text))
        })
    }

    /// Evaluate the visibility decision for a child `name` under `dir`.
    pub fn decide_child(&self, dir: &LexicalPath, name: &str) -> Explained<Decision> {
        match dir.child(name) {
            Ok(path) => self.decide(&path),
            Err(_) => Explained {
                decision: Decision::Masked,
                matches: Vec::new(),
                frozen_by: None,
                fail_closed_non_utf8: false,
            },
        }
    }

    /// Whether any unmask rule could match a descendant of `dir`, so `dir` itself
    /// must remain traversable even though it is masked.
    pub fn may_unmask_descendant(&self, dir: &LexicalPath) -> bool {
        if dir.is_non_utf8() {
            return false;
        }
        let components = dir.components();
        self.rules
            .iter()
            .filter(|rule| rule.effect == RuleEffect::Unmask)
            .any(|rule| match rule.pattern.literal_prefix() {
                None => true,
                Some(literal) => {
                    let prefix = literal.components();
                    (prefix.len() > components.len() && prefix.starts_with(components))
                        || (literal.extends_below() && components.starts_with(prefix))
                }
            })
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Serialize for MountPolicyProgram {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        MountPolicyProgramWire {
            version: Some(1),
            rules: self.rules.clone(),
            protect: self.protect.clone(),
            writes: self.writes.clone(),
            case_sensitivity: self.case_sensitivity,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for MountPolicyProgram {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = MountPolicyProgramWire::deserialize(deserializer)?;
        match wire.version {
            Some(1) => {
                let mut program = Self {
                    version: 1,
                    rules: wire.rules,
                    protect: wire.protect,
                    writes: wire.writes,
                    case_sensitivity: wire.case_sensitivity,
                };
                program.recompile_patterns().map_err(de::Error::custom)?;
                Ok(program)
            }
            Some(version) => Err(de::Error::custom(format!(
                "unsupported mount policy program version {version}; supported version is 1"
            ))),
            None => Err(de::Error::custom(
                "mount policy program version is required (expected version 1)",
            )),
        }
    }
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Visible => "visible",
            Self::Masked => "masked",
            Self::TraversalOnly => "traversal-only",
        })
    }
}
