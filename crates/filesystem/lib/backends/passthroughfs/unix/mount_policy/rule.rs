//! Compiled policy rules and provenance (spec 22 §4, §11).

use serde::{Deserialize, Serialize};
use std::{fmt, path::PathBuf};

use super::pattern::Pattern;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The effect a path-policy rule has on visibility: mask or unmask.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleEffect {
    /// Hide the matching path from the guest.
    Mask,
    /// Expose the matching path to the guest.
    Unmask,
}

/// The provenance scope of a policy rule, ordered by authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeKind {
    /// Home-registry scope (highest authority).
    HomeRegistry,
    /// User-level global override scope.
    UserGlobalOverrides,
    /// Reference configuration scope.
    ReferenceConfig,
    /// Config-repository layer scope.
    ConfigRepoLayer,
    /// Workload-defined scope.
    Workload,
    /// Per-mount-entry scope (lowest authority).
    MountEntry,
}

/// Provenance of a policy rule: the layer, source file, and scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleOrigin {
    /// Name of the policy layer that declared the rule.
    pub layer: String,
    /// Source file path where the rule was declared.
    pub file: PathBuf,
    /// Authority scope of the rule.
    pub scope_kind: ScopeKind,
}

/// A single compiled path-policy rule: effect, pattern, overridability, origin.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PathPolicyRule {
    /// Visibility effect (mask or unmask).
    pub effect: RuleEffect,
    /// Compiled glob pattern for matching paths.
    pub pattern: Pattern,
    /// Whether a later rule can override this one.
    pub overridable: bool,
    /// Provenance of the rule.
    pub origin: RuleOrigin,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PathPolicyRule {
    /// Whether this rule is terminal (non-overridable) and freezes further matches.
    pub fn is_terminal(&self) -> bool {
        !self.overridable
    }
}

impl ScopeKind {
    /// Return the numeric authority rank of this scope (higher overrides lower).
    pub fn authority(self) -> u32 {
        self as u32
    }

    /// Return the stable human-readable scope label.
    pub fn label(self) -> &'static str {
        match self {
            Self::HomeRegistry => "home-registry",
            Self::UserGlobalOverrides => "user-global-overrides",
            Self::ReferenceConfig => "reference-config",
            Self::ConfigRepoLayer => "config-repo-layer",
            Self::Workload => "workload",
            Self::MountEntry => "mount-entry",
        }
    }
}

impl fmt::Display for RuleEffect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Mask => "mask",
            Self::Unmask => "unmask",
        })
    }
}

impl fmt::Display for ScopeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl fmt::Display for RuleOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "layer '{}' ({}, {} scope)",
            self.layer,
            self.file.display(),
            self.scope_kind.label()
        )
    }
}
