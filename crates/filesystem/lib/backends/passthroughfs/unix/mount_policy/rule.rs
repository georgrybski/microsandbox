//! Compiled policy rules and provenance (spec 22 §4, §11).

use serde::{Deserialize, Serialize};
use std::{fmt, path::PathBuf};

use super::pattern::Pattern;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleEffect {
    Mask,
    Unmask,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeKind {
    HomeRegistry,
    UserGlobalOverrides,
    ReferenceConfig,
    ConfigRepoLayer,
    Workload,
    MountEntry,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleOrigin {
    pub layer: String,
    pub file: PathBuf,
    pub scope_kind: ScopeKind,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PathPolicyRule {
    pub effect: RuleEffect,
    pub pattern: Pattern,
    pub overridable: bool,
    pub origin: RuleOrigin,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PathPolicyRule {
    pub fn is_terminal(&self) -> bool {
        !self.overridable
    }
}

impl ScopeKind {
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
