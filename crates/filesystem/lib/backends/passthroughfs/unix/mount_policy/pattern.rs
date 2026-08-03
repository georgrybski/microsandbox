//! Glob patterns for compiled mount policies (spec 22 §6).

use globset::{GlobBuilder, GlobMatcher};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::fmt;

use super::rule::RuleOrigin;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A compiled glob pattern for a mount path-policy rule (spec 22 §6).
///
/// Patterns are mount-root-relative and reject absolute paths, `..` escapes,
/// and NUL bytes. Directory-only patterns (trailing `/`) only match directories.
#[derive(Debug, Clone)]
pub struct Pattern {
    raw: String,
    matcher: GlobMatcher,
    stem: Option<GlobMatcher>,
    dir_only: bool,
}

/// The literal leading components of a [`Pattern`], used for descendant checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiteralPrefix {
    components: Vec<String>,
    extends_below: bool,
}

/// Why a [`Pattern`] failed to compile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternErrorKind {
    /// Pattern is empty.
    Empty,
    /// Pattern starts with `/`.
    Absolute(String),
    /// Pattern contains a NUL byte.
    NulByte(String),
    /// Pattern contains a `..` component.
    ParentEscape(String),
    /// Pattern is not a valid glob; `pattern` is the raw string and `message` is the globset error message.
    InvalidGlob {
        /// Raw pattern string.
        pattern: String,
        /// Globset error message.
        message: String,
    },
}

/// Error returned when a [`Pattern`] cannot be compiled, with optional provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternError {
    kind: PatternErrorKind,
    origin: Option<RuleOrigin>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Pattern {
    /// Compile a [`Pattern`] from a raw glob string, recording the rule [`RuleOrigin`].
    ///
    /// # Errors
    ///
    /// Returns a [`PatternError`] (see [`PatternErrorKind`]) if the pattern is
    /// empty, absolute, contains `..` or a NUL byte, or is not a valid glob.
    pub fn compile(raw: &str, origin: &RuleOrigin) -> Result<Self, PatternError> {
        Self::compile_inner(raw, false).map_err(|kind| PatternError {
            kind,
            origin: Some(origin.clone()),
        })
    }

    /// Parse a [`Pattern`] without recording rule provenance.
    ///
    /// # Errors
    ///
    /// Returns a [`PatternError`] for the same reasons as [`Pattern::compile`].
    pub fn parse(raw: &str) -> Result<Self, PatternError> {
        Self::compile_inner(raw, false).map_err(|kind| PatternError { kind, origin: None })
    }

    /// Recompile this pattern's matchers with the requested case sensitivity.
    pub fn set_case_insensitive(&mut self, case_insensitive: bool) -> Result<(), PatternError> {
        let compiled = Self::compile_inner(&self.raw, case_insensitive)
            .map_err(|kind| PatternError { kind, origin: None })?;
        self.matcher = compiled.matcher;
        self.stem = compiled.stem;
        self.dir_only = compiled.dir_only;
        Ok(())
    }

    /// Return the raw authored pattern string.
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// Return whether this pattern is directory-only.
    pub fn is_dir_only(&self) -> bool {
        self.dir_only
    }

    fn compile_inner(raw: &str, case_insensitive: bool) -> Result<Self, PatternErrorKind> {
        if raw.is_empty() {
            return Err(PatternErrorKind::Empty);
        }
        if raw.contains('\0') {
            return Err(PatternErrorKind::NulByte(raw.to_string()));
        }
        if raw.starts_with('/') {
            return Err(PatternErrorKind::Absolute(raw.to_string()));
        }
        let dir_only = raw.ends_with('/');
        let body = if dir_only { &raw[..raw.len() - 1] } else { raw };
        if body.is_empty() {
            return Err(PatternErrorKind::Empty);
        }
        if body.split('/').any(|component| component == "..") {
            return Err(PatternErrorKind::ParentEscape(raw.to_string()));
        }
        let matcher = GlobBuilder::new(body)
            .literal_separator(true)
            .case_insensitive(case_insensitive)
            .build()
            .map_err(|source| PatternErrorKind::InvalidGlob {
                pattern: raw.to_string(),
                message: source.to_string(),
            })?
            .compile_matcher();
        let stem = body
            .strip_suffix("/**")
            .filter(|stem| !stem.is_empty())
            .map(|stem| {
                GlobBuilder::new(stem)
                    .literal_separator(true)
                    .case_insensitive(case_insensitive)
                    .build()
                    .map(|glob| glob.compile_matcher())
                    .map_err(|source| PatternErrorKind::InvalidGlob {
                        pattern: raw.to_string(),
                        message: source.to_string(),
                    })
            })
            .transpose()?;
        Ok(Self {
            raw: raw.to_string(),
            matcher,
            stem,
            dir_only,
        })
    }

    /// Whether the pattern matches the given path string.
    pub fn matches_path(&self, path: &str) -> bool {
        (!self.dir_only && self.is_match(path)) || self.matches_any_ancestor(path)
    }

    /// Whether the pattern matches the given directory path string.
    pub fn matches_dir(&self, path: &str) -> bool {
        self.is_match(path) || self.matches_any_ancestor(path)
    }

    /// Whether the pattern matches a path whose directory-ness is unknown.
    pub fn matches_unknown(&self, path: &str) -> bool {
        self.is_match(path) || self.matches_any_ancestor(path)
    }

    fn is_match(&self, path: &str) -> bool {
        self.matcher.is_match(path) || self.stem.as_ref().is_some_and(|stem| stem.is_match(path))
    }

    fn matches_any_ancestor(&self, path: &str) -> bool {
        let mut rest = path;
        while let Some(index) = rest.rfind('/') {
            rest = &rest[..index];
            if self.is_match(rest) {
                return true;
            }
        }
        false
    }

    /// Return the literal leading components, if any, for descendant analysis.
    pub fn literal_prefix(&self) -> Option<LiteralPrefix> {
        let body = self.raw.strip_suffix('/').unwrap_or(&self.raw);
        let total = body.split('/').count();
        let mut components = Vec::new();
        for component in body.split('/') {
            if component == "**" || component.contains(['*', '?', '[', ']', '{', '}']) {
                break;
            }
            components.push(component.to_string());
        }
        (!components.is_empty()).then_some(LiteralPrefix {
            extends_below: components.len() < total,
            components,
        })
    }
}

impl LiteralPrefix {
    /// Return the literal leading components of the pattern.
    pub fn components(&self) -> &[String] {
        &self.components
    }
    /// Whether the pattern extends below its literal prefix (i.e. has a glob tail).
    pub fn extends_below(&self) -> bool {
        self.extends_below
    }
}

impl PatternError {
    /// Return the error kind for a [`PatternError`].
    pub fn kind(&self) -> &PatternErrorKind {
        &self.kind
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl PartialEq for Pattern {
    fn eq(&self, other: &Self) -> bool {
        self.raw == other.raw
    }
}
impl Eq for Pattern {}

impl Serialize for Pattern {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.raw)
    }
}

impl<'de> Deserialize<'de> for Pattern {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(de::Error::custom)
    }
}

impl fmt::Display for PatternErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("mount policy pattern is empty"),
            Self::Absolute(pattern) => write!(f, "mount policy pattern '{pattern}' is absolute"),
            Self::NulByte(pattern) => {
                write!(f, "mount policy pattern {pattern:?} contains a NUL byte")
            }
            Self::ParentEscape(pattern) => {
                write!(f, "mount policy pattern '{pattern}' contains '..'")
            }
            Self::InvalidGlob { pattern, message } => write!(
                f,
                "mount policy pattern '{pattern}' is not a valid glob: {message}"
            ),
        }
    }
}

impl fmt::Display for PatternError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.origin {
            Some(origin) => write!(f, "{} [declared at {origin}]", self.kind),
            None => self.kind.fmt(f),
        }
    }
}

impl std::error::Error for PatternError {}
