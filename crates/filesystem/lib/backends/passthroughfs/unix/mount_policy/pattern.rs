//! Glob patterns for compiled mount policies (spec 22 §6).

use globset::{GlobBuilder, GlobMatcher};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::fmt;

use super::rule::RuleOrigin;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Pattern {
    raw: String,
    matcher: GlobMatcher,
    stem: Option<GlobMatcher>,
    dir_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiteralPrefix {
    components: Vec<String>,
    extends_below: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternErrorKind {
    Empty,
    Absolute(String),
    NulByte(String),
    ParentEscape(String),
    InvalidGlob { pattern: String, message: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternError {
    kind: PatternErrorKind,
    origin: Option<RuleOrigin>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Pattern {
    pub fn compile(raw: &str, origin: &RuleOrigin) -> Result<Self, PatternError> {
        Self::compile_inner(raw).map_err(|kind| PatternError {
            kind,
            origin: Some(origin.clone()),
        })
    }

    pub fn parse(raw: &str) -> Result<Self, PatternError> {
        Self::compile_inner(raw).map_err(|kind| PatternError { kind, origin: None })
    }

    /// Return the raw authored pattern string.
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// Return whether this pattern is directory-only.
    pub fn is_dir_only(&self) -> bool {
        self.dir_only
    }

    fn compile_inner(raw: &str) -> Result<Self, PatternErrorKind> {
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

    pub fn matches_path(&self, path: &str) -> bool {
        (!self.dir_only && self.is_match(path)) || self.matches_any_ancestor(path)
    }

    pub fn matches_dir(&self, path: &str) -> bool {
        self.is_match(path) || self.matches_any_ancestor(path)
    }

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
    pub fn components(&self) -> &[String] {
        &self.components
    }
    pub fn extends_below(&self) -> bool {
        self.extends_below
    }
}

impl PatternError {
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
