//! Component-wise lexical mount-root-relative paths.

use std::fmt;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A lexical, mount-root-relative path split into normalized components.
///
/// `.` and empty components are dropped, and absolute paths and `..`
/// components are rejected, so a `LexicalPath` always denotes a path beneath
/// the mount root. Non-UTF-8 paths are represented via [`LexicalPath::from_bytes`]
/// and flagged with [`LexicalPath::is_non_utf8`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LexicalPath {
    normalized: String,
    components: Vec<String>,
    non_utf8: bool,
}

/// Errors returned when a [`LexicalPath`] cannot be constructed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LexicalPathError {
    /// Path starts with `/`.
    Absolute(String),
    /// Path contains a `..` component.
    ParentEscape(String),
    /// Child name is empty, `.`, `..`, or contains `/`.
    InvalidChildName(String),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl LexicalPath {
    /// Construct a [`LexicalPath`] from a UTF-8 string, normalized relative to the
    /// mount root.
    ///
    /// # Errors
    ///
    /// Returns [`LexicalPathError::Absolute`] if `path` starts with `/`, or
    /// [`LexicalPathError::ParentEscape`] if `path` contains a `..` component.
    pub fn new(path: &str) -> Result<Self, LexicalPathError> {
        if path.starts_with('/') {
            return Err(LexicalPathError::Absolute(path.to_string()));
        }
        let mut components = Vec::new();
        for component in path.split('/') {
            match component {
                "" | "." => {}
                ".." => return Err(LexicalPathError::ParentEscape(path.to_string())),
                other => components.push(other.to_string()),
            }
        }
        Ok(Self {
            normalized: components.join("/"),
            components,
            non_utf8: false,
        })
    }

    /// Construct a [`LexicalPath`] from raw bytes.
    ///
    /// Valid UTF-8 bytes behave like [`LexicalPath::new`]; invalid bytes produce a
    /// non-UTF-8 sentinel path (see [`LexicalPath::is_non_utf8`]).
    ///
    /// # Errors
    ///
    /// Returns a [`LexicalPathError`] only when the bytes are valid UTF-8 but the
    /// decoded path is absolute or contains `..`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, LexicalPathError> {
        match std::str::from_utf8(bytes) {
            Ok(path) => Self::new(path),
            Err(_) => Ok(Self {
                normalized: String::new(),
                components: Vec::new(),
                non_utf8: true,
            }),
        }
    }

    /// Return the normalized path as a string slice, or `None` for non-UTF-8 paths.
    pub fn as_str(&self) -> Option<&str> {
        (!self.non_utf8).then_some(self.normalized.as_str())
    }

    /// Whether this path was constructed from non-UTF-8 bytes.
    pub fn is_non_utf8(&self) -> bool {
        self.non_utf8
    }

    /// Return the normalized path components in order.
    pub fn components(&self) -> &[String] {
        &self.components
    }

    /// Append a single child component and return the resulting [`LexicalPath`].
    ///
    /// # Errors
    ///
    /// Returns [`LexicalPathError::InvalidChildName`] if `name` is empty, `.`,
    /// `..`, or contains a `/`.
    pub fn child(&self, name: &str) -> Result<Self, LexicalPathError> {
        if self.non_utf8 {
            return Ok(self.clone());
        }
        if name.is_empty() || name == "." || name == ".." || name.contains('/') {
            return Err(LexicalPathError::InvalidChildName(name.to_string()));
        }
        let mut components = self.components.clone();
        components.push(name.to_string());
        Ok(Self {
            normalized: components.join("/"),
            components,
            non_utf8: false,
        })
    }
}

impl fmt::Display for LexicalPathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Absolute(path) => write!(f, "policy path '{path}' is absolute"),
            Self::ParentEscape(path) => write!(f, "policy path '{path}' contains '..'"),
            Self::InvalidChildName(name) => write!(f, "child name '{name}' is invalid"),
        }
    }
}

impl std::error::Error for LexicalPathError {}
