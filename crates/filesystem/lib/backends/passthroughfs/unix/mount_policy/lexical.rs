//! Component-wise lexical mount-root-relative paths.

use std::fmt;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LexicalPath {
    normalized: String,
    components: Vec<String>,
    non_utf8: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LexicalPathError {
    Absolute(String),
    ParentEscape(String),
    InvalidChildName(String),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl LexicalPath {
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

    pub fn as_str(&self) -> Option<&str> {
        (!self.non_utf8).then_some(self.normalized.as_str())
    }

    pub fn is_non_utf8(&self) -> bool {
        self.non_utf8
    }

    pub fn components(&self) -> &[String] {
        &self.components
    }

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
