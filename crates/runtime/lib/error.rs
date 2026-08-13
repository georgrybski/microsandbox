//! Error types for the microsandbox-runtime crate.

use thiserror::Error;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The result type for runtime operations.
pub type RuntimeResult<T> = Result<T, RuntimeError>;

/// Errors that can occur while loading a compiled mount policy from disk.
#[derive(Debug, Error)]
pub enum MountPolicyLoadError {
    /// The policy file could not be found at the given path.
    #[error("mount policy file not found: {0}")]
    FileNotFound(String),

    /// The policy file contents are not valid JSON or failed to deserialize.
    #[error("invalid mount policy JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),

    /// The policy program version is unsupported or missing.
    #[error("unsupported mount policy program version: {0}")]
    UnsupportedVersion(String),

    /// An I/O error occurred while reading the policy file.
    #[error("mount policy io error: {0}")]
    Io(#[from] std::io::Error),

    /// The policy path escapes the approved state directory.
    #[error("mount policy path escapes the approved state directory")]
    PathEscape,

    /// The policy path contains a symlink, which is rejected.
    #[error("mount policy path contains a symlink, which is rejected")]
    SymlinkRejected,
}

/// Errors that can occur during runtime operations.
#[derive(Debug, Error)]
pub enum RuntimeError {
    /// An I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// A database error.
    #[error("database error: {0}")]
    Database(#[from] sea_orm::DbErr),

    /// A JSON serialization/deserialization error.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// An errno-based system error.
    #[error("system error: {0}")]
    #[cfg(unix)]
    Nix(#[from] nix::errno::Errno),

    /// A custom error message.
    #[error("{0}")]
    Custom(String),
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl From<MountPolicyLoadError> for RuntimeError {
    fn from(error: MountPolicyLoadError) -> Self {
        RuntimeError::Custom(format!("policy load failed: {error}"))
    }
}

impl microsandbox_db::retry::IsSqliteBusy for RuntimeError {
    fn is_sqlite_busy(&self) -> bool {
        matches!(self, RuntimeError::Database(db_err) if microsandbox_db::retry::is_sqlite_busy(db_err))
    }
}
