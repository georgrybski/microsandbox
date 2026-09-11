//! Typed brokerd errors.

use std::io;

use thiserror::Error;

use crate::epoch::EpochError;
use crate::keys::CustodyError;
use crate::prelude::PreludeError;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Every failure mode of the broker daemon.
///
/// Custody, prelude, and epoch variants carry identifiers and static failure
/// details only — never key material — so they are safe to log.
#[derive(Debug, Error)]
pub enum BrokerError {
    /// The typed bootstrap frame was missing, malformed, or invalid.
    #[error("bootstrap: {0}")]
    Bootstrap(String),

    /// The agent console could not be opened, read, or written.
    #[error("console: {0}")]
    Console(String),

    /// PID 1 guest initialization failed.
    #[error("init: {0}")]
    Init(String),

    /// Sealed key custody refused.
    #[error(transparent)]
    Custody(#[from] CustodyError),

    /// The divert prelude could not be decoded.
    #[error(transparent)]
    Prelude(#[from] PreludeError),

    /// A validated divert was refused against provisioned epoch state.
    #[error("divert refused: {0}")]
    DivertRefused(String),

    /// SSH epoch handling failed.
    #[error(transparent)]
    Epoch(#[from] EpochError),

    /// Upstream egress dialing or tunneling failed.
    #[error("egress: {0}")]
    Egress(String),

    /// SSH termination or reorigination failed.
    #[error("ssh: {0}")]
    Ssh(String),

    /// Underlying russh protocol failure.
    #[error("ssh: {0}")]
    Russh(#[from] russh::Error),

    /// Underlying I/O failure.
    #[error("io: {0}")]
    Io(#[from] io::Error),

    /// Protocol frame encode or decode failure.
    #[error("protocol: {0}")]
    Protocol(String),
}

/// Convenience alias for brokerd results.
pub type BrokerResult<T> = Result<T, BrokerError>;
