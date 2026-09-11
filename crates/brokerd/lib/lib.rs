//! `microsandbox-brokerd` is the SSH-divert broker that runs inside the broker VM.
//! It supports an ordinary managed service and a separate legacy PID 1 mode.
//!
//! Unlike agentd, brokerd is not a general agent: it serves no exec,
//! filesystem, or general TCP sessions. Legacy mode receives sealed key material in the typed
//! bootstrap, binds the SSH epoch provisioned over the agent console to its
//! transport CID, listens on the divert vsock port for host-diverted guest
//! SSH sessions, terminates those sessions as an SSH server, and reoriginates
//! them upstream as an SSH client through the host-side TCP forwarder. The
//! guest IP stack stays down; all upstream egress leaves through the vsock
//! egress port.
//!
//! Managed service mode receives complete launch policies over its separate
//! protected host transport, uses explicit CA-signed host credentials and never
//! opens the agent console. Both modes share the native SSH relay implementation.
//!
//! This crate is Linux-only.

#![cfg(target_os = "linux")]
#![warn(missing_docs)]

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub mod audit;
pub mod broker;
pub mod config;
pub mod console;
pub mod egress;
pub mod epoch;
pub mod error;
pub mod host_identity;
pub mod init;
pub mod keys;
#[cfg(test)]
mod managed_ssh_tests;
pub mod management;
pub mod patterns;
pub mod policy;
pub mod prelude;
pub mod service;
pub mod ssh;
mod ssh_io;
pub mod vsock;

pub use broker::Broker;
pub use config::BrokerConfig;
pub use error::*;
