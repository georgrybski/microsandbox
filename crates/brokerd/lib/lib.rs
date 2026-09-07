//! `microsandbox-brokerd` is the minimal PID 1 init and SSH-divert broker
//! that runs inside the broker VM.
//!
//! Unlike agentd, brokerd is not a general agent: it serves no exec,
//! filesystem, or TCP sessions. It receives sealed key material in the typed
//! bootstrap, binds the SSH epoch provisioned over the agent console to its
//! transport CID, listens on the divert vsock port for host-diverted guest
//! SSH sessions, terminates those sessions as an SSH server, and reoriginates
//! them upstream as an SSH client through the host-side TCP forwarder. The
//! guest IP stack stays down; all upstream egress leaves through the vsock
//! egress port.
//!
//! This crate is Linux-only.

#![cfg(target_os = "linux")]
#![warn(missing_docs)]

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub mod broker;
pub mod config;
pub mod console;
pub mod egress;
pub mod epoch;
pub mod error;
pub mod init;
pub mod keys;
pub mod prelude;
pub mod vsock;

pub use broker::Broker;
pub use config::BrokerConfig;
pub use error::*;
