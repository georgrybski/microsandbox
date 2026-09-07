//! Broker VM configuration: vsock ports and provisioned upstream state.
//!
//! brokerd only knows vsock ports and CIDs. Host socket paths never cross
//! into the guest: the launcher projects each host-side route onto a numeric
//! guest port, and these constants must match that projection. A mismatch
//! fails loud at bind or dial time rather than misrouting traffic.

use microsandbox_protocol::bootstrap::BrokerUpstream;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Guest vsock port brokerd LISTENs on for diverted guest SSH sessions.
///
/// The host shim dials its host-side unix socket and libkrun injects the
/// accepted stream into this guest port, so the guest side must LISTEN: a
/// guest dial to a listen-mode port is reset.
pub const SSH_DIVERT_LISTEN_PORT: u32 = 3022;

/// Guest vsock port brokerd dials for upstream TCP egress.
///
/// Each connection speaks the client side of the egress-port framing in
/// [`crate::egress`]; the host-side TCP forwarder that answers is
/// provisioned outside this crate and only ever sees numeric ports.
pub const EGRESS_CONNECT_PORT: u32 = 3023;

/// Maximum divert prelude frame size accepted from a diverted stream.
pub const MAX_PRELUDE_BYTES: usize = 64 * 1024;

/// Timeout for reading one divert prelude from an accepted stream.
pub const PRELUDE_READ_TIMEOUT_SECS: u64 = 10;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Runtime configuration for one brokerd instance.
///
/// Ports default to [`SSH_DIVERT_LISTEN_PORT`] and
/// [`EGRESS_CONNECT_PORT`]; the upstream pins arrive in the typed
/// bootstrap and are `None` when the host predates them.
#[derive(Debug, Clone)]
pub struct BrokerConfig {
    /// Guest vsock port to LISTEN on for diverted sessions.
    pub divert_port: u32,

    /// Guest vsock port to dial for upstream egress.
    pub egress_port: u32,

    /// Pinned upstream servers projected from the grant host list.
    pub upstream: Option<BrokerUpstream>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl BrokerConfig {
    /// Create a configuration with explicit ports and upstream pins.
    pub fn new(divert_port: u32, egress_port: u32, upstream: Option<BrokerUpstream>) -> Self {
        Self {
            divert_port,
            egress_port,
            upstream,
        }
    }

    /// Look up the pin for a divert destination.
    ///
    /// Returns `None` when no pin matches, which fails the session closed:
    /// dialing an unpinned upstream is never attempted.
    pub fn pin_for(
        &self,
        host: &str,
        port: u16,
    ) -> Option<&microsandbox_protocol::bootstrap::BrokerUpstreamHost> {
        self.upstream
            .as_ref()?
            .hosts
            .iter()
            .find(|entry| entry.host == host && entry.port == port)
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for BrokerConfig {
    fn default() -> Self {
        Self {
            divert_port: SSH_DIVERT_LISTEN_PORT,
            egress_port: EGRESS_CONNECT_PORT,
            upstream: None,
        }
    }
}
