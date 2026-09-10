//! SSH gateway divert plumbing: prelude framing and broker relay.
//!
//! Configured SSH endpoints route to the host dispatcher before the TCP proxy
//! opens a direct upstream connection. The dispatcher receives the framed
//! destination prelude and the untouched guest stream, then resolves credential
//! custody. Only that selected path may return an SSH identification string.
//! Classifiers restrict other endpoints but cannot switch an established SSH
//! stream to a terminating broker.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::mpsc;

use super::classifier::{SshClassification, SshClassifier};
use super::policy::{BrokerEndpoint, SshFlow, SshPolicy};
use crate::netstack::shared::SharedState;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Guest/server bytes examined before an undecided SSH classification
/// falls through to the generic egress verdict.
///
/// An SSH identification string is at most 255 bytes including `CRLF`,
/// so 512 bytes generously covers a banner plus a few comment lines
/// while bounding how long non-SSH flows stay undecided. This is smaller
/// than the proxy's `SERVER_READ_BUF_SIZE` (16 KiB) because the gateway
/// only needs the banner prefix, not a full data window; the timeout
/// below matches the existing `PEEK_BUDGET` (5 s) so SSH gating adds no
/// extra worst-case latency beyond the current first-flight peek.
pub const SSH_PRELUDE_BYTE_BUDGET: usize = 512;

/// Time allowed for the SSH banner to complete before falling through
/// to the generic egress verdict.
///
/// Matches the proxy's existing `PEEK_BUDGET` (5 s): server-first
/// protocols already budget this long for the first flight, so the
/// gateway reuses the same window rather than introducing a second
/// timeout. An incomplete banner after this window is the one deliberate
/// hole (fail-open to egress with an observable log line) because the
/// banner is short and 512 bytes is generous; withholding the connection
/// longer would stall non-SSH flows.
pub const SSH_CLASSIFY_TIMEOUT: Duration = Duration::from_secs(5);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Divert prelude sent to the broker before SSH bytes flow.
///
/// The broker uses `dest_host`/`dest_port` to reoriginate its own
/// upstream dial, `transport_cid` to attribute the session to a sandbox
/// transport, and `epoch` (unix seconds) to correlate logs across
/// restarts.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SshDivertPrelude {
    /// Guest-observed destination host (SNI, cached hostname, or IP string).
    pub dest_host: String,
    /// Guest-observed destination port.
    pub dest_port: u16,
    /// Sandbox transport identifier for broker attribution.
    pub transport_cid: u64,
    /// Unix seconds at divert time for broker log correlation.
    pub epoch: u64,
}

/// Runtime SSH gateway configuration for one sandbox.
///
/// `None` at the proxy means SSH gating is disabled and the existing
/// data path runs unchanged. `Some` enables classification and
/// divert/direct/deny enforcement. The broker path is host-side only;
/// when `broker` is `None`, divert-intended flows deny fail-closed.
#[derive(Debug, Clone)]
pub struct SshGatewayConfig {
    /// SSH strict mode and grants.
    pub policy: SshPolicy,
    /// Divert target when configured; `None` denies divert-intended flows.
    pub broker: Option<BrokerEndpoint>,
    /// Sandbox transport identifier stamped into the divert prelude.
    ///
    /// Carried by the host-side [`SshBrokerBinding`] (derived at spawn
    /// from the leased network slot). `0` (unspecified) only when no
    /// binding exists, in which case no divert can happen.
    pub transport_cid: u64,
}

/// Host-side SSH broker binding for one sandbox launch.
///
/// The private launch contract carries this on
/// [`crate::config::ResolvedNetworkConfig`]; it never appears in
/// guest-visible `NetworkConfig.ssh` / `NetworkSpec.ssh` serialization.
/// The endpoint names the broker unix socket diverted flows dial and
/// `transport_cid` attributes the session to one sandbox transport.
/// Spawn derives the transport identifier from the leased network slot,
/// the per-sandbox discriminator available in this tree, and stamps it
/// into every divert prelude alongside the wall-clock epoch.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SshBrokerBinding {
    /// Divert target for broker-mediated SSH sessions.
    pub endpoint: BrokerEndpoint,
    /// Sandbox transport identifier stamped into the divert prelude.
    pub transport_cid: u64,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SshDivertPrelude {
    /// Create a prelude for `flow` stamped with `transport_cid` and the
    /// current wall-clock epoch.
    pub fn new(flow: &SshFlow, transport_cid: u64, epoch: u64) -> Self {
        Self {
            dest_host: flow.host.clone(),
            dest_port: flow.port,
            transport_cid,
            epoch,
        }
    }
}

impl SshGatewayConfig {
    /// Create a gateway configuration from its policy, optional broker
    /// endpoint, and transport identifier.
    pub fn new(policy: SshPolicy, broker: Option<BrokerEndpoint>, transport_cid: u64) -> Self {
        Self {
            policy,
            broker,
            transport_cid,
        }
    }

    /// Convenience for sharing across proxy tasks.
    pub fn shared(self) -> Arc<Self> {
        Arc::new(self)
    }
}

impl SshBrokerBinding {
    /// Create a binding from a broker endpoint and transport identifier.
    pub fn new(endpoint: BrokerEndpoint, transport_cid: u64) -> Self {
        Self {
            endpoint,
            transport_cid,
        }
    }

    /// Join this host-side binding with the guest-visible policy into
    /// the per-sandbox gateway configuration the proxy enforces.
    pub fn gateway_config(&self, policy: SshPolicy) -> SshGatewayConfig {
        SshGatewayConfig::new(policy, Some(self.endpoint.clone()), self.transport_cid)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Derive the SSH flow destination from the guest destination.
///
/// Prefers the SNI hostname when the earlier peek captured one (rare for
/// SSH, which carries no TLS SNI), then the resolved-hostname cache's
/// representative name for the destination IP, and finally the
/// stringified IP. Mirrors the egress policy's hostname sources so SSH
/// grants match the same names domain rules use.
pub fn ssh_flow_for_destination(
    dst: SocketAddr,
    shared: &SharedState,
    sni: Option<&str>,
) -> SshFlow {
    if let Some(name) = sni.filter(|s| !s.is_empty()) {
        return SshFlow::new(name, dst.port());
    }
    if let Some(cached) = shared.preferred_hostname_for_ip(dst.ip()) {
        return SshFlow::new(cached, dst.port());
    }
    SshFlow::new(dst.ip().to_string(), dst.port())
}

/// Combine per-direction classifications into one flow verdict.
///
/// Either direction's banner proves SSH; otherwise a decided `NotSsh`
/// on either side proves the flow cannot become SSH, so it wins over a
/// lingering `NeedMoreData`. Both `NeedMoreData` keeps the flow
/// undecided so the caller can wait for the byte/time budget before
/// falling through to egress.
pub fn combined_ssh_classification(
    guest: SshClassification,
    server: SshClassification,
) -> SshClassification {
    if guest.is_ssh() || server.is_ssh() {
        SshClassification::Ssh
    } else if guest == SshClassification::NotSsh || server == SshClassification::NotSsh {
        SshClassification::NotSsh
    } else {
        SshClassification::NeedMoreData
    }
}

/// Classify guest and server samples fed in arrival order.
///
/// Each sample is fed to its own classifier (one instance per direction
/// per connection); the combined verdict follows
/// [`combined_ssh_classification`].
pub fn classify_ssh_directions(guest_bytes: &[u8], server_bytes: &[u8]) -> SshClassification {
    let mut guest = SshClassifier::new();
    let mut server = SshClassifier::new();
    let guest_verdict = guest.feed(guest_bytes);
    let server_verdict = server.feed(server_bytes);
    combined_ssh_classification(guest_verdict, server_verdict)
}

/// Current wall-clock epoch in unix seconds for the divert prelude.
///
/// The smoltcp stack's monotonic `EPOCH` measures process uptime for
/// packet timers and cannot correlate broker logs across restarts, so
/// the gateway stamps wall-clock seconds instead.
pub fn current_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Encode a divert prelude as `u32` big-endian length prefix plus CBOR payload.
pub fn encode_ssh_divert_prelude(prelude: &SshDivertPrelude) -> Vec<u8> {
    let mut payload = Vec::new();
    ciborium::into_writer(prelude, &mut payload).expect("prelude CBOR encoding is infallible");
    let len = u32::try_from(payload.len()).expect("prelude fits in u32");
    let mut framed = Vec::with_capacity(4 + payload.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(&payload);
    framed
}

/// Decode a framed divert prelude, returning the prelude and total bytes consumed.
pub fn decode_ssh_divert_prelude(bytes: &[u8]) -> io::Result<(SshDivertPrelude, usize)> {
    if bytes.len() < 4 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "divert prelude missing length prefix",
        ));
    }
    let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if bytes.len() < 4 + len {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "divert prelude payload truncated",
        ));
    }
    let prelude: SshDivertPrelude = ciborium::from_reader(&bytes[4..4 + len]).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("divert prelude CBOR decode failed: {e}"),
        )
    })?;
    Ok((prelude, 4 + len))
}

/// Dial the broker unix socket and send the framed divert prelude.
pub async fn dial_broker_and_send_prelude(
    endpoint: &BrokerEndpoint,
    prelude: &SshDivertPrelude,
) -> io::Result<UnixStream> {
    let mut stream = UnixStream::connect(endpoint.path()).await?;
    let framed = encode_ssh_divert_prelude(prelude);
    stream.write_all(&framed).await?;
    stream.flush().await?;
    Ok(stream)
}

/// Relay SSH bytes between the guest channels and an established broker stream.
///
/// `initial_guest` carries the buffered guest first flight (for example
/// the client banner) and is written to the broker before the relay
/// loop starts. Call only before any direct upstream connection or server
/// bytes: this stream must carry exactly one guest-facing SSH handshake.
pub async fn relay_ssh_via_broker(
    broker: UnixStream,
    initial_guest: Vec<u8>,
    mut from_smoltcp: mpsc::Receiver<Bytes>,
    to_smoltcp: mpsc::Sender<Bytes>,
    shared: Arc<SharedState>,
) -> io::Result<()> {
    let (mut broker_rx, mut broker_tx) = broker.into_split();
    if !initial_guest.is_empty() {
        broker_tx.write_all(&initial_guest).await?;
        broker_tx.flush().await?;
    }

    let mut broker_buf = vec![0u8; 16384];
    let mut guest_eof = false;
    loop {
        tokio::select! {
            data = from_smoltcp.recv(), if !guest_eof => {
                match data {
                    Some(bytes) => {
                        if !bytes.is_empty() {
                            broker_tx.write_all(&bytes).await?;
                            broker_tx.flush().await?;
                        }
                    }
                    None => {
                        guest_eof = true;
                        if broker_tx.shutdown().await.is_err() {
                            break;
                        }
                    }
                }
            }
            result = broker_rx.read(&mut broker_buf) => {
                match result {
                    Ok(0) => break,
                    Ok(n) => {
                        let data = Bytes::copy_from_slice(&broker_buf[..n]);
                        if to_smoltcp.send(data).await.is_err() {
                            break;
                        }
                        shared.proxy_wake.wake();
                    }
                    Err(e) => return Err(e),
                }
            }
        }
    }

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combined_verdict_prefers_ssh_then_not_ssh() {
        use SshClassification::{NeedMoreData, NotSsh, Ssh};
        assert_eq!(combined_ssh_classification(Ssh, NotSsh), Ssh);
        assert_eq!(combined_ssh_classification(NotSsh, Ssh), Ssh);
        assert_eq!(combined_ssh_classification(Ssh, NeedMoreData), Ssh);
        assert_eq!(combined_ssh_classification(NotSsh, NeedMoreData), NotSsh);
        assert_eq!(combined_ssh_classification(NeedMoreData, NotSsh), NotSsh);
        assert_eq!(
            combined_ssh_classification(NeedMoreData, NeedMoreData),
            NeedMoreData
        );
        assert_eq!(combined_ssh_classification(NotSsh, NotSsh), NotSsh);
    }

    #[test]
    fn banner_order_server_first_classifies_as_ssh() {
        let guest: &[u8] = b"";
        let server: &[u8] = b"SSH-2.0-OpenSSH_9.6\r\n";
        assert_eq!(
            classify_ssh_directions(guest, server),
            SshClassification::Ssh
        );
    }

    #[test]
    fn banner_order_client_first_classifies_as_ssh() {
        let guest: &[u8] = b"SSH-2.0-OpenSSH_9.6\r\n";
        let server: &[u8] = b"";
        assert_eq!(
            classify_ssh_directions(guest, server),
            SshClassification::Ssh
        );
    }

    #[test]
    fn banner_order_interleaved_classifies_as_ssh() {
        let guest: &[u8] = b"SSH-2.0-OpenSSH_9.6\r\n";
        let server: &[u8] = b"SSH-2.0-OpenSSH_9.6\r\n";
        assert_eq!(
            classify_ssh_directions(guest, server),
            SshClassification::Ssh
        );
    }

    #[test]
    fn prelude_framing_round_trips_with_length_prefix() {
        let prelude = SshDivertPrelude {
            dest_host: "example.com".to_string(),
            dest_port: 22,
            transport_cid: 7,
            epoch: 1_700_000_000,
        };
        let framed = encode_ssh_divert_prelude(&prelude);
        assert!(framed.len() > 4);
        let len = u32::from_be_bytes([framed[0], framed[1], framed[2], framed[3]]) as usize;
        assert_eq!(len, framed.len() - 4);
        let (decoded, consumed) = decode_ssh_divert_prelude(&framed).unwrap();
        assert_eq!(decoded, prelude);
        assert_eq!(consumed, framed.len());
        assert_eq!(decoded.dest_host, "example.com");
        assert_eq!(decoded.dest_port, 22);
        assert_eq!(decoded.transport_cid, 7);
        assert_eq!(decoded.epoch, 1_700_000_000);
    }

    #[test]
    fn prelude_decode_rejects_truncated_frames() {
        let prelude = SshDivertPrelude {
            dest_host: "example.com".to_string(),
            dest_port: 22,
            transport_cid: 1,
            epoch: 2,
        };
        let framed = encode_ssh_divert_prelude(&prelude);
        assert!(decode_ssh_divert_prelude(&framed[..2]).is_err());
        assert!(decode_ssh_divert_prelude(&framed[..framed.len() - 1]).is_err());
    }

    #[test]
    fn broker_binding_builds_live_gateway_config() {
        let binding = SshBrokerBinding::new(
            BrokerEndpoint::new("/run/msb/ssh-broker.sock").expect("test broker must validate"),
            9,
        );
        let gateway = binding.gateway_config(SshPolicy::default());
        assert_eq!(gateway.transport_cid, 9);
        assert_eq!(
            gateway
                .broker
                .as_ref()
                .expect("binding must populate the broker"),
            &BrokerEndpoint::new("unix:///run/msb/ssh-broker.sock").unwrap(),
        );
    }

    #[test]
    fn broker_binding_survives_the_launch_contract_round_trip() {
        let binding = SshBrokerBinding::new(
            BrokerEndpoint::new("/run/msb/ssh-broker.sock").expect("test broker must validate"),
            9,
        );
        let json = serde_json::to_string(&binding).unwrap();
        assert!(json.contains("ssh-broker.sock"));
        let back: SshBrokerBinding = serde_json::from_str(&json).unwrap();
        assert_eq!(back, binding);
    }
}
