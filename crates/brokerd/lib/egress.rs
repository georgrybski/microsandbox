//! Upstream egress through the host-side TCP forwarder.
//!
//! The broker VM keeps its guest IP stack down, so upstream SSH egress
//! leaves through a vsock CONNECT-style egress port (guest dials, host
//! answers). brokerd implements the client side of the egress-port framing
//! only: it dials the egress port, sends one framed connect request naming
//! the upstream destination, awaits a framed acknowledgement, and then the
//! stream carries raw TCP bytes. The host-side forwarder that answers this
//! framing is provisioned outside this crate; its numeric port is the only
//! coupling, configured in [`crate::config`].

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{BrokerError, BrokerResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Maximum egress connect/ack frame size.
const MAX_EGRESS_FRAME_BYTES: usize = 64 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Connect request opening one egress tunnel to an upstream destination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressConnect {
    /// Upstream hostname or IP string (matches the divert prelude dest).
    pub host: String,

    /// Upstream TCP port.
    pub port: u16,
}

/// Forwarder acknowledgement for one egress connect request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressAck {
    /// Whether the forwarder will now carry TCP bytes on this stream.
    pub ok: bool,

    /// Human-readable detail for refused tunnels (identifiers only).
    #[serde(default)]
    pub detail: String,
}

/// Every way egress framing can fail before the tunnel opens.
#[derive(Debug, Error)]
pub enum EgressError {
    /// A frame ended early or exceeded the size cap.
    #[error("egress frame invalid: {0}")]
    Framing(String),

    /// The forwarder refused the tunnel.
    #[error("egress refused for {host}:{port}: {detail}")]
    Refused {
        /// Requested upstream host.
        host: String,

        /// Requested upstream port.
        port: u16,

        /// Forwarder refusal detail.
        detail: String,
    },
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Encode an egress connect request as `u32` big-endian length plus CBOR.
pub fn encode_egress_connect(request: &EgressConnect) -> Vec<u8> {
    frame_cbor(request)
}

/// Decode a framed egress connect request.
pub fn decode_egress_connect(bytes: &[u8]) -> Result<(EgressConnect, usize), EgressError> {
    unframe_cbor(bytes)
}

/// Encode an egress acknowledgement as `u32` big-endian length plus CBOR.
pub fn encode_egress_ack(ack: &EgressAck) -> Vec<u8> {
    frame_cbor(ack)
}

/// Decode a framed egress acknowledgement.
pub fn decode_egress_ack(bytes: &[u8]) -> Result<(EgressAck, usize), EgressError> {
    unframe_cbor(bytes)
}

/// Open one egress tunnel over an already-dialed egress-port stream.
///
/// Sends the connect request for `(host, port)`, awaits the forwarder ack,
/// and fails closed on refusal. On success the stream carries raw TCP
/// bytes to the upstream destination.
pub async fn open_egress_tunnel<S>(stream: &mut S, host: &str, port: u16) -> BrokerResult<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let framed = encode_egress_connect(&EgressConnect {
        host: host.to_string(),
        port,
    });
    stream
        .write_all(&framed)
        .await
        .map_err(|e| BrokerError::Egress(format!("write egress connect: {e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| BrokerError::Egress(format!("flush egress connect: {e}")))?;
    let ack = read_egress_ack(stream)
        .await
        .map_err(|e| BrokerError::Egress(e.to_string()))?;
    if !ack.ok {
        return Err(BrokerError::Egress(
            EgressError::Refused {
                host: host.to_string(),
                port,
                detail: ack.detail,
            }
            .to_string(),
        ));
    }
    Ok(())
}

/// Read one framed egress acknowledgement from the forwarder.
pub async fn read_egress_ack<S>(stream: &mut S) -> Result<EgressAck, EgressError>
where
    S: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| EgressError::Framing(format!("egress ack length prefix unreadable: {e}")))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_EGRESS_FRAME_BYTES {
        return Err(EgressError::Framing(format!(
            "egress ack of {len} bytes exceeds {MAX_EGRESS_FRAME_BYTES} byte cap"
        )));
    }
    let mut payload = vec![0u8; len];
    stream
        .read_exact(&mut payload)
        .await
        .map_err(|e| EgressError::Framing(format!("egress ack payload truncated: {e}")))?;
    ciborium::from_reader(&payload[..])
        .map_err(|e| EgressError::Framing(format!("egress ack CBOR decode failed: {e}")))
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

fn frame_cbor<T: serde::Serialize>(value: &T) -> Vec<u8> {
    let mut payload = Vec::new();
    ciborium::into_writer(value, &mut payload).expect("egress CBOR encoding is infallible");
    let len = u32::try_from(payload.len()).expect("egress frame fits in u32");
    let mut framed = Vec::with_capacity(4 + payload.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(&payload);
    framed
}

fn unframe_cbor<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<(T, usize), EgressError> {
    if bytes.len() < 4 {
        return Err(EgressError::Framing(
            "egress frame missing length prefix".to_string(),
        ));
    }
    let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if len > MAX_EGRESS_FRAME_BYTES {
        return Err(EgressError::Framing(format!(
            "egress frame of {len} bytes exceeds {MAX_EGRESS_FRAME_BYTES} byte cap"
        )));
    }
    if bytes.len() < 4 + len {
        return Err(EgressError::Framing(
            "egress frame payload truncated".to_string(),
        ));
    }
    let value: T = ciborium::from_reader(&bytes[4..4 + len])
        .map_err(|e| EgressError::Framing(format!("egress CBOR decode failed: {e}")))?;
    Ok((value, 4 + len))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[test]
    fn egress_connect_framing_round_trips() {
        let request = EgressConnect {
            host: "example.com".to_string(),
            port: 22,
        };
        let framed = encode_egress_connect(&request);
        let (decoded, consumed) = decode_egress_connect(&framed).unwrap();
        assert_eq!(decoded, request);
        assert_eq!(consumed, framed.len());
    }

    #[test]
    fn egress_ack_framing_round_trips() {
        let ack = EgressAck {
            ok: true,
            detail: String::new(),
        };
        let framed = encode_egress_ack(&ack);
        let (decoded, consumed) = decode_egress_ack(&framed).unwrap();
        assert_eq!(decoded, ack);
        assert_eq!(consumed, framed.len());
    }

    #[test]
    fn egress_framing_rejects_truncated_and_oversize_frames() {
        let framed = encode_egress_connect(&EgressConnect {
            host: "example.com".to_string(),
            port: 22,
        });
        assert!(decode_egress_connect(&framed[..2]).is_err());
        assert!(decode_egress_connect(&framed[..framed.len() - 1]).is_err());
        let oversize = u32::MAX.to_be_bytes().to_vec();
        assert!(decode_egress_connect(&oversize).is_err());
    }

    #[tokio::test]
    async fn egress_tunnel_opens_on_forwarder_ack() {
        let (mut client, mut forwarder) = duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut len_buf = [0u8; 4];
            forwarder.read_exact(&mut len_buf).await.unwrap();
            let len = u32::from_be_bytes(len_buf) as usize;
            let mut payload = vec![0u8; len];
            forwarder.read_exact(&mut payload).await.unwrap();
            let request: EgressConnect = ciborium::from_reader(&payload[..]).unwrap();
            assert_eq!(request.host, "example.com");
            assert_eq!(request.port, 22);
            let ack = encode_egress_ack(&EgressAck {
                ok: true,
                detail: String::new(),
            });
            forwarder.write_all(&ack).await.unwrap();
        });
        open_egress_tunnel(&mut client, "example.com", 22)
            .await
            .unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn egress_tunnel_fails_closed_on_refusal() {
        let (mut client, mut forwarder) = duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let n = forwarder.read(&mut buf).await.unwrap();
            assert!(n > 4);
            let ack = encode_egress_ack(&EgressAck {
                ok: false,
                detail: "denied by policy".to_string(),
            });
            forwarder.write_all(&ack).await.unwrap();
        });
        let err = open_egress_tunnel(&mut client, "example.com", 22)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("denied by policy"));
        server.await.unwrap();
    }
}
