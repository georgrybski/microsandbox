//! Divert prelude framing and validation.
//!
//! The host TCP proxy dials the broker unix socket, sends a `u32`
//! big-endian length prefix plus CBOR payload, then relays SSH bytes. This
//! module mirrors the codec in `crates/network/lib/ssh/gateway.rs`
//! (`encode_ssh_divert_prelude` / `decode_ssh_divert_prelude`): the struct
//! carries identical field names and types, so both sides encode the same
//! CBOR map and stay wire-compatible without sharing the host-only network
//! crate inside the guest binary.

use std::io;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::epoch::EpochState;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Divert prelude sent to the broker before SSH bytes flow.
///
/// Field names and types intentionally match the host-side gateway prelude
/// so the CBOR maps decode interchangeably.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// Every way a divert prelude frame can fail to decode.
#[derive(Debug, Error)]
pub enum PreludeError {
    /// The frame ended before the length prefix or payload completed.
    #[error("divert prelude truncated: {0}")]
    Truncated(String),

    /// The length prefix or CBOR payload was malformed.
    #[error("divert prelude malformed: {0}")]
    Malformed(String),
}

/// Every way a decoded prelude can be refused against provisioned state.
///
/// Rejection reasons carry identifiers and counters only — no key material
/// and no guest payload bytes — so they are safe to log.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PreludeReject {
    /// No epoch provision has been accepted yet; there is nothing to bind.
    #[error("no epoch provision accepted yet")]
    NoProvision,

    /// The prelude's transport CID does not match the console-provisioned
    /// CID. The provisioned CID wins: the console channel is host-asserted
    /// while the prelude arrives over a guest-influenced path, so a
    /// mismatch reads as spoof and the session is refused.
    #[error("transport CID mismatch: prelude claims {got}, provisioned {want}")]
    CidMismatch {
        /// CID observed in the prelude.
        got: u64,

        /// CID bound from the console provision.
        want: u32,
    },

    /// The prelude divert time predates the provision's validity floor.
    #[error("stale divert: prelude epoch {got} predates not_before {not_before}")]
    Stale {
        /// Divert time observed in the prelude.
        got: u64,

        /// Validity floor from the console provision.
        not_before: u64,
    },
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SshDivertPrelude {
    /// Validate this prelude against provisioned epoch state.
    ///
    /// The provisioned transport CID wins over the prelude claim
    /// (transport-CID-wins): only a prelude stamped for the bound CID and
    /// at or after the provision's validity floor is accepted.
    pub fn validate_against(&self, state: Option<&EpochState>) -> Result<(), PreludeReject> {
        let Some(state) = state else {
            return Err(PreludeReject::NoProvision);
        };
        if self.transport_cid != u64::from(state.cid) {
            return Err(PreludeReject::CidMismatch {
                got: self.transport_cid,
                want: state.cid,
            });
        }
        if self.epoch < state.not_before {
            return Err(PreludeReject::Stale {
                got: self.epoch,
                not_before: state.not_before,
            });
        }
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

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
pub fn decode_ssh_divert_prelude(bytes: &[u8]) -> Result<(SshDivertPrelude, usize), PreludeError> {
    if bytes.len() < 4 {
        return Err(PreludeError::Truncated(
            "divert prelude missing length prefix".to_string(),
        ));
    }
    let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if bytes.len() < 4 + len {
        return Err(PreludeError::Truncated(
            "divert prelude payload truncated".to_string(),
        ));
    }
    let prelude: SshDivertPrelude = ciborium::from_reader(&bytes[4..4 + len])
        .map_err(|e| PreludeError::Malformed(format!("divert prelude CBOR decode failed: {e}")))?;
    Ok((prelude, 4 + len))
}

/// Read one framed divert prelude from a diverted stream.
///
/// Caps the declared payload at `max_bytes` before allocating so a corrupt
/// length prefix cannot force a huge allocation.
pub async fn read_ssh_divert_prelude<S>(
    stream: &mut S,
    max_bytes: usize,
) -> Result<SshDivertPrelude, PreludeError>
where
    S: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.map_err(|e| {
        PreludeError::Truncated(format!("divert prelude length prefix unreadable: {e}"))
    })?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max_bytes {
        return Err(PreludeError::Malformed(format!(
            "divert prelude of {len} bytes exceeds {max_bytes} byte cap"
        )));
    }
    let mut payload = vec![0u8; len];
    stream
        .read_exact(&mut payload)
        .await
        .map_err(|e| PreludeError::Truncated(format!("divert prelude payload truncated: {e}")))?;
    let prelude: SshDivertPrelude = ciborium::from_reader(&payload[..])
        .map_err(|e| PreludeError::Malformed(format!("divert prelude CBOR decode failed: {e}")))?;
    Ok(prelude)
}

/// Write one framed divert prelude to a stream (shim side of the contract).
pub async fn write_ssh_divert_prelude<S>(
    stream: &mut S,
    prelude: &SshDivertPrelude,
) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let framed = encode_ssh_divert_prelude(prelude);
    stream.write_all(&framed).await?;
    stream.flush().await
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::epoch::EpochState;

    fn sample_prelude() -> SshDivertPrelude {
        SshDivertPrelude {
            dest_host: "example.com".to_string(),
            dest_port: 22,
            transport_cid: 7,
            epoch: 1_700_000_000,
        }
    }

    fn sample_state() -> EpochState {
        EpochState {
            instance: "sandbox-1".to_string(),
            cid: 7,
            epoch: 3,
            issued_at: 1_699_999_900,
            not_before: 1_699_999_900,
        }
    }

    #[test]
    fn prelude_framing_round_trips_with_length_prefix() {
        let prelude = sample_prelude();
        let framed = encode_ssh_divert_prelude(&prelude);
        assert!(framed.len() > 4);
        let len = u32::from_be_bytes([framed[0], framed[1], framed[2], framed[3]]) as usize;
        assert_eq!(len, framed.len() - 4);
        let (decoded, consumed) = decode_ssh_divert_prelude(&framed).unwrap();
        assert_eq!(decoded, prelude);
        assert_eq!(consumed, framed.len());
    }

    #[test]
    fn prelude_decode_rejects_truncated_frames() {
        let framed = encode_ssh_divert_prelude(&sample_prelude());
        assert!(decode_ssh_divert_prelude(&framed[..2]).is_err());
        assert!(decode_ssh_divert_prelude(&framed[..framed.len() - 1]).is_err());
        assert!(decode_ssh_divert_prelude(&[]).is_err());
    }

    #[test]
    fn prelude_decode_rejects_garbage_payload() {
        let mut framed = 4u32.to_be_bytes().to_vec();
        framed.extend_from_slice(b"nope");
        assert!(matches!(
            decode_ssh_divert_prelude(&framed),
            Err(PreludeError::Malformed(_))
        ));
    }

    #[test]
    fn prelude_read_enforces_the_size_cap() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (mut client, mut server) = tokio::net::UnixStream::pair().unwrap();
            let framed = encode_ssh_divert_prelude(&sample_prelude());
            client.write_all(&framed).await.unwrap();
            let err = read_ssh_divert_prelude(&mut server, 4).await.unwrap_err();
            assert!(matches!(err, PreludeError::Malformed(_)));
        });
    }

    #[test]
    fn prelude_validation_accepts_bound_cid_and_fresh_epoch() {
        let state = sample_state();
        sample_prelude().validate_against(Some(&state)).unwrap();
    }

    #[test]
    fn prelude_validation_refuses_without_provision() {
        let err = sample_prelude().validate_against(None).unwrap_err();
        assert_eq!(err, PreludeReject::NoProvision);
    }

    #[test]
    fn prelude_validation_refuses_spoofed_cid() {
        let state = sample_state();
        let mut prelude = sample_prelude();
        prelude.transport_cid = 99;
        let err = prelude.validate_against(Some(&state)).unwrap_err();
        assert_eq!(err, PreludeReject::CidMismatch { got: 99, want: 7 });
    }

    #[test]
    fn prelude_validation_refuses_stale_epoch() {
        let state = sample_state();
        let mut prelude = sample_prelude();
        prelude.epoch = state.not_before - 1;
        let err = prelude.validate_against(Some(&state)).unwrap_err();
        assert_eq!(
            err,
            PreludeReject::Stale {
                got: state.not_before - 1,
                not_before: state.not_before
            }
        );
    }
}
