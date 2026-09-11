//! Shim↔brokerd framing end-to-end over Unix socket pairs (no VM).
//!
//! Simulates the host shim side (prelude send, then SSH bytes) against the
//! brokerd side (prelude read, epoch/CID validation, then byte pump toward
//! a simulated egress leg), proving the divert contract without vsock.

use microsandbox_brokerd::broker::relay_bytes;
use microsandbox_brokerd::config::MAX_PRELUDE_BYTES;
use microsandbox_brokerd::epoch::{EpochState, apply_provision};
use microsandbox_brokerd::prelude::{
    PreludeReject, SshDivertPrelude, read_ssh_divert_prelude, write_ssh_divert_prelude,
};
use microsandbox_protocol::core::SshEpochProvision;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn provision() -> SshEpochProvision {
    SshEpochProvision {
        instance: "sandbox-1".to_string(),
        cid: 7,
        epoch: 3,
        issued_at: 1_700_000_000,
        not_before: 1_700_000_000,
    }
}

fn bound_state() -> EpochState {
    let mut state = None;
    apply_provision(&mut state, &provision()).unwrap();
    state.unwrap()
}

#[tokio::test]
async fn divert_framing_end_to_end_accepts_bound_session() {
    let state = bound_state();
    // Shim leg (host proxy side) and broker leg (accepted divert stream).
    let (mut shim, mut broker_leg) = tokio::net::UnixStream::pair().unwrap();
    // Egress leg: broker side pumps validated bytes here; the far end
    // stands in for the host-side TCP forwarder.
    let (mut egress_near, mut egress_far) = tokio::net::UnixStream::pair().unwrap();

    let prelude = SshDivertPrelude {
        dest_host: "example.com".to_string(),
        dest_port: 22,
        transport_cid: 7,
        epoch: 1_700_000_100,
    };
    write_ssh_divert_prelude(&mut shim, &prelude).await.unwrap();
    shim.write_all(b"SSH-2.0-OpenSSH_9.6\r\n").await.unwrap();

    let decoded = read_ssh_divert_prelude(&mut broker_leg, MAX_PRELUDE_BYTES)
        .await
        .unwrap();
    assert_eq!(decoded, prelude);
    decoded.validate_against(Some(&state)).unwrap();

    let pump = tokio::spawn(async move {
        relay_bytes(&mut broker_leg, &mut egress_near)
            .await
            .unwrap();
    });

    // The guest first flight arrives at the egress leg intact.
    let mut banner = [0u8; 21];
    egress_far.read_exact(&mut banner).await.unwrap();
    assert_eq!(&banner, b"SSH-2.0-OpenSSH_9.6\r\n");

    // And bytes flow back toward the guest.
    egress_far.write_all(b"SSH-2.0-Broker\r\n").await.unwrap();
    let mut back = [0u8; 16];
    shim.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"SSH-2.0-Broker\r\n");

    drop(shim);
    drop(egress_far);
    let _ = pump.await;
}

#[tokio::test]
async fn divert_framing_end_to_end_refuses_spoofed_cid() {
    let state = bound_state();
    let (mut shim, mut broker_leg) = tokio::net::UnixStream::pair().unwrap();

    let spoofed = SshDivertPrelude {
        dest_host: "example.com".to_string(),
        dest_port: 22,
        transport_cid: 99,
        epoch: 1_700_000_100,
    };
    write_ssh_divert_prelude(&mut shim, &spoofed).await.unwrap();
    let decoded = read_ssh_divert_prelude(&mut broker_leg, MAX_PRELUDE_BYTES)
        .await
        .unwrap();
    let err = decoded.validate_against(Some(&state)).unwrap_err();
    assert_eq!(err, PreludeReject::CidMismatch { got: 99, want: 7 });
}

#[tokio::test]
async fn divert_framing_end_to_end_refuses_stale_epoch() {
    let state = bound_state();
    let (mut shim, mut broker_leg) = tokio::net::UnixStream::pair().unwrap();

    let stale = SshDivertPrelude {
        dest_host: "example.com".to_string(),
        dest_port: 22,
        transport_cid: 7,
        epoch: 1_699_999_999,
    };
    write_ssh_divert_prelude(&mut shim, &stale).await.unwrap();
    let decoded = read_ssh_divert_prelude(&mut broker_leg, MAX_PRELUDE_BYTES)
        .await
        .unwrap();
    assert!(matches!(
        decoded.validate_against(Some(&state)),
        Err(PreludeReject::Stale { .. })
    ));
}
