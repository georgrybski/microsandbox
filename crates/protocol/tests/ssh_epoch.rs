//! SSH epoch protocol family: wire names, codec round-trips, and generation gates.
//!
//! `core.ssh_epoch.provision` is host-initiated with a non-zero correlation
//! ID and no frame flags; `core.ssh_epoch.ack` is the guest reply. Both were
//! introduced in generation 8, so older-generation peers must not be offered
//! them under the lower-peer negotiation rules (see `VERSIONING.md`).

use microsandbox_protocol::{
    codec,
    core::{SshEpochAck, SshEpochProvision},
    message::{Message, MessageType, PROTOCOL_VERSION},
};

#[test]
fn ssh_epoch_wire_names_roundtrip() {
    assert_eq!(
        MessageType::SshEpochProvision.as_str(),
        "core.ssh_epoch.provision"
    );
    assert_eq!(MessageType::SshEpochAck.as_str(), "core.ssh_epoch.ack");
    assert_eq!(
        MessageType::from_wire_str("core.ssh_epoch.provision"),
        Some(MessageType::SshEpochProvision)
    );
    assert_eq!(
        MessageType::from_wire_str("core.ssh_epoch.ack"),
        Some(MessageType::SshEpochAck)
    );
}

#[test]
fn ssh_epoch_flags_are_zero() {
    assert_eq!(MessageType::SshEpochProvision.flags(), 0);
    assert_eq!(MessageType::SshEpochAck.flags(), 0);
}

#[test]
fn ssh_epoch_introduced_in_generation_8() {
    assert_eq!(MessageType::SshEpochProvision.min_protocol_version(), 8);
    assert_eq!(MessageType::SshEpochAck.min_protocol_version(), 8);
    assert_eq!(PROTOCOL_VERSION, 8);
}

#[test]
fn ssh_epoch_unavailable_to_older_generations() {
    for peer in [1, 2, 4, 5, 6, 7] {
        assert!(
            !MessageType::SshEpochProvision.is_available_at(peer),
            "provision must be unavailable at generation {peer}"
        );
        assert!(
            !MessageType::SshEpochAck.is_available_at(peer),
            "ack must be unavailable at generation {peer}"
        );
    }
    assert!(MessageType::SshEpochProvision.is_available_at(8));
    assert!(MessageType::SshEpochAck.is_available_at(8));
    assert!(MessageType::SshEpochProvision.is_available_at(PROTOCOL_VERSION));
    assert!(MessageType::SshEpochAck.is_available_at(PROTOCOL_VERSION));
}

#[test]
fn ssh_epoch_provision_codec_roundtrip() {
    let payload = SshEpochProvision {
        instance: "sandbox-01".to_string(),
        cid: 42,
        epoch: 7,
        issued_at: 1_700_000_000,
        not_before: 1_699_999_990,
    };
    let msg = Message::with_payload(MessageType::SshEpochProvision, 11, &payload).unwrap();
    assert_eq!(msg.v, PROTOCOL_VERSION);
    assert_eq!(msg.id, 11);
    assert_ne!(msg.id, 0);
    assert_eq!(msg.flags, 0);

    let mut frame = Vec::new();
    codec::encode_to_buf(&msg, &mut frame).unwrap();
    let decoded = codec::decode_message_frame(&frame).unwrap();
    assert_eq!(decoded.t, MessageType::SshEpochProvision);
    assert_eq!(decoded.id, 11);
    assert_eq!(decoded.flags, 0);
    assert_eq!(decoded.v, PROTOCOL_VERSION);

    let body: SshEpochProvision = decoded.payload().unwrap();
    assert_eq!(body.instance, payload.instance);
    assert_eq!(body.cid, payload.cid);
    assert_eq!(body.epoch, payload.epoch);
    assert_eq!(body.issued_at, payload.issued_at);
    assert_eq!(body.not_before, payload.not_before);
}

#[test]
fn ssh_epoch_ack_codec_roundtrip() {
    let payload = SshEpochAck {
        cid: 42,
        epoch: 7,
        ok: true,
    };
    let msg = Message::with_payload(MessageType::SshEpochAck, 11, &payload).unwrap();
    assert_eq!(msg.v, PROTOCOL_VERSION);
    assert_eq!(msg.id, 11);
    assert_eq!(msg.flags, 0);

    let mut frame = Vec::new();
    codec::encode_to_buf(&msg, &mut frame).unwrap();
    let decoded = codec::decode_message_frame(&frame).unwrap();
    assert_eq!(decoded.t, MessageType::SshEpochAck);
    assert_eq!(decoded.id, 11);
    assert_eq!(decoded.flags, 0);

    let body: SshEpochAck = decoded.payload().unwrap();
    assert_eq!(body.cid, payload.cid);
    assert_eq!(body.epoch, payload.epoch);
    assert_eq!(body.ok, payload.ok);
}

#[test]
fn ssh_epoch_ack_negative_codec_roundtrip() {
    let payload = SshEpochAck {
        cid: 9,
        epoch: 3,
        ok: false,
    };
    let msg = Message::with_payload(MessageType::SshEpochAck, 5, &payload).unwrap();
    let mut frame = Vec::new();
    codec::encode_to_buf(&msg, &mut frame).unwrap();
    let decoded = codec::decode_message_frame(&frame).unwrap();
    let body: SshEpochAck = decoded.payload().unwrap();
    assert_eq!(body.cid, 9);
    assert_eq!(body.epoch, 3);
    assert!(!body.ok);
}
