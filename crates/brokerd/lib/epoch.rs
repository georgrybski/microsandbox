//! SSH epoch binding for the broker VM.
//!
//! The host provisions the current SSH epoch over the console agent port
//! (virtio-console, generation-8 codec) with [`SshEpochProvision`]; brokerd
//! binds that epoch to its transport CID, acknowledges with
//! [`SshEpochAck`], and validates every divert prelude against the bound
//! state. Newer provisions supersede older ones; stale provisions are
//! acknowledged negatively and never applied.

use microsandbox_protocol::core::{SshEpochAck, SshEpochProvision};
use thiserror::Error;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Epoch state bound from the latest accepted console provision.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EpochState {
    /// Sandbox instance the epoch belongs to.
    pub instance: String,

    /// Transport CID the epoch is bound to.
    pub cid: u32,

    /// Monotonic epoch number; newer epochs supersede older ones.
    pub epoch: u64,

    /// Unix seconds when the epoch was issued.
    pub issued_at: u64,

    /// Unix seconds before which divert times are refused as stale.
    pub not_before: u64,
}

/// Every way an epoch provision can be refused.
#[derive(Debug, Error)]
pub enum EpochError {
    /// The provision targets a different instance than the bound state.
    #[error("epoch provision for instance '{got}' does not match bound '{want}'")]
    InstanceMismatch {
        /// Instance observed in the provision.
        got: String,

        /// Instance already bound.
        want: String,
    },
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Apply a console epoch provision to the bound state.
///
/// The first provision for an instance binds it; a newer monotonic epoch
/// for the bound instance supersedes. A provision for a different instance
/// is refused (transport-CID-wins: the bound CID keeps serving its
/// instance), and a stale epoch is acknowledged negatively without
/// touching the bound state. The returned ack always carries the
/// provision's CID and epoch so the host can correlate it.
pub fn apply_provision(
    state: &mut Option<EpochState>,
    provision: &SshEpochProvision,
) -> Result<SshEpochAck, EpochError> {
    let ack_for = |ok: bool| SshEpochAck {
        cid: provision.cid,
        epoch: provision.epoch,
        ok,
    };
    match state {
        None => {
            *state = Some(EpochState {
                instance: provision.instance.clone(),
                cid: provision.cid,
                epoch: provision.epoch,
                issued_at: provision.issued_at,
                not_before: provision.not_before,
            });
            Ok(ack_for(true))
        }
        Some(bound) if bound.instance != provision.instance => Err(EpochError::InstanceMismatch {
            got: provision.instance.clone(),
            want: bound.instance.clone(),
        }),
        Some(bound) if provision.epoch <= bound.epoch => Ok(ack_for(false)),
        Some(bound) => {
            *bound = EpochState {
                instance: provision.instance.clone(),
                cid: provision.cid,
                epoch: provision.epoch,
                issued_at: provision.issued_at,
                not_before: provision.not_before,
            };
            Ok(ack_for(true))
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn provision(instance: &str, cid: u32, epoch: u64) -> SshEpochProvision {
        SshEpochProvision {
            instance: instance.to_string(),
            cid,
            epoch,
            issued_at: 1_700_000_000,
            not_before: 1_700_000_000,
        }
    }

    #[test]
    fn first_provision_binds_and_acks_ok() {
        let mut state = None;
        let ack = apply_provision(&mut state, &provision("sandbox-1", 7, 1)).unwrap();
        assert!(ack.ok);
        assert_eq!(ack.cid, 7);
        assert_eq!(ack.epoch, 1);
        let bound = state.unwrap();
        assert_eq!(bound.instance, "sandbox-1");
        assert_eq!(bound.cid, 7);
    }

    #[test]
    fn newer_provision_supersedes_and_older_is_nacked() {
        let mut state = None;
        apply_provision(&mut state, &provision("sandbox-1", 7, 2)).unwrap();
        let ack = apply_provision(&mut state, &provision("sandbox-1", 7, 5)).unwrap();
        assert!(ack.ok);
        assert_eq!(state.as_ref().unwrap().epoch, 5);

        let ack = apply_provision(&mut state, &provision("sandbox-1", 7, 5)).unwrap();
        assert!(!ack.ok, "same epoch must not supersede");
        let ack = apply_provision(&mut state, &provision("sandbox-1", 7, 1)).unwrap();
        assert!(!ack.ok, "stale epoch must not supersede");
        assert_eq!(state.as_ref().unwrap().epoch, 5);
    }

    #[test]
    fn provision_for_another_instance_is_refused() {
        let mut state = None;
        apply_provision(&mut state, &provision("sandbox-1", 7, 1)).unwrap();
        let err = apply_provision(&mut state, &provision("sandbox-2", 9, 2)).unwrap_err();
        assert!(matches!(err, EpochError::InstanceMismatch { .. }));
        assert_eq!(state.as_ref().unwrap().instance, "sandbox-1");
    }
}
