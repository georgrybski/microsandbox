//! SSH flow classification and divert/direct/deny policy.
//!
//! [`classifier`] recognizes plaintext SSH identification strings with a
//! bounded streaming matcher; [`policy`] composes the classification with
//! the generic egress verdict and an SSH-specific grant set into a
//! divert/direct/deny decision for the egress path to enforce; [`gateway`]
//! carries the divert prelude framing and broker relay for the proxy to
//! enforce divert decisions.

pub mod classifier;
pub mod gateway;
pub mod policy;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use classifier::{
    SshClassification, SshClassifier, classify_ssh_bytes, trailing_fragment_is_banner_prefix,
};
pub use gateway::{
    SSH_CLASSIFY_TIMEOUT, SSH_PRELUDE_BYTE_BUDGET, SshBrokerBinding, SshDivertPrelude,
    SshGatewayConfig, classify_ssh_directions, combined_ssh_classification, current_epoch_secs,
    decode_ssh_divert_prelude, dial_broker_and_send_prelude, encode_ssh_divert_prelude,
    relay_ssh_via_broker, ssh_flow_for_destination,
};
pub use policy::{
    BrokerEndpoint, BrokerEndpointError, SshDecision, SshFlow, SshGrant, SshPolicy,
    decide_ssh_egress, decide_ssh_endpoint,
};
