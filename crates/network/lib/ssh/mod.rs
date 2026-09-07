//! SSH flow classification and divert/direct/deny policy.
//!
//! [`classifier`] recognizes plaintext SSH identification strings with a
//! bounded streaming matcher; [`policy`] composes the classification with
//! the generic egress verdict and an SSH-specific grant set into a
//! divert/direct/deny decision for the egress path to enforce.

pub mod classifier;
pub mod policy;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use classifier::{SshClassification, SshClassifier, classify_ssh_bytes};
pub use policy::{
    BrokerEndpoint, BrokerEndpointError, SshDecision, SshFlow, SshGrant, SshPolicy,
    decide_ssh_egress,
};
