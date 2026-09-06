//! SSH divert/direct/deny policy view and decision function.
//!
//! This module composes with the existing egress machinery without changing
//! its semantics: the caller first evaluates the generic transport policy
//! ([`Action`] via `NetworkPolicy::evaluate_egress`), classifies the flow
//! with [`SshClassification`](super::classifier::SshClassification), then
//! calls [`decide_ssh_egress`] for the final routing verdict.
//!
//! Deny strength reuses the secrets [`ViolationAction`] vocabulary
//! (`Block`, `BlockAndLog`, `BlockAndTerminate`) so SSH enforcement logs
//! and terminates the same way secret violations do. The SSH policy never
//! emits `Passthrough`; a `Passthrough` value stored on the policy is
//! coerced to `Block` (fail closed).
//!
//! ## Call-site shape
//!
//! The egress path (for example `crates/network/lib/tcp/proxy.rs`) calls:
//!
//! 1. `NetworkPolicy::evaluate_egress` (or `evaluate_egress_with_source`)
//!    for the generic TCP `Allow`/`Deny`.
//! 2. The streaming [`SshClassifier`](super::classifier::SshClassifier)
//!    over the plaintext pre-key-exchange bytes (guest first flight or
//!    server banner).
//! 3. [`decide_ssh_egress`] with the flow host/port, the classification,
//!    the egress [`Action`], the [`SshPolicy`], and the optional
//!    [`BrokerEndpoint`].
//!
//! This module does not hook the proxy data path itself; it only exposes
//! the decision function and its inputs for the egress path to call.
//!
//! ## Wiring point
//!
//! No `CredentialsPlan` or broker handoff exists in this tree (no
//! workestrate crate). The workestrate control plane is expected to
//! compile `[policy.ssh]` plus grants into the runtime [`SshPolicy`]
//! view defined here, and to supply the [`BrokerEndpoint`] for the
//! unix-socket shim when divert is configured. Until that wiring lands,
//! callers construct [`SshPolicy`] directly and pass `None` for the
//! broker to get direct-or-deny behavior.

use crate::policy::{Action, PortRange};
use crate::secrets::config::{HostPattern, ViolationAction};

use super::classifier::SshClassification;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Flow destination for an SSH decision: the dialed host and port.
///
/// `host` is the guest-observed destination name (SNI or resolved-hostname
/// cache hit when known, otherwise the stringified destination IP) and
/// `port` is the destination port. Construction trims a single trailing
/// dot so `example.com.` matches the same grants as `example.com`;
/// matching itself is ASCII case-insensitive via [`HostPattern`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshFlow {
    /// Destination host name or stringified IP.
    pub host: String,
    /// Destination port.
    pub port: u16,
}

/// One SSH allowance: a host pattern plus the ports it covers.
///
/// An empty `ports` set matches any port, mirroring [`crate::policy::Rule`]
/// port semantics. Ports are otherwise matched with
/// [`PortRange::contains`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshGrant {
    /// Host pattern this grant covers.
    pub host: HostPattern,
    /// Port ranges this grant covers (empty means any port).
    pub ports: Vec<PortRange>,
}

/// SSH-specific policy view.
///
/// Composes with, but does not alter, the generic [`Action`] egress
/// policy. `strict` selects confinement: when `true`, an SSH flow to a
/// non-granted destination is denied even if generic TCP egress would
/// allow it. When `false`, non-granted SSH flows follow the generic
/// egress verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshPolicy {
    /// When `true`, SSH to non-granted destinations is denied even if
    /// generic TCP egress allows it.
    pub strict: bool,
    /// SSH allowances consulted for divert and strict-deny.
    pub grants: Vec<SshGrant>,
    /// Deny strength for SSH violations. `Passthrough` is coerced to
    /// `Block` (fail closed) since placeholder forwarding is meaningless
    /// for SSH routing.
    pub on_violation: ViolationAction,
}

/// Abstract divert target for the credentials broker.
///
/// Opaque for this task: the later shim integration (unix-socket dial,
/// transport CID stamping, epoch prelude) interprets `address`. The
/// decision function only needs to know whether a broker path is
/// configured (`Some`) or not (`None`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerEndpoint {
    /// Broker address in a future-shim-defined form (for example a
    /// unix-socket path). Treated opaquely here.
    pub address: String,
}

/// Final routing verdict for an egress flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshDecision {
    /// Proxy the SSH session through the credentials broker.
    Divert {
        /// Broker endpoint to divert to.
        endpoint: BrokerEndpoint,
    },
    /// Connect directly to the destination.
    Direct,
    /// Refuse the connection with secrets-style deny strength.
    Deny {
        /// How to enforce and report the deny.
        action: ViolationAction,
    },
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SshFlow {
    /// Create a flow destination, trimming a trailing dot from `host`.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        let raw: String = host.into();
        let trimmed = raw.trim_end_matches('.');
        let host = if trimmed.is_empty() {
            raw
        } else {
            trimmed.to_string()
        };
        Self { host, port }
    }
}

impl SshGrant {
    /// Create a grant from a host pattern and port ranges.
    pub fn new(host: HostPattern, ports: Vec<PortRange>) -> Self {
        Self { host, ports }
    }

    /// Grant an exact host on a single port.
    pub fn exact(host: &str, port: u16) -> Self {
        Self {
            host: HostPattern::Exact(host.to_string()),
            ports: vec![PortRange::single(port)],
        }
    }

    /// Returns `true` when this grant covers `flow` (host and port).
    pub fn matches(&self, flow: &SshFlow) -> bool {
        if !self.host.matches(&flow.host) {
            return false;
        }
        if self.ports.is_empty() {
            return true;
        }
        self.ports.iter().any(|range| range.contains(flow.port))
    }
}

impl SshPolicy {
    /// Create a policy with default deny strength
    /// ([`ViolationAction::BlockAndLog`]).
    pub fn new(strict: bool, grants: Vec<SshGrant>) -> Self {
        Self {
            strict,
            grants,
            on_violation: ViolationAction::default(),
        }
    }

    /// Override the deny strength.
    pub fn with_violation(mut self, action: ViolationAction) -> Self {
        self.on_violation = action;
        self
    }

    /// Returns `true` when any grant covers `flow`.
    pub fn is_granted(&self, flow: &SshFlow) -> bool {
        self.grants.iter().any(|grant| grant.matches(flow))
    }

    /// Deny strength for this policy, coercing `Passthrough` to `Block`.
    pub fn deny_action(&self) -> ViolationAction {
        match &self.on_violation {
            ViolationAction::Passthrough(_) => ViolationAction::Block,
            action => action.clone(),
        }
    }
}

impl BrokerEndpoint {
    /// Create an opaque broker endpoint.
    pub fn new(address: impl Into<String>) -> Self {
        Self {
            address: address.into(),
        }
    }
}

impl SshDecision {
    /// Returns `true` for [`SshDecision::Divert`].
    pub fn is_divert(&self) -> bool {
        matches!(self, SshDecision::Divert { .. })
    }

    /// Returns `true` for [`SshDecision::Direct`].
    pub fn is_direct(&self) -> bool {
        matches!(self, SshDecision::Direct)
    }

    /// Returns `true` for [`SshDecision::Deny`].
    pub fn is_deny(&self) -> bool {
        matches!(self, SshDecision::Deny { .. })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Decide divert/direct/deny for an egress flow.
///
/// `egress` is the generic transport verdict the caller already computed
/// with `NetworkPolicy::evaluate_egress` (default-deny included), so
/// unclassified flows and non-strict SSH flows fall through to it
/// unchanged. `broker` is `Some` when the divert path is configured and
/// `None` otherwise.
///
/// Precedence:
///
/// - Unclassified (`NotSsh` / `NeedMoreData`, for example an incomplete
///   banner at timeout): follow `egress` (`Allow` becomes `Direct`,
///   `Deny` becomes `Deny`).
/// - Classified SSH to a granted destination: `Divert` when the broker
///   is configured and `egress` allows; `Direct` when granted but no
///   broker is configured (documented sensible default, still gated on
///   `egress`); `Deny` when `egress` denies (fail closed).
/// - Classified SSH to a non-granted destination with `strict`: `Deny`
///   even if `egress` allows (protocol-specific restriction overrides
///   the generic transport allowance, including nonstandard ports whose
///   port set misses every grant).
/// - Classified SSH to a non-granted destination without `strict`:
///   follow `egress`.
///
pub fn decide_ssh_egress(
    flow: &SshFlow,
    classification: SshClassification,
    egress: Action,
    ssh_policy: &SshPolicy,
    broker: Option<&BrokerEndpoint>,
) -> SshDecision {
    if !classification.is_ssh() {
        return match egress {
            Action::Allow => SshDecision::Direct,
            Action::Deny => SshDecision::Deny {
                action: ssh_policy.deny_action(),
            },
        };
    }

    if ssh_policy.is_granted(flow) {
        match egress {
            Action::Deny => SshDecision::Deny {
                action: ssh_policy.deny_action(),
            },
            Action::Allow => match broker {
                Some(endpoint) => SshDecision::Divert {
                    endpoint: endpoint.clone(),
                },
                None => SshDecision::Direct,
            },
        }
    } else if ssh_policy.strict {
        SshDecision::Deny {
            action: ssh_policy.deny_action(),
        }
    } else {
        match egress {
            Action::Allow => SshDecision::Direct,
            Action::Deny => SshDecision::Deny {
                action: ssh_policy.deny_action(),
            },
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn flow(host: &str, port: u16) -> SshFlow {
        SshFlow::new(host, port)
    }

    fn strict_grant(host: &str, port: u16) -> SshPolicy {
        SshPolicy::new(true, vec![SshGrant::exact(host, port)])
    }

    fn broker() -> BrokerEndpoint {
        BrokerEndpoint::new("unix:///run/msb/ssh-broker.sock")
    }

    #[test]
    fn granted_host_with_strict_and_broker_diverts() {
        let policy = strict_grant("example.com", 22);
        let decision = decide_ssh_egress(
            &flow("example.com", 22),
            SshClassification::Ssh,
            Action::Allow,
            &policy,
            Some(&broker()),
        );
        assert_eq!(decision, SshDecision::Divert { endpoint: broker() });
    }

    #[test]
    fn granted_host_without_broker_goes_direct() {
        let policy = strict_grant("example.com", 22);
        let decision = decide_ssh_egress(
            &flow("example.com", 22),
            SshClassification::Ssh,
            Action::Allow,
            &policy,
            None,
        );
        assert_eq!(decision, SshDecision::Direct);
    }

    #[test]
    fn non_granted_strict_ssh_denies_even_when_tcp_allows() {
        let policy = strict_grant("example.com", 22);
        let decision = decide_ssh_egress(
            &flow("other.example", 22),
            SshClassification::Ssh,
            Action::Allow,
            &policy,
            Some(&broker()),
        );
        assert!(decision.is_deny());
    }

    #[test]
    fn non_granted_non_strict_ssh_follows_tcp_allow() {
        let policy = SshPolicy::new(false, vec![SshGrant::exact("example.com", 22)]);
        let decision = decide_ssh_egress(
            &flow("other.example", 22),
            SshClassification::Ssh,
            Action::Allow,
            &policy,
            Some(&broker()),
        );
        assert_eq!(decision, SshDecision::Direct);
    }

    #[test]
    fn banner_on_nonstandard_port_with_strict_denies() {
        let policy = strict_grant("example.com", 22);
        let decision = decide_ssh_egress(
            &flow("example.com", 2222),
            SshClassification::Ssh,
            Action::Allow,
            &policy,
            Some(&broker()),
        );
        assert!(decision.is_deny());
    }

    #[test]
    fn unclassified_flow_follows_egress_allow() {
        let policy = strict_grant("example.com", 22);
        for classification in [SshClassification::NotSsh, SshClassification::NeedMoreData] {
            let decision = decide_ssh_egress(
                &flow("other.example", 22),
                classification,
                Action::Allow,
                &policy,
                Some(&broker()),
            );
            assert_eq!(decision, SshDecision::Direct);
        }
    }

    #[test]
    fn unclassified_flow_preserves_default_deny() {
        let policy = strict_grant("example.com", 22);
        for classification in [SshClassification::NotSsh, SshClassification::NeedMoreData] {
            let decision = decide_ssh_egress(
                &flow("other.example", 22),
                classification,
                Action::Deny,
                &policy,
                Some(&broker()),
            );
            assert!(decision.is_deny());
        }
    }

    #[test]
    fn granted_flow_with_egress_deny_stays_denied() {
        let policy = strict_grant("example.com", 22);
        let decision = decide_ssh_egress(
            &flow("example.com", 22),
            SshClassification::Ssh,
            Action::Deny,
            &policy,
            Some(&broker()),
        );
        assert!(decision.is_deny());
    }

    #[test]
    fn deny_carries_configured_block_and_terminate() {
        let policy = SshPolicy::new(true, vec![SshGrant::exact("example.com", 22)])
            .with_violation(ViolationAction::BlockAndTerminate);
        let decision = decide_ssh_egress(
            &flow("other.example", 22),
            SshClassification::Ssh,
            Action::Allow,
            &policy,
            None,
        );
        assert_eq!(
            decision,
            SshDecision::Deny {
                action: ViolationAction::BlockAndTerminate
            }
        );
    }

    #[test]
    fn passthrough_violation_coerces_to_block() {
        let policy = SshPolicy::new(true, vec![SshGrant::exact("example.com", 22)]).with_violation(
            ViolationAction::Passthrough(vec![HostPattern::Exact("example.com".to_string())]),
        );
        let decision = decide_ssh_egress(
            &flow("other.example", 22),
            SshClassification::Ssh,
            Action::Allow,
            &policy,
            None,
        );
        assert_eq!(
            decision,
            SshDecision::Deny {
                action: ViolationAction::Block
            }
        );
    }

    #[test]
    fn grant_host_matching_is_case_insensitive_and_trims_dot() {
        let grant = SshGrant::exact("Example.COM", 22);
        assert!(grant.matches(&flow("example.com.", 22)));
        assert!(grant.matches(&flow("EXAMPLE.com", 22)));
        assert!(!grant.matches(&flow("other.com", 22)));
    }

    #[test]
    fn wildcard_grant_matches_subdomains() {
        let grant = SshGrant::new(
            HostPattern::Wildcard("*.example.com".to_string()),
            vec![PortRange::single(22)],
        );
        assert!(grant.matches(&flow("host.example.com", 22)));
        assert!(!grant.matches(&flow("host.example.com", 2222)));
    }

    #[test]
    fn empty_ports_match_any_port() {
        let grant = SshGrant::new(HostPattern::Exact("example.com".to_string()), vec![]);
        assert!(grant.matches(&flow("example.com", 22)));
        assert!(grant.matches(&flow("example.com", 2222)));
    }
}
