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
//!    over the plaintext pre-key-exchange bytes (guest first flight and
//!    server banner, each fed to its own classifier in arrival order).
//! 3. [`decide_ssh_egress`] with the flow host/port, the classification,
//!    the egress [`Action`], the [`SshPolicy`], and the optional
//!    [`BrokerEndpoint`].
//!
//! This module does not hook the proxy data path itself; it only exposes
//! the decision function and its inputs for the egress path to call.
//!
//! ## Wiring point
//!
//! The control plane compiles SSH grants into the runtime [`SshPolicy`]
//! view defined here and supplies the [`BrokerEndpoint`] for the
//! unix-socket shim when divert is configured. Callers construct
//! [`SshPolicy`] directly and pass `None` for the broker when no divert
//! path exists; granted SSH then denies fail-closed rather than falling
//! back to direct.

use std::path::{Path, PathBuf};

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

/// Divert target for the credentials broker: a validated host-side unix-socket path.
///
/// Host-side only: the socket path names a host IPC endpoint and must never
/// appear in guest-visible configuration. Validation accepts
/// `unix:///absolute/path` or a bare absolute path (`/absolute/path`) and
/// rejects empty, relative, and non-`unix` schemes fail-closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerEndpoint {
    /// Validated absolute unix-socket path.
    path: PathBuf,
}

/// Reason a broker address failed validation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BrokerEndpointError {
    /// The address is empty or carries no path.
    #[error("broker endpoint must not be empty")]
    Empty,
    /// The path is not absolute; the broker socket must live at an absolute
    /// host path so a guest-relative value cannot redirect the dial.
    #[error("broker endpoint path must be absolute: `{0}`")]
    NotAbsolute(String),
    /// The scheme is not `unix`; only host unix sockets are valid divert
    /// targets.
    #[error("broker endpoint scheme must be unix: `{0}`")]
    NonUnixScheme(String),
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
    /// Validate a broker address into a host-side unix-socket path.
    ///
    /// Accepts `unix:///absolute/path` or a bare absolute path such as
    /// `/run/msb/ssh-broker.sock`. Rejects empty values, relative paths,
    /// and non-`unix` schemes fail-closed: callers must treat `Err` as
    /// divert-unavailable and deny divert-intended flows rather than
    /// falling back to direct.
    pub fn new(address: impl AsRef<str>) -> Result<Self, BrokerEndpointError> {
        let raw = address.as_ref();
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(BrokerEndpointError::Empty);
        }
        if let Some(rest) = trimmed.strip_prefix("unix://") {
            if rest.is_empty() {
                return Err(BrokerEndpointError::Empty);
            }
            if !rest.starts_with('/') {
                return Err(BrokerEndpointError::NotAbsolute(trimmed.to_string()));
            }
            return Ok(Self {
                path: PathBuf::from(rest),
            });
        }
        if trimmed.contains("://") {
            return Err(BrokerEndpointError::NonUnixScheme(trimmed.to_string()));
        }
        if trimmed.starts_with("unix:") {
            return Err(BrokerEndpointError::NonUnixScheme(trimmed.to_string()));
        }
        if !trimmed.starts_with('/') {
            return Err(BrokerEndpointError::NotAbsolute(trimmed.to_string()));
        }
        Ok(Self {
            path: PathBuf::from(trimmed),
        })
    }

    /// Validated absolute unix-socket path for dialing the broker.
    pub fn path(&self) -> &Path {
        &self.path
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
/// `None` otherwise; a broker dial failure is enforced as `Deny` by the
/// proxy path, never by silently falling back to `Direct`.
///
/// Precedence:
///
/// - Unclassified (`NotSsh` / `NeedMoreData`, for example an incomplete
///   banner at timeout): follow `egress` (`Allow` becomes `Direct`,
///   `Deny` becomes `Deny`).
/// - Classified SSH to a granted destination: `Divert` when the broker
///   is configured and `egress` allows; `Deny` when `egress` denies or
///   when no broker is configured (fail closed: a granted flow without a
///   divert path never falls back to direct, since that would bypass
///   broker authentication silently).
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
            // Divert-intended without a broker path denies fail-closed;
            // falling back to direct would silently bypass broker
            // authentication, so it is never allowed.
            Action::Allow => match broker {
                Some(endpoint) => SshDecision::Divert {
                    endpoint: endpoint.clone(),
                },
                None => SshDecision::Deny {
                    action: ssh_policy.deny_action(),
                },
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
        BrokerEndpoint::new("unix:///run/msb/ssh-broker.sock").expect("test broker must validate")
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
    fn granted_host_without_broker_denies_fail_closed() {
        let policy = strict_grant("example.com", 22);
        let decision = decide_ssh_egress(
            &flow("example.com", 22),
            SshClassification::Ssh,
            Action::Allow,
            &policy,
            None,
        );
        assert!(
            decision.is_deny(),
            "divert-intended without a broker path must deny, never fall back to direct: got {decision:?}"
        );
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

    #[test]
    fn broker_endpoint_accepts_unix_and_bare_absolute_paths() {
        let unix = BrokerEndpoint::new("unix:///run/msb/ssh-broker.sock").expect("unix scheme");
        assert_eq!(
            unix.path().as_os_str(),
            std::ffi::OsStr::new("/run/msb/ssh-broker.sock")
        );
        let bare = BrokerEndpoint::new("/run/msb/ssh-broker.sock").expect("bare absolute path");
        assert_eq!(
            bare.path().as_os_str(),
            std::ffi::OsStr::new("/run/msb/ssh-broker.sock")
        );
        assert_eq!(unix, bare);
    }

    #[test]
    fn broker_endpoint_rejects_relative_empty_and_non_unix() {
        assert_eq!(BrokerEndpoint::new(""), Err(BrokerEndpointError::Empty));
        assert_eq!(BrokerEndpoint::new("   "), Err(BrokerEndpointError::Empty));
        assert_eq!(
            BrokerEndpoint::new("unix://"),
            Err(BrokerEndpointError::Empty)
        );
        assert!(matches!(
            BrokerEndpoint::new("run/msb/broker.sock"),
            Err(BrokerEndpointError::NotAbsolute(_))
        ));
        assert!(matches!(
            BrokerEndpoint::new("unix://run/msb/broker.sock"),
            Err(BrokerEndpointError::NotAbsolute(_))
        ));
        assert!(matches!(
            BrokerEndpoint::new("tcp://127.0.0.1:22"),
            Err(BrokerEndpointError::NonUnixScheme(_))
        ));
        assert!(matches!(
            BrokerEndpoint::new("http://example.com/broker"),
            Err(BrokerEndpointError::NonUnixScheme(_))
        ));
        assert!(matches!(
            BrokerEndpoint::new("unix:/run/msb/broker.sock"),
            Err(BrokerEndpointError::NonUnixScheme(_))
        ));
    }

    /// Fail-closed matrix over classification × strict × grants × egress ×
    /// broker presence. Divert-intended without a broker path denies
    /// (never direct); unclassified flows follow the generic egress
    /// verdict unchanged.
    #[test]
    fn fail_closed_matrix_covers_classification_strict_grants_egress_broker() {
        struct Case {
            name: &'static str,
            classification: SshClassification,
            strict: bool,
            grants: bool,
            egress: Action,
            broker: bool,
            expect_divert: bool,
            expect_direct: bool,
        }

        let granted = vec![SshGrant::exact("example.com", 22)];
        let cases = [
            // Divert-intended: granted SSH with egress allow diverts only
            // when the broker path is present; absent denies fail-closed.
            Case {
                name: "ssh granted strict allow broker diverts",
                classification: SshClassification::Ssh,
                strict: true,
                grants: true,
                egress: Action::Allow,
                broker: true,
                expect_divert: true,
                expect_direct: false,
            },
            Case {
                name: "ssh granted strict allow absent denies",
                classification: SshClassification::Ssh,
                strict: true,
                grants: true,
                egress: Action::Allow,
                broker: false,
                expect_divert: false,
                expect_direct: false,
            },
            Case {
                name: "ssh granted non-strict allow broker diverts",
                classification: SshClassification::Ssh,
                strict: false,
                grants: true,
                egress: Action::Allow,
                broker: true,
                expect_divert: true,
                expect_direct: false,
            },
            Case {
                name: "ssh granted non-strict allow absent denies",
                classification: SshClassification::Ssh,
                strict: false,
                grants: true,
                egress: Action::Allow,
                broker: false,
                expect_divert: false,
                expect_direct: false,
            },
            // Granted SSH with egress deny always denies.
            Case {
                name: "ssh granted strict deny broker denies",
                classification: SshClassification::Ssh,
                strict: true,
                grants: true,
                egress: Action::Deny,
                broker: true,
                expect_divert: false,
                expect_direct: false,
            },
            Case {
                name: "ssh granted strict deny absent denies",
                classification: SshClassification::Ssh,
                strict: true,
                grants: true,
                egress: Action::Deny,
                broker: false,
                expect_divert: false,
                expect_direct: false,
            },
            // Non-granted SSH with strict denies even when egress allows.
            Case {
                name: "ssh non-granted strict allow broker denies",
                classification: SshClassification::Ssh,
                strict: true,
                grants: false,
                egress: Action::Allow,
                broker: true,
                expect_divert: false,
                expect_direct: false,
            },
            Case {
                name: "ssh non-granted strict allow absent denies",
                classification: SshClassification::Ssh,
                strict: true,
                grants: false,
                egress: Action::Allow,
                broker: false,
                expect_divert: false,
                expect_direct: false,
            },
            // Non-granted SSH without strict follows egress.
            Case {
                name: "ssh non-granted non-strict allow follows direct",
                classification: SshClassification::Ssh,
                strict: false,
                grants: false,
                egress: Action::Allow,
                broker: true,
                expect_divert: false,
                expect_direct: true,
            },
            Case {
                name: "ssh non-granted non-strict deny denies",
                classification: SshClassification::Ssh,
                strict: false,
                grants: false,
                egress: Action::Deny,
                broker: true,
                expect_divert: false,
                expect_direct: false,
            },
            // Empty grants with strict behave as non-granted strict.
            Case {
                name: "ssh empty strict allow denies",
                classification: SshClassification::Ssh,
                strict: true,
                grants: false,
                egress: Action::Allow,
                broker: true,
                expect_divert: false,
                expect_direct: false,
            },
            // Unclassified flows follow egress unchanged regardless of
            // strict, grants, or broker presence.
            Case {
                name: "not-ssh strict allow follows direct",
                classification: SshClassification::NotSsh,
                strict: true,
                grants: true,
                egress: Action::Allow,
                broker: true,
                expect_divert: false,
                expect_direct: true,
            },
            Case {
                name: "not-ssh strict deny denies",
                classification: SshClassification::NotSsh,
                strict: true,
                grants: true,
                egress: Action::Deny,
                broker: true,
                expect_divert: false,
                expect_direct: false,
            },
            Case {
                name: "need-more-data strict allow follows direct",
                classification: SshClassification::NeedMoreData,
                strict: true,
                grants: true,
                egress: Action::Allow,
                broker: false,
                expect_divert: false,
                expect_direct: true,
            },
            Case {
                name: "need-more-data strict deny denies",
                classification: SshClassification::NeedMoreData,
                strict: true,
                grants: true,
                egress: Action::Deny,
                broker: false,
                expect_divert: false,
                expect_direct: false,
            },
            Case {
                name: "need-more-data non-strict empty allow follows direct",
                classification: SshClassification::NeedMoreData,
                strict: false,
                grants: false,
                egress: Action::Allow,
                broker: false,
                expect_divert: false,
                expect_direct: true,
            },
        ];

        for case in cases {
            let policy = SshPolicy::new(
                case.strict,
                if case.grants {
                    granted.clone()
                } else {
                    Vec::new()
                },
            );
            let broker_endpoint = broker();
            let decision = decide_ssh_egress(
                &flow("example.com", 22),
                case.classification,
                case.egress,
                &policy,
                case.broker.then_some(&broker_endpoint),
            );
            match (case.expect_divert, case.expect_direct) {
                (true, _) => assert!(
                    decision.is_divert(),
                    "{}: expected divert, got {decision:?}",
                    case.name
                ),
                (_, true) => assert_eq!(
                    decision,
                    SshDecision::Direct,
                    "{}: expected direct (egress fallthrough)",
                    case.name
                ),
                _ => assert!(
                    decision.is_deny(),
                    "{}: expected deny, got {decision:?}",
                    case.name
                ),
            }
            // Divert-intended without a broker must never silently fall
            // back to direct.
            if case.classification.is_ssh()
                && case.grants
                && case.egress == Action::Allow
                && !case.broker
            {
                assert!(
                    !decision.is_direct(),
                    "{}: absent broker must not fall back to direct",
                    case.name
                );
            }
        }
    }
}
