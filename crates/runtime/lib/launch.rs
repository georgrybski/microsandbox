//! The typed launch contract between the SDK and the `msb sandbox` process.
//!
//! [`LaunchConfig`] is the bulk of a sandbox's configuration. The SDK builds
//! it, serializes it as JSON, and hands it to `msb sandbox` over an inherited
//! file descriptor (see [`crate::vm::CONFIG_FD`]); the process deserializes it
//! and builds its [`crate::vm::Config`] from it. Only a few operator-readable
//! labels and the real inherited fds stay on the process argv. This keeps the
//! network config and secret-bearing env out of `ps` and `/proc/<pid>/cmdline`
//! — see issue #997.

use std::collections::HashSet;
use std::path::PathBuf;

use microsandbox_protocol::bootstrap::GuestBootstrap;
use microsandbox_types::{CpuPlacement, DeploymentProfile, PlacementProfile, VsockRouteSpec};
use serde::{Deserialize, Serialize};

use microsandbox_types::TransparentHugePagePolicy;

#[cfg(feature = "net")]
use microsandbox_network::ResolvedNetworkConfig;

use crate::vm::{MetricsSlotHandoff, StartupCommand};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Must-understand launcher capability for assigning and checking a guest CID.
pub const GUEST_CID_CAPABILITY: &str = "guest-cid-v1";

/// Must-understand launch requirement for device-owned host-to-guest listeners.
pub const HOST_VSOCK_LISTEN_CAPABILITY: &str = "host-vsock-listen-v1";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A transient supervisor-owned Unix listener forwarding into a guest vsock port.
///
/// Unlike durable guest-to-host routes, this path belongs to one launch and must
/// be provided again after replacement or restart. No application identity is
/// derived from bytes sent through this endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostVsockListener {
    /// Fresh absolute socket pathname inside a private supervisor-owned directory.
    pub host_socket: PathBuf,
    /// Guest stream port accepting connections from the vsock host CID.
    pub guest_port: u32,
}

/// The bulk `msb sandbox` configuration delivered over the config fd.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct LaunchConfig {
    /// Path to the sandbox database file.
    pub db_path: PathBuf,

    /// Timeout when acquiring a sandbox database connection from the pool.
    pub db_connect_timeout_secs: u64,

    /// Directory for log files.
    pub log_dir: PathBuf,

    /// Runtime directory (scripts, heartbeat).
    pub runtime_dir: PathBuf,

    /// Approved root beneath which `policy=` mount tokens are resolved.
    ///
    /// Host-side and user-owned (anchored at `MSB_HOME/mount-policy`, not the
    /// per-sandbox runtime directory). The fail-closed loader
    /// (`vm::load_mount_policy`) still rejects absolute paths and `..`
    /// components and walks each component with `O_NOFOLLOW` beneath this
    /// root. Empty means a legacy launch config; the loader falls back to
    /// `<runtime_dir>/mount-policy`.
    #[serde(default)]
    pub mount_policy_dir: PathBuf,

    /// Root directory holding every sandbox's persisted state.
    pub sandboxes_dir: PathBuf,

    /// Root directory holding ephemeral host-runtime artifacts.
    #[serde(default)]
    pub run_dir: PathBuf,

    /// Internal directory containing process-held CPU allocation leases.
    pub cpu_lease_dir: PathBuf,

    /// Internal directory containing process-held writeback pressure leases.
    pub writeback_lease_dir: PathBuf,

    /// Requested host CPU placement policy.
    pub cpu_placement: CpuPlacement,

    /// Host-defined profile name retained for diagnostics and missing-profile validation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placement_profile_name: Option<String>,

    /// Host-resolved profile definition; sandbox clients submit only the name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placement_profile: Option<PlacementProfile>,

    /// Path to the Unix domain socket for the agent relay.
    pub agent_sock: PathBuf,

    /// Path to the libkrunfw shared library.
    pub libkrunfw_path: PathBuf,

    /// Guest transparent huge-page policy selected at boot.
    #[serde(default)]
    pub thp: TransparentHugePagePolicy,

    /// Whether the guest receives the host's nested CPU virtualization
    /// capability (Linux x86_64 only). Defaults to off; absent in launch
    /// payloads from older launchers means off.
    #[serde(default)]
    pub nested_virt: bool,

    /// Per-writable-raw-disk hard budget for buffered host dirty data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_writeback_limit_bytes: Option<u64>,

    /// Host-global dirty-credit pool shared fairly by live writable disks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_writeback_pool_bytes: Option<u64>,

    /// User workload to start after boot, if any.
    pub startup: Option<StartupCommand>,

    /// Lifetime bounds for the sandbox.
    pub lifecycle: Lifecycle,

    /// Metrics sampling configuration and the host-reserved slot.
    pub metrics: MetricsConfig,

    /// Root filesystem source.
    pub rootfs: RootfsConfig,

    /// Additional virtio-fs mounts as `tag:host_path[:opts]`.
    pub mounts: Vec<String>,

    /// Isolated host-file mounts handled by the single-file backend.
    #[serde(default)]
    pub file_mounts: Vec<FileMountConfig>,

    /// Disk-image volume mounts as `id:host_path:format[:ro]`.
    pub disks: Vec<String>,

    /// Path to the init binary in the guest.
    pub init_path: Option<PathBuf>,

    /// Typed one-shot configuration delivered to agentd over its console.
    pub bootstrap: GuestBootstrap,

    /// Path to the executable to run in the guest.
    pub exec_path: Option<PathBuf>,

    /// Arguments to pass to the executable.
    pub exec_args: Vec<String>,

    /// Network launch configuration. Present only when the `net` feature is on.
    #[cfg(feature = "net")]
    pub network: Option<ResolvedNetworkConfig>,

    /// Host-runtime isolation profile enforced by backend implementations.
    #[cfg(feature = "net")]
    #[serde(default)]
    pub deployment_profile: DeploymentProfile,

    /// Sandbox slot for deterministic network address derivation.
    #[cfg(feature = "net")]
    pub sandbox_slot: u16,

    /// Host Unix sockets exposed through virtio-vsock.
    #[serde(default)]
    pub vsock: Vec<VsockRouteSpec>,

    /// CID reserved by the host supervisor for this launch, never a network slot.
    ///
    /// The launcher must require [`GUEST_CID_CAPABILITY`] on the runtime argv:
    /// an older runtime must refuse, not silently discard this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest_cid: Option<u32>,

    /// Transient host-to-guest listeners; requires [`HOST_VSOCK_LISTEN_CAPABILITY`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub host_vsock_listeners: Vec<HostVsockListener>,
}

/// Lifetime bounds for the sandbox.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Lifecycle {
    /// Hard cap on total sandbox lifetime in seconds.
    pub max_duration_secs: Option<u64>,

    /// Idle timeout in seconds.
    pub idle_timeout_secs: Option<u64>,
}

/// Metrics sampling configuration.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Sampling interval in milliseconds.
    pub sample_interval_ms: u64,

    /// Disable sampling; overrides `sample_interval_ms`.
    pub disabled: bool,

    /// Host-reserved shared-memory slot, if metrics are enabled.
    pub slot: Option<MetricsSlotHandoff>,
}

/// Root filesystem source for the sandbox.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RootfsConfig {
    /// Root filesystem path for direct passthrough mounts.
    pub path: Option<PathBuf>,

    /// Follow symlinks when resolving a bind (`path`) rootfs.
    ///
    /// Defaults to `false` (resolve following no symlink), matching the
    /// `--mount` protection for the caller/tenant-provided rootfs path.
    #[serde(default)]
    pub follow_root_symlinks: bool,

    /// Disk image file path for virtio-blk rootfs.
    pub disk: Option<PathBuf>,

    /// Disk image format (qcow2, raw, vmdk).
    pub disk_format: Option<String>,

    /// Mount the disk image as read-only.
    pub disk_readonly: bool,

    /// Writable upper block device for OCI rootfs overlay.
    pub upper: Option<PathBuf>,

    /// Upper disk image format ("raw", "qcow2"). Absent means raw — the
    /// managed `upper.ext4` fast path. Set for user-supplied disk-image
    /// root disks so the runner attaches with the right format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upper_format: Option<String>,
}

/// Host-side configuration for one isolated file mount.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMountConfig {
    /// `tag:host_path[:opts]` specification parsed by the runtime.
    pub mount: String,

    /// Filename presented at the root of the synthetic virtio-fs share.
    pub filename: String,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl LaunchConfig {
    /// Validate must-understand requirements before creating runtime artifacts.
    /// This is a launch compatibility guard, not guest authentication.
    pub fn validate_capabilities(&self, required: &[String]) -> Result<(), String> {
        for capability in required {
            if capability != GUEST_CID_CAPABILITY && capability != HOST_VSOCK_LISTEN_CAPABILITY {
                return Err(format!("unsupported launch capability: {capability}"));
            }
        }
        let requires_cid = required.iter().any(|c| c == GUEST_CID_CAPABILITY);
        if requires_cid != self.guest_cid.is_some() {
            return Err(
                "guest CID and guest-cid-v1 launch requirement must be supplied together".into(),
            );
        }
        if let Some(cid) = self.guest_cid {
            validate_guest_cid(cid)?;
        }
        let requires_listeners = required.iter().any(|c| c == HOST_VSOCK_LISTEN_CAPABILITY);
        if requires_listeners == self.host_vsock_listeners.is_empty() {
            return Err("host listeners and host-vsock-listen-v1 launch requirement must be supplied together".into());
        }
        validate_host_vsock_listeners(&self.host_vsock_listeners, &self.vsock)?;
        #[cfg(feature = "net")]
        if !self.host_vsock_listeners.is_empty()
            && self.deployment_profile == DeploymentProfile::MultiTenant
        {
            return Err("host vsock listeners are disabled for multi-tenant deployments".into());
        }
        #[cfg(feature = "net")]
        validate_ssh_guest_cid(self.guest_cid, self.network.as_ref())?;
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Validate host-listener direction and route ownership before runtime mutations.
pub fn validate_host_vsock_listeners(
    listeners: &[HostVsockListener],
    routes: &[VsockRouteSpec],
) -> Result<(), String> {
    if !cfg!(unix) && !listeners.is_empty() {
        return Err("host vsock listeners require a Unix host".into());
    }
    let mut ports: HashSet<u32> = routes
        .iter()
        .filter(|route| route.socket_type == microsandbox_types::VsockSocketType::Stream)
        .map(|route| route.port)
        .collect();
    let mut paths = HashSet::new();
    for listener in listeners {
        if !listener.host_socket.is_absolute() {
            return Err("host vsock listener path must be absolute".into());
        }
        if listener.guest_port == 0 || listener.guest_port == u32::MAX {
            return Err("host vsock listener port must be between 1 and 4294967294".into());
        }
        if !ports.insert(listener.guest_port) {
            return Err(format!(
                "duplicate vsock stream port {}",
                listener.guest_port
            ));
        }
        if !paths.insert(&listener.host_socket) {
            return Err("duplicate host vsock listener path".into());
        }
    }
    Ok(())
}

/// Refuse reserved vsock addresses, including the wildcard address.
pub fn validate_guest_cid(cid: u32) -> Result<(), String> {
    if cid < 3 || cid == u32::MAX {
        return Err(format!("invalid guest CID {cid}: reserved vsock address"));
    }
    Ok(())
}

/// Require the SSH network context to name the exact CID assigned to libkrun.
#[cfg(feature = "net")]
pub fn validate_ssh_guest_cid(
    cid: Option<u32>,
    network: Option<&ResolvedNetworkConfig>,
) -> Result<(), String> {
    if let Some(binding) = network.and_then(ResolvedNetworkConfig::ssh_broker) {
        let cid = cid.ok_or("SSH custody requires a host-reserved guest CID")?;
        validate_guest_cid(cid)?;
        if binding.transport_cid != u64::from(cid) {
            return Err("SSH broker attribution does not match the assigned guest CID".into());
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

    #[cfg(unix)]
    #[test]
    fn host_listeners_require_capability_without_changing_legacy_routes() {
        let mut launch = LaunchConfig::default();
        let required = [HOST_VSOCK_LISTEN_CAPABILITY.to_string()];
        assert!(launch.validate_capabilities(&required).is_err());
        launch.host_vsock_listeners.push(HostVsockListener {
            host_socket: "/run/launch/service.sock".into(),
            guest_port: 5000,
        });
        assert!(launch.validate_capabilities(&[]).is_err());
        assert!(launch.validate_capabilities(&required).is_ok());
        launch.guest_cid = Some(65_536);
        assert!(launch.validate_capabilities(&required).is_err());
        assert!(
            launch
                .validate_capabilities(&[
                    HOST_VSOCK_LISTEN_CAPABILITY.into(),
                    GUEST_CID_CAPABILITY.into()
                ])
                .is_ok()
        );
    }

    #[cfg(unix)]
    #[test]
    fn host_listener_validation_rejects_collisions_and_invalid_endpoints() {
        use microsandbox_types::VsockSocketType;
        let valid = HostVsockListener {
            host_socket: "/run/launch/service.sock".into(),
            guest_port: 5000,
        };
        for port in [0, u32::MAX] {
            let invalid = HostVsockListener {
                guest_port: port,
                ..valid.clone()
            };
            assert!(validate_host_vsock_listeners(&[invalid], &[]).is_err());
        }
        let relative = HostVsockListener {
            host_socket: "relative.sock".into(),
            ..valid.clone()
        };
        assert!(validate_host_vsock_listeners(&[relative], &[]).is_err());
        let other_port = HostVsockListener {
            guest_port: 5001,
            ..valid.clone()
        };
        assert!(validate_host_vsock_listeners(&[valid.clone(), other_port], &[]).is_err());
        let other_path = HostVsockListener {
            host_socket: "/run/other.sock".into(),
            ..valid.clone()
        };
        assert!(validate_host_vsock_listeners(&[valid.clone(), other_path], &[]).is_err());
        let mut route = VsockRouteSpec {
            host_socket: "/run/outbound.sock".into(),
            port: 5000,
            socket_type: VsockSocketType::Stream,
        };
        assert!(
            validate_host_vsock_listeners(std::slice::from_ref(&valid), &[route.clone()]).is_err()
        );
        route.socket_type = VsockSocketType::Dgram;
        assert!(validate_host_vsock_listeners(&[valid], &[route]).is_ok());
    }

    #[cfg(all(unix, feature = "net"))]
    #[test]
    fn multi_tenant_launch_refuses_host_listener() {
        let launch = LaunchConfig {
            deployment_profile: DeploymentProfile::MultiTenant,
            host_vsock_listeners: vec![HostVsockListener {
                host_socket: "/run/launch/service.sock".into(),
                guest_port: 5000,
            }],
            ..Default::default()
        };
        assert!(
            launch
                .validate_capabilities(&[HOST_VSOCK_LISTEN_CAPABILITY.into()])
                .unwrap_err()
                .contains("multi-tenant")
        );
    }

    #[test]
    fn guest_cid_requires_explicit_capability_and_valid_address() {
        let mut launch = LaunchConfig::default();
        let required = [GUEST_CID_CAPABILITY.to_string()];
        assert!(launch.validate_capabilities(&[]).is_ok());
        assert!(launch.validate_capabilities(&required).is_err());
        assert!(
            launch
                .validate_capabilities(&["unknown-v2".into()])
                .is_err()
        );
        for cid in [0, 1, 2, u32::MAX] {
            launch.guest_cid = Some(cid);
            assert!(launch.validate_capabilities(&required).is_err());
        }
        for cid in [3, 65_536, u32::MAX - 1] {
            launch.guest_cid = Some(cid);
            assert!(launch.validate_capabilities(&required).is_ok());
            assert!(launch.validate_capabilities(&[]).is_err());
        }
    }

    #[cfg(feature = "net")]
    #[test]
    fn ssh_attribution_must_match_assigned_cid_not_a_network_slot() {
        use microsandbox_network::ssh::{BrokerEndpoint, SshBrokerBinding};

        let mut network = ResolvedNetworkConfig::default();
        let endpoint = BrokerEndpoint::new("/run/test-broker.sock").unwrap();
        network.set_ssh_broker(Some(SshBrokerBinding::new(endpoint, 65_536)));
        assert!(validate_ssh_guest_cid(Some(65_536), Some(&network)).is_ok());
        for cid in [None, Some(1), Some(3), Some(65_537), Some(u32::MAX)] {
            assert!(validate_ssh_guest_cid(cid, Some(&network)).is_err());
        }
        assert!(validate_ssh_guest_cid(None, None).is_ok());
    }
}
