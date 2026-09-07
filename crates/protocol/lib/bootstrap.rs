//! Typed host-to-guest configuration delivered before agent initialization.

use std::net::{Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use microsandbox_scan::{ActionSet, Decoder};

use crate::exec::ExecRlimit;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Complete one-shot configuration consumed by agentd during guest boot.
///
/// The runtime preloads this payload into the agent console before the VM
/// starts. The surrounding protocol envelope supplies the schema generation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestBootstrap {
    /// Block-backed root filesystem assembly, when required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_root: Option<BootstrapBlockRoot>,

    /// Virtiofs directory mounts installed inside the guest.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dir_mounts: Vec<BootstrapDirMount>,

    /// Virtiofs file mounts installed inside the guest.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub file_mounts: Vec<BootstrapFileMount>,

    /// Additional block-device mounts installed inside the guest.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disk_mounts: Vec<BootstrapDiskMount>,

    /// Tmpfs mounts installed inside the guest.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tmpfs_mounts: Vec<BootstrapTmpfsMount>,

    /// Guest hostname.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,

    /// Host alias written into the guest's hosts file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_alias: Option<String>,

    /// Guest network interface and address configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<BootstrapNetwork>,

    /// Sandbox-wide resource limits inherited by guest workloads.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rlimits: Vec<ExecRlimit>,

    /// Default guest user for command execution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,

    /// Default working directory for requests that omit one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_cwd: Option<String>,

    /// Environment inherited by requests that do not override a key.
    ///
    /// Secret entries contain guest-visible placeholders, never host secret
    /// values. Explicit exec and handoff environment entries take precedence.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub default_env: Vec<BootstrapEnvVar>,

    /// In-guest security policy.
    #[serde(default)]
    pub security_profile: BootstrapSecurityProfile,

    /// Optional PID 1 handoff after agentd finishes guest initialization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handoff_init: Option<BootstrapHandoffInit>,

    /// Sealed SSH key material for the broker VM.
    ///
    /// Only the broker VM consumes this field; agentd ignores it.
    /// Additive and optional: a host that predates this field omits it and
    /// the guest decodes the absence as `None`, which brokerd refuses with
    /// a typed custody error instead of starting unauthenticated.
    ///
    /// Key material travels in this typed frame rather than the process
    /// environment because environment entries stay readable through
    /// `/proc/<pid>/environ`. The bootstrap console channel itself is
    /// host-asserted and unmeasured: it carries no attestation that the
    /// bytes came from the intended launcher, so a compromised host could
    /// substitute material. brokerd's custody boundary therefore starts at
    /// receipt — it authenticates upstream with whatever arrived here and
    /// never treats arrival as proof of provenance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub broker_key: Option<BrokerSshKey>,

    /// Pinned upstream SSH servers projected from the grant host list.
    ///
    /// Only the broker VM consumes this field; agentd ignores it.
    /// Additive and optional with the same version-skew behavior as
    /// `broker_key`: absence fails diverted sessions closed, with no
    /// fallback to unverified upstream connections.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub broker_upstream: Option<BrokerUpstream>,

    /// DLP patterns enforced on relayed SSH sessions.
    ///
    /// Only the broker VM consumes this field; agentd ignores it.
    /// Additive and optional with the same version-skew behavior as
    /// `broker_key`: absence means no DLP scanning and relayed sessions
    /// pass through unchanged. brokerd moves the pattern bytes into
    /// sealed custody at ingest and emits only pattern ids and digests
    /// in audit records — pattern content is never persisted or logged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub broker_patterns: Option<BrokerPatterns>,
}

/// Block-backed root filesystem configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum BootstrapBlockRoot {
    /// A single filesystem image mounted as the guest root.
    DiskImage {
        /// Guest block-device path.
        device: String,

        /// Filesystem type, or `None` to probe inside the guest.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fstype: Option<String>,
    },

    /// An EROFS lower filesystem combined with a writable overlay upper.
    OciErofs {
        /// Read-only EROFS block-device path.
        lower: String,

        /// Writable overlay backing.
        upper: BootstrapBlockRootUpper,
    },
}

/// Writable backing for an OCI EROFS root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum BootstrapBlockRootUpper {
    /// Writable filesystem supplied by a guest block device.
    Device {
        /// Guest block-device path.
        device: String,

        /// Filesystem type on the device.
        fstype: String,
    },

    /// RAM-backed writable upper.
    Tmpfs {
        /// Optional maximum size in MiB.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        size_mib: Option<u32>,
    },
}

/// Common guest mount flags.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapMountFlags {
    /// Mount read-only.
    #[serde(default)]
    pub readonly: bool,

    /// Disallow execution from the mount.
    #[serde(default)]
    pub noexec: bool,

    /// Ignore set-user-ID and set-group-ID bits.
    #[serde(default)]
    pub nosuid: bool,

    /// Disallow device nodes.
    #[serde(default)]
    pub nodev: bool,
}

/// Guest-side virtiofs directory mount.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapDirMount {
    /// Virtiofs device tag.
    pub tag: String,

    /// Absolute guest mount path.
    pub guest_path: String,

    /// Guest mount flags.
    #[serde(default)]
    pub flags: BootstrapMountFlags,
}

/// Guest-side virtiofs file mount.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapFileMount {
    /// Virtiofs device tag.
    pub tag: String,

    /// Filename inside the staged virtiofs directory.
    pub filename: String,

    /// Absolute guest file path.
    pub guest_path: String,

    /// Guest mount flags.
    #[serde(default)]
    pub flags: BootstrapMountFlags,
}

/// Guest-side block-device mount.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapDiskMount {
    /// Virtio block-device identifier.
    pub id: String,

    /// Absolute guest mount path.
    pub guest_path: String,

    /// Filesystem type, or `None` to probe inside the guest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fstype: Option<String>,

    /// Guest mount flags.
    #[serde(default)]
    pub flags: BootstrapMountFlags,
}

/// Guest-side tmpfs mount.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapTmpfsMount {
    /// Absolute guest mount path.
    pub path: String,

    /// Optional maximum size in MiB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_mib: Option<u32>,

    /// Optional Unix mode applied to the tmpfs root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,

    /// Guest mount flags.
    #[serde(default)]
    pub flags: BootstrapMountFlags,
}

/// Guest network interface and address configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapNetwork {
    /// Guest interface name.
    pub interface: String,

    /// Guest interface MAC address.
    pub mac: [u8; 6],

    /// Guest interface MTU.
    pub mtu: u16,

    /// IPv4 address configuration when IPv4 is active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv4: Option<BootstrapIpv4>,

    /// IPv6 address configuration when IPv6 is active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<BootstrapIpv6>,
}

/// Guest IPv4 address configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapIpv4 {
    /// Guest IPv4 address.
    pub address: Ipv4Addr,

    /// CIDR prefix length.
    pub prefix_len: u8,

    /// Default gateway.
    pub gateway: Ipv4Addr,

    /// DNS resolver address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<Ipv4Addr>,
}

/// Guest IPv6 address configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapIpv6 {
    /// Guest IPv6 address.
    pub address: Ipv6Addr,

    /// CIDR prefix length.
    pub prefix_len: u8,

    /// Default gateway.
    pub gateway: Ipv6Addr,

    /// DNS resolver address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<Ipv6Addr>,
}

/// A baseline guest environment entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapEnvVar {
    /// Environment variable name.
    pub key: String,

    /// Environment variable value.
    pub value: String,
}

/// In-guest security profile selected for a sandbox.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapSecurityProfile {
    /// Preserve normal guest-root behavior.
    #[default]
    Default,

    /// Restrict mount and process privileges inside the guest.
    Restricted,
}

/// Optional PID 1 handoff after agentd completes initialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapHandoffInit {
    /// Absolute init path inside the guest, or the `auto` sentinel.
    pub cmd: String,

    /// Arguments following `argv[0]`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,

    /// Working directory entered before the handoff.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,

    /// Environment merged over the inherited runtime environment.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<BootstrapEnvVar>,
}

/// Expected key-type tag for broker SSH key material.
pub const BROKER_KEY_TYPE_ED25519: &str = "ed25519";

/// Sealed SSH key material delivered to the broker VM inside the typed bootstrap.
///
/// Carries decrypted private key bytes (resolved host-side; brokerd receives
/// material, never resolution configuration). brokerd moves these bytes into
/// zeroized in-memory key state exactly once and never re-serializes them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokerSshKey {
    /// Key-type tag. brokerd accepts exactly [`BROKER_KEY_TYPE_ED25519`]
    /// and fails closed with a wrong-type custody error for anything else.
    pub key_type: String,

    /// Decrypted private key bytes. For `"ed25519"` this is the 32-byte
    /// private seed, which brokerd expands into a keypair in zeroized
    /// memory.
    #[serde(with = "serde_bytes")]
    pub key_bytes: Vec<u8>,
}

/// Upstream SSH servers the broker VM may reoriginate toward.
///
/// Projected host-side from the grant host list: each entry pins one
/// server the broker is allowed to dial, the login user to present, and
/// the server public key to require. brokerd authenticates upstream with
/// the [`BrokerSshKey`] and requires an exact pin match; there is no
/// fallback to unverified connections.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokerUpstream {
    /// Pinned upstream servers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<BrokerUpstreamHost>,
}

/// One pinned upstream SSH server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokerUpstreamHost {
    /// Hostname as the guest addressed it (matched against the divert
    /// prelude destination).
    pub host: String,

    /// Upstream SSH port.
    pub port: u16,

    /// Login user for upstream public-key authentication.
    pub user: String,

    /// Expected server public key as an `authorized_keys` line
    /// (`"<algorithm> <base64> [comment]"`).
    pub public_key: String,
}

/// DLP patterns for the broker VM's SSH relay scanner.
///
/// Projected host-side from the credential policy: each entry names one
/// credential, carries its match bytes, and states the coalesced action
/// contributed when it hits. brokerd compiles these into a sealed match
/// library at ingest; the bytes never leave that custody.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokerPatterns {
    /// Patterns to compile into the relay scanner.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub patterns: Vec<BrokerPattern>,
}

/// One DLP pattern delivered to the broker VM inside the typed bootstrap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokerPattern {
    /// Credential name for audit attribution (never secret content).
    pub credential_id: String,

    /// Authored encoding of [`BrokerPattern::bytes`].
    pub decoder: Decoder,

    /// Authored pattern bytes: the literal credential bytes for
    /// [`Decoder::Raw`](microsandbox_scan::Decoder::Raw), standard-base64
    /// text decoding to them for
    /// [`Decoder::Base64`](microsandbox_scan::Decoder::Base64). brokerd
    /// moves these bytes into sealed custody exactly once and never
    /// re-serializes them.
    #[serde(with = "serde_bytes")]
    pub bytes: Vec<u8>,

    /// Coalesced action contributed when this pattern hits.
    #[serde(default)]
    pub action: ActionSet,
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        codec,
        message::{Message, MessageType, PROTOCOL_VERSION},
    };

    #[test]
    fn guest_bootstrap_round_trips_transport_sensitive_values() {
        let bootstrap = GuestBootstrap {
            block_root: Some(BootstrapBlockRoot::OciErofs {
                lower: "/dev/vda".to_string(),
                upper: BootstrapBlockRootUpper::Tmpfs {
                    size_mib: Some(512),
                },
            }),
            dir_mounts: vec![BootstrapDirMount {
                tag: "workspace".to_string(),
                guest_path: "/workspace:with separators".to_string(),
                flags: BootstrapMountFlags {
                    noexec: true,
                    ..BootstrapMountFlags::default()
                },
            }],
            file_mounts: vec![BootstrapFileMount {
                tag: "config".to_string(),
                filename: "app.json".to_string(),
                guest_path: "/etc/app.json".to_string(),
                flags: BootstrapMountFlags {
                    readonly: true,
                    ..BootstrapMountFlags::default()
                },
            }],
            disk_mounts: vec![BootstrapDiskMount {
                id: "data".to_string(),
                guest_path: "/data".to_string(),
                fstype: Some("ext4".to_string()),
                flags: BootstrapMountFlags::default(),
            }],
            tmpfs_mounts: vec![BootstrapTmpfsMount {
                path: "/tmp".to_string(),
                size_mib: Some(64),
                mode: Some(0o1777),
                flags: BootstrapMountFlags::default(),
            }],
            hostname: Some("quoted-env-test".to_string()),
            host_alias: Some("host.microsandbox.internal".to_string()),
            network: Some(BootstrapNetwork {
                interface: "eth0".to_string(),
                mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
                mtu: 1500,
                ipv4: Some(BootstrapIpv4 {
                    address: "172.16.0.2".parse().unwrap(),
                    prefix_len: 30,
                    gateway: "172.16.0.1".parse().unwrap(),
                    dns: Some("172.16.0.1".parse().unwrap()),
                }),
                ipv6: Some(BootstrapIpv6 {
                    address: "fd42:6d73:62::2".parse().unwrap(),
                    prefix_len: 64,
                    gateway: "fd42:6d73:62::1".parse().unwrap(),
                    dns: Some("fd42:6d73:62::1".parse().unwrap()),
                }),
            }),
            rlimits: vec![ExecRlimit {
                resource: "nofile".to_string(),
                soft: 1024,
                hard: 4096,
            }],
            user: Some("1000:1000".to_string()),
            default_cwd: Some("/workspace with spaces".to_string()),
            default_env: vec![
                BootstrapEnvVar {
                    key: "APP_CONFIG".to_string(),
                    value: "{\"message\":\"hello\"}".to_string(),
                },
                BootstrapEnvVar {
                    key: "UNICODE".to_string(),
                    value: "snowman: \u{2603}\nnext\tcolumn".to_string(),
                },
                BootstrapEnvVar {
                    key: "EMPTY".to_string(),
                    value: String::new(),
                },
            ],
            security_profile: BootstrapSecurityProfile::Restricted,
            handoff_init: Some(BootstrapHandoffInit {
                cmd: "/sbin/init".to_string(),
                args: vec!["--unit=multi user.target".to_string()],
                cwd: Some("/workspace with spaces".to_string()),
                env: vec![BootstrapEnvVar {
                    key: "HANDOFF_JSON".to_string(),
                    value: "{\"enabled\":true}".to_string(),
                }],
            }),
            broker_key: Some(BrokerSshKey {
                key_type: BROKER_KEY_TYPE_ED25519.to_string(),
                key_bytes: vec![0x42; 32],
            }),
            broker_upstream: Some(BrokerUpstream {
                hosts: vec![BrokerUpstreamHost {
                    host: "example.com".to_string(),
                    port: 22,
                    user: "deploy".to_string(),
                    public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBrokerTestPin".to_string(),
                }],
            }),
            broker_patterns: Some(BrokerPatterns {
                patterns: vec![BrokerPattern {
                    credential_id: "api-key".to_string(),
                    decoder: Decoder::Raw,
                    bytes: b"test-only-pattern-bytes".to_vec(),
                    action: ActionSet {
                        enforce: None,
                        audit: true,
                        count: true,
                    },
                }],
            }),
        };

        let message = Message::with_payload(MessageType::Bootstrap, 0, &bootstrap).unwrap();
        assert_eq!(message.v, PROTOCOL_VERSION);
        let mut frame = Vec::new();
        codec::encode_to_buf(&message, &mut frame).unwrap();
        let decoded = codec::decode_message_frame(&frame).unwrap();
        assert_eq!(decoded.payload::<GuestBootstrap>().unwrap(), bootstrap);
    }

    #[test]
    fn guest_bootstrap_without_broker_fields_decodes_to_none() {
        // A host that predates the broker fields omits them; the new guest
        // must decode the absence as `None` so brokerd can refuse custody
        // cleanly instead of misreading the frame.
        #[derive(serde::Serialize, serde::Deserialize)]
        struct OldBootstrap {
            #[serde(default)]
            hostname: Option<String>,
        }

        let old = OldBootstrap {
            hostname: Some("legacy-host".to_string()),
        };
        let mut payload = Vec::new();
        ciborium::into_writer(&old, &mut payload).unwrap();
        let bootstrap: GuestBootstrap = ciborium::from_reader(&payload[..]).unwrap();
        assert_eq!(bootstrap.hostname.as_deref(), Some("legacy-host"));
        assert_eq!(bootstrap.broker_key, None);
        assert_eq!(bootstrap.broker_upstream, None);
        assert_eq!(bootstrap.broker_patterns, None);

        // The reverse direction holds too: unknown trailing fields from a
        // newer sender are ignored by an older shape.
        let full = GuestBootstrap {
            broker_key: Some(BrokerSshKey {
                key_type: BROKER_KEY_TYPE_ED25519.to_string(),
                key_bytes: vec![0x42; 32],
            }),
            ..GuestBootstrap::default()
        };
        let mut encoded = Vec::new();
        ciborium::into_writer(&full, &mut encoded).unwrap();
        let as_old: OldBootstrap = ciborium::from_reader(&encoded[..]).unwrap();
        assert_eq!(as_old.hostname, None);
    }
}
