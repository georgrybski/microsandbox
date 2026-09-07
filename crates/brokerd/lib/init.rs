//! Minimal PID 1 init for the broker VM.
//!
//! Follows agentd's init patterns (essential filesystem mounts, block-root
//! assembly with pivot into the final root) but stays deliberately narrow:
//! no user volume mounts, no hostname or network configuration, no TLS or
//! script setup. The broker VM keeps its guest IP stack down entirely —
//! upstream egress leaves through the host-side TCP forwarder over the
//! vsock egress port, never through a guest interface.

use microsandbox_protocol::bootstrap::BootstrapBlockRoot;

use crate::error::BrokerResult;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Mount only the filesystems needed to discover and open the agent console.
///
/// The console descriptor remains valid when a block-backed root later
/// pivots and remounts the essential filesystems inside the final root.
pub fn prepare_bootstrap_console() -> BrokerResult<()> {
    linux::mount_bootstrap_filesystems()
}

/// Perform synchronous PID 1 initialization for the broker VM.
///
/// Mounts the essential filesystems and, when the bootstrap carries a
/// block-backed root, assembles and pivots into it. Never configures guest
/// networking: the broker VM has no IP stack by design.
pub fn init(block_root: Option<&BootstrapBlockRoot>) -> BrokerResult<()> {
    linux::mount_filesystems()?;
    if let Some(spec) = block_root {
        linux::mount_block_root(spec)?;
    }
    linux::create_run_dir()?;
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Modules
//--------------------------------------------------------------------------------------------------

mod linux {
    use nix::mount::{self, MsFlags};
    use nix::sys::stat::Mode;
    use nix::unistd;

    use microsandbox_protocol::bootstrap::{BootstrapBlockRoot, BootstrapBlockRootUpper};

    use crate::error::{BrokerError, BrokerResult};

    /// Mount the minimum filesystems needed for virtio-console discovery.
    pub fn mount_bootstrap_filesystems() -> BrokerResult<()> {
        mount_dev()?;
        mount_sys()?;
        Ok(())
    }

    /// Mount the essential Linux filesystems inside the broker guest.
    pub fn mount_filesystems() -> BrokerResult<()> {
        mount_dev()?;

        let nodev_noexec_nosuid =
            MsFlags::MS_NODEV | MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID | MsFlags::MS_RELATIME;
        mkdir_ignore_exists("/proc")?;
        mount_ignore_busy(
            Some("proc"),
            "/proc",
            Some("proc"),
            nodev_noexec_nosuid,
            None::<&str>,
        )?;
        mount_sys()?;

        mkdir_ignore_exists("/sys/fs/cgroup")?;
        mount_ignore_busy(
            Some("cgroup2"),
            "/sys/fs/cgroup",
            Some("cgroup2"),
            nodev_noexec_nosuid,
            None::<&str>,
        )?;

        let noexec_nosuid = MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID | MsFlags::MS_RELATIME;
        mkdir_ignore_exists("/dev/pts")?;
        mount_ignore_busy(
            Some("devpts"),
            "/dev/pts",
            Some("devpts"),
            noexec_nosuid,
            None::<&str>,
        )?;
        mkdir_ignore_exists("/dev/shm")?;
        mount_ignore_busy(
            Some("tmpfs"),
            "/dev/shm",
            Some("tmpfs"),
            noexec_nosuid,
            None::<&str>,
        )?;
        Ok(())
    }

    /// Assemble the root filesystem from the bootstrap block-root spec,
    /// then pivot into it.
    pub fn mount_block_root(spec: &BootstrapBlockRoot) -> BrokerResult<()> {
        mkdir_ignore_exists("/newroot")?;
        match spec {
            BootstrapBlockRoot::DiskImage { device, fstype } => {
                mount_disk_image(device, fstype.as_deref())?;
            }
            BootstrapBlockRoot::OciErofs { lower, upper } => {
                mount_oci_erofs(lower, upper)?;
            }
        }
        pivot_to_newroot()?;
        Ok(())
    }

    /// Create the broker runtime directory.
    pub fn create_run_dir() -> BrokerResult<()> {
        mkdir_ignore_exists("/run")?;
        mkdir_ignore_exists("/run/microsandbox")?;
        Ok(())
    }

    fn mount_dev() -> BrokerResult<()> {
        mkdir_ignore_exists("/dev")?;
        mount_ignore_busy(
            Some("devtmpfs"),
            "/dev",
            Some("devtmpfs"),
            MsFlags::MS_RELATIME,
            None::<&str>,
        )
    }

    fn mount_sys() -> BrokerResult<()> {
        let flags =
            MsFlags::MS_NODEV | MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID | MsFlags::MS_RELATIME;
        mkdir_ignore_exists("/sys")?;
        mount_ignore_busy(Some("sysfs"), "/sys", Some("sysfs"), flags, None::<&str>)
    }

    fn mount_disk_image(device: &str, fstype: Option<&str>) -> BrokerResult<()> {
        if let Some(fstype) = fstype {
            mount::mount(
                Some(device),
                "/newroot",
                Some(fstype),
                MsFlags::empty(),
                None::<&str>,
            )
            .map_err(|e| {
                BrokerError::Init(format!(
                    "failed to mount {device} at /newroot as {fstype}: {e}"
                ))
            })?;
        } else {
            let fstypes = read_proc_filesystems()?;
            let mut mounted = false;
            for fstype in &fstypes {
                if mount::mount(
                    Some(device),
                    "/newroot",
                    Some(fstype.as_str()),
                    MsFlags::empty(),
                    None::<&str>,
                )
                .is_ok()
                {
                    mounted = true;
                    break;
                }
            }
            if !mounted {
                return Err(BrokerError::Init(format!(
                    "failed to mount {device} at /newroot: no supported filesystem found"
                )));
            }
        }
        Ok(())
    }

    fn mount_oci_erofs(lower_device: &str, upper: &BootstrapBlockRootUpper) -> BrokerResult<()> {
        let lower_dir = "/.broker/rootfs/lower";
        mkdir_ignore_exists("/.broker/rootfs")?;
        mkdir_ignore_exists(lower_dir)?;
        mount::mount(
            Some(lower_device),
            lower_dir,
            Some("erofs"),
            MsFlags::MS_RDONLY,
            None::<&str>,
        )
        .map_err(|e| BrokerError::Init(format!("mount {lower_device} at {lower_dir}: {e}")))?;

        let upperfs_dir = "/.broker/rootfs/upperfs";
        mkdir_ignore_exists(upperfs_dir)?;
        match upper {
            BootstrapBlockRootUpper::Device { device, fstype } => {
                mount::mount(
                    Some(device.as_str()),
                    upperfs_dir,
                    Some(fstype.as_str()),
                    MsFlags::empty(),
                    None::<&str>,
                )
                .map_err(|e| BrokerError::Init(format!("mount {device} at {upperfs_dir}: {e}")))?;
            }
            BootstrapBlockRootUpper::Tmpfs { size_mib } => {
                let data = size_mib
                    .map(|mib| format!("size={},mode=755", u64::from(mib) * 1024 * 1024))
                    .unwrap_or_else(|| "mode=755".to_owned());
                mount::mount(
                    Some("tmpfs"),
                    upperfs_dir,
                    Some("tmpfs"),
                    MsFlags::MS_RELATIME,
                    Some(data.as_str()),
                )
                .map_err(|e| {
                    BrokerError::Init(format!("mount tmpfs upper at {upperfs_dir}: {e}"))
                })?;
            }
        }

        let upper_dir = format!("{upperfs_dir}/upper");
        let work_dir = format!("{upperfs_dir}/work");
        std::fs::create_dir_all(&upper_dir)
            .map_err(|e| BrokerError::Init(format!("mkdir {upper_dir}: {e}")))?;
        std::fs::create_dir_all(&work_dir)
            .map_err(|e| BrokerError::Init(format!("mkdir {work_dir}: {e}")))?;
        let mount_data = format!("lowerdir={lower_dir},upperdir={upper_dir},workdir={work_dir}");
        mount::mount(
            Some("overlay"),
            "/newroot",
            Some("overlay"),
            MsFlags::empty(),
            Some(mount_data.as_str()),
        )
        .map_err(|e| BrokerError::Init(format!("mount overlay at /newroot: {e}")))?;
        Ok(())
    }

    /// Move `/newroot` into `/` and remount the essentials inside.
    ///
    /// Unlike the general agent there is no runtime virtiofs share to
    /// carry across, so the pivot moves the mount alone.
    fn pivot_to_newroot() -> BrokerResult<()> {
        unistd::chdir("/newroot")
            .map_err(|e| BrokerError::Init(format!("failed to chdir /newroot: {e}")))?;
        mount::mount(Some("."), "/", None::<&str>, MsFlags::MS_MOVE, None::<&str>)
            .map_err(|e| BrokerError::Init(format!("failed to MS_MOVE /newroot to /: {e}")))?;
        unistd::chroot(".").map_err(|e| BrokerError::Init(format!("failed to chroot: {e}")))?;
        unistd::chdir("/")
            .map_err(|e| BrokerError::Init(format!("failed to chdir / after chroot: {e}")))?;
        mount_filesystems()?;
        Ok(())
    }

    fn read_proc_filesystems() -> BrokerResult<Vec<String>> {
        let content = std::fs::read_to_string("/proc/filesystems")
            .map_err(|e| BrokerError::Init(format!("failed to read /proc/filesystems: {e}")))?;
        Ok(content
            .lines()
            .filter_map(|line| {
                if line.starts_with("nodev") {
                    return None;
                }
                let fstype = line.trim();
                if fstype.is_empty() {
                    None
                } else {
                    Some(fstype.to_string())
                }
            })
            .collect())
    }

    fn mkdir_ignore_exists(path: &str) -> BrokerResult<()> {
        match unistd::mkdir(path, Mode::from_bits_truncate(0o755)) {
            Ok(()) => Ok(()),
            Err(nix::Error::EEXIST) => Ok(()),
            Err(e) => Err(BrokerError::Init(format!("mkdir {path}: {e}"))),
        }
    }

    fn mount_ignore_busy(
        source: Option<&str>,
        target: &str,
        fstype: Option<&str>,
        flags: MsFlags,
        data: Option<&str>,
    ) -> BrokerResult<()> {
        match mount::mount(source, target, fstype, flags, data) {
            Ok(()) => Ok(()),
            Err(nix::Error::EBUSY) => Ok(()),
            Err(e) => Err(BrokerError::Init(format!("failed to mount {target}: {e}"))),
        }
    }
}
