//! Removal operations: unlink, rmdir, rename.
//!
//! All operations validate names and protect `init.krun` from deletion/renaming.
//! On Linux, `renameat2` is used for flag support (RENAME_NOREPLACE, RENAME_EXCHANGE).
//! On macOS, `renameatx_np` is used with translated flag values.

use std::{ffi::CStr, io};

use super::{PassthroughFs, inode};
#[cfg(target_os = "linux")]
use crate::backends::shared::inode_table::NamespaceAlias;
use crate::{
    Context,
    backends::shared::{name_validation, platform},
};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Linux `RENAME_EXCHANGE` flag: atomically swap source and destination.
#[cfg(target_os = "linux")]
const RENAME_EXCHANGE: u32 = 2;

/// Remove a file.
///
/// On macOS, opens an fd to the file before unlinking so that open handles
/// can still access the data after the directory entry is removed (the
/// `/.vol/<dev>/<ino>` path becomes invalid after unlink).
pub(crate) fn do_unlink(
    fs: &PassthroughFs,
    _ctx: Context,
    parent: u64,
    name: &CStr,
) -> io::Result<()> {
    name_validation::validate_name(name)?;
    if fs.cfg.readonly() {
        return Err(platform::erofs());
    }

    // Protect init.krun from deletion.
    if fs.is_reserved_init_name(parent, name.to_bytes()) {
        return Err(platform::eacces());
    }

    #[cfg(target_os = "linux")]
    let tagged_masked = remove_admission(fs, parent, name)?;

    let parent_fd = inode::get_inode_fd(fs, parent)?;

    #[cfg(target_os = "linux")]
    let pre_unlink_fd = {
        let fd = unsafe {
            libc::openat(
                parent_fd.raw(),
                name.as_ptr(),
                libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd >= 0 { Some(fd) } else { None }
    };

    #[cfg(target_os = "linux")]
    let pre_unlink_key = match pre_unlink_fd {
        Some(fd) => match inode::linux_alt_key_from_fd(fd) {
            Ok(key) => Some(key),
            Err(err) => {
                unsafe { libc::close(fd) };
                return Err(err);
            }
        },
        None => None,
    };

    // On macOS, grab an fd before unlink to keep the file data alive.
    #[cfg(target_os = "macos")]
    let pre_unlink_fd = {
        let fd = unsafe {
            libc::openat(
                parent_fd.raw(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd >= 0 { Some(fd) } else { None }
    };

    let ret = unsafe { libc::unlinkat(parent_fd.raw(), name.as_ptr(), 0) };
    if ret < 0 {
        #[cfg(target_os = "linux")]
        if let Some(fd) = pre_unlink_fd {
            unsafe { libc::close(fd) };
        }
        #[cfg(target_os = "macos")]
        if let Some(fd) = pre_unlink_fd {
            unsafe { libc::close(fd) };
        }
        return Err(platform::linux_error(io::Error::last_os_error()));
    }

    #[cfg(target_os = "linux")]
    if let Some(fd) = pre_unlink_fd {
        let alias = NamespaceAlias::new(parent, name.to_bytes());
        if let Some(alt_key) = pre_unlink_key {
            let mut inodes = fs.inodes.write().unwrap();
            if let Some(data) = inodes.get_alt(&alt_key).cloned() {
                let detached = inode::remove_alias_locked(&mut inodes, &data, &alias);
                if detached {
                    inode::store_unlinked_fd(&data, fd);
                } else {
                    unsafe { libc::close(fd) };
                }
            } else {
                unsafe { libc::close(fd) };
            }
        } else {
            unsafe { libc::close(fd) };
        }
    }

    #[cfg(target_os = "linux")]
    if tagged_masked && let Some(tags) = fs.tags() {
        tags.evict(parent, name.to_bytes());
    }

    // Store the fd in InodeData so open_inode_fd can use it.
    #[cfg(target_os = "macos")]
    if let Some(fd) = pre_unlink_fd {
        // Look up the inode by stat identity from the pre-unlink fd.
        let st = platform::fstat(fd);
        if let Ok(st) = st {
            let alt_key = crate::backends::shared::inode_table::InodeAltKey::new(
                st.st_ino,
                platform::stat_dev(&st),
            );
            let inodes = fs.inodes.read().unwrap();
            if let Some(data) = inodes.get_alt(&alt_key) {
                inode::store_unlinked_fd(data, fd);
            } else {
                // No tracked inode — close the fd.
                unsafe { libc::close(fd) };
            }
        } else {
            unsafe { libc::close(fd) };
        }
    }

    Ok(())
}

/// Remove a directory.
pub(crate) fn do_rmdir(
    fs: &PassthroughFs,
    _ctx: Context,
    parent: u64,
    name: &CStr,
) -> io::Result<()> {
    name_validation::validate_name(name)?;
    if fs.cfg.readonly() {
        return Err(platform::erofs());
    }

    if fs.is_reserved_init_name(parent, name.to_bytes()) {
        return Err(platform::eacces());
    }

    #[cfg(target_os = "linux")]
    let tagged_masked = rmdir_admission(fs, parent, name)?;

    let parent_fd = inode::get_inode_fd(fs, parent)?;

    #[cfg(target_os = "linux")]
    let pre_rmdir_fd = {
        let fd = unsafe {
            libc::openat(
                parent_fd.raw(),
                name.as_ptr(),
                libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY,
            )
        };
        if fd >= 0 { Some(fd) } else { None }
    };

    #[cfg(target_os = "linux")]
    let pre_rmdir_key = match pre_rmdir_fd {
        Some(fd) => match inode::linux_alt_key_from_fd(fd) {
            Ok(key) => Some(key),
            Err(err) => {
                unsafe { libc::close(fd) };
                return Err(err);
            }
        },
        None => None,
    };

    let ret = unsafe { libc::unlinkat(parent_fd.raw(), name.as_ptr(), libc::AT_REMOVEDIR) };
    if ret < 0 {
        let initial_errno = io::Error::last_os_error().raw_os_error();
        #[cfg(target_os = "linux")]
        if initial_errno == Some(libc::ENOTEMPTY)
            && let Some(policy) = fs.mask_policy()
            && let Some(path) = inode::lexical_child_path(fs, parent, name.to_bytes())
            && let Ok(lexical) = super::mount_policy::LexicalPath::new(&path)
            && matches!(
                policy.decide(&lexical).decision,
                super::mount_policy::Decision::Masked
                    | super::mount_policy::Decision::TraversalOnly
            )
            && cascade_remove(fs, &path, &lexical, 0, None)
        {
            let retry =
                unsafe { libc::unlinkat(parent_fd.raw(), name.as_ptr(), libc::AT_REMOVEDIR) };
            if retry == 0 {
                // Continue through the ordinary successful-rmdir cleanup below.
            } else {
                if let Some(fd) = pre_rmdir_fd {
                    unsafe { libc::close(fd) };
                }
                return Err(io::Error::from_raw_os_error(libc::ENOTEMPTY));
            }
        } else {
            #[cfg(target_os = "linux")]
            if let Some(fd) = pre_rmdir_fd {
                unsafe { libc::close(fd) };
            }
            return Err(io::Error::from_raw_os_error(
                initial_errno.unwrap_or(libc::EIO),
            ));
        }
    }

    #[cfg(target_os = "linux")]
    if let Some(fd) = pre_rmdir_fd {
        let alias = NamespaceAlias::new(parent, name.to_bytes());
        if let Some(alt_key) = pre_rmdir_key {
            let mut inodes = fs.inodes.write().unwrap();
            if let Some(data) = inodes.get_alt(&alt_key).cloned() {
                let detached = inode::remove_alias_locked(&mut inodes, &data, &alias);
                if detached {
                    inode::store_unlinked_fd(&data, fd);
                } else {
                    unsafe { libc::close(fd) };
                }
            } else {
                unsafe { libc::close(fd) };
            }
        } else {
            unsafe { libc::close(fd) };
        }
    }
    #[cfg(target_os = "linux")]
    if tagged_masked && let Some(tags) = fs.tags() {
        tags.evict(parent, name.to_bytes());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn cascade_remove(
    fs: &PassthroughFs,
    lexical_path: &str,
    lexical: &super::mount_policy::LexicalPath,
    depth: usize,
    dir_synthetic_inode: Option<u64>,
) -> bool {
    if depth > 64 {
        return false;
    }
    let Some(policy) = fs.mask_policy() else {
        return false;
    };
    let host_path = fs.cfg.root_dir.join(lexical_path);
    let dir_synthetic_inode =
        dir_synthetic_inode.or_else(|| inode::synthetic_inode_for_host_path(fs, &host_path));
    let Ok(entries) = std::fs::read_dir(&host_path) else {
        return false;
    };
    for entry in entries {
        let Ok(entry) = entry else { return false };
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return false;
        };
        let child_path = format!("{lexical_path}/{name}");
        let Ok(child) = super::mount_policy::LexicalPath::new(&child_path) else {
            return false;
        };
        if policy.is_protected(&child) {
            return false;
        }
        match policy.decide(&child).decision {
            super::mount_policy::Decision::Visible => return false,
            super::mount_policy::Decision::Masked
                if dir_synthetic_inode
                    .is_some_and(|parent| fs.tagged_visible(parent, name.as_bytes())) =>
            {
                return false;
            }
            super::mount_policy::Decision::Masked
            | super::mount_policy::Decision::TraversalOnly => {
                let Ok(meta) = std::fs::symlink_metadata(entry.path()) else {
                    return false;
                };
                if meta.file_type().is_dir() {
                    let child_synthetic_inode =
                        inode::synthetic_inode_for_host_path(fs, &entry.path());
                    if !cascade_remove(fs, &child_path, &child, depth + 1, child_synthetic_inode) {
                        return false;
                    }
                    if std::fs::remove_dir(entry.path()).is_err() {
                        return false;
                    }
                } else if std::fs::remove_file(entry.path()).is_err() {
                    return false;
                }
                if let Some(parent_inode) = dir_synthetic_inode
                    && let Some(tags) = fs.tags()
                {
                    tags.evict(parent_inode, name.as_bytes());
                }
            }
        }
    }
    let _ = lexical;
    true
}

/// Rename a file or directory.
pub(crate) fn do_rename(
    fs: &PassthroughFs,
    _ctx: Context,
    olddir: u64,
    oldname: &CStr,
    newdir: u64,
    newname: &CStr,
    flags: u32,
) -> io::Result<()> {
    name_validation::validate_name(oldname)?;
    name_validation::validate_name(newname)?;
    if fs.cfg.readonly() {
        return Err(platform::erofs());
    }

    // Protect init.krun from being renamed or overwritten.
    if fs.is_reserved_init_name(olddir, oldname.to_bytes())
        || fs.is_reserved_init_name(newdir, newname.to_bytes())
    {
        return Err(platform::eacces());
    }

    #[cfg(target_os = "linux")]
    {
        rename_admission(fs, olddir, oldname, newdir, newname)?;
    }

    let old_fd = inode::get_inode_fd(fs, olddir)?;
    let new_fd = inode::get_inode_fd(fs, newdir)?;

    #[cfg(target_os = "linux")]
    {
        let source_probe_fd = unsafe {
            libc::openat(
                old_fd.raw(),
                oldname.as_ptr(),
                libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if source_probe_fd < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }
        let source_key = match inode::linux_alt_key_from_fd(source_probe_fd) {
            Ok(key) => key,
            Err(err) => {
                unsafe { libc::close(source_probe_fd) };
                return Err(err);
            }
        };
        unsafe { libc::close(source_probe_fd) };

        let target_probe_fd = unsafe {
            libc::openat(
                new_fd.raw(),
                newname.as_ptr(),
                libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        let target_probe = if target_probe_fd >= 0 {
            let target_key = match inode::linux_alt_key_from_fd(target_probe_fd) {
                Ok(key) => key,
                Err(err) => {
                    unsafe { libc::close(target_probe_fd) };
                    return Err(err);
                }
            };
            Some((target_probe_fd, target_key))
        } else if io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            None
        } else {
            return Err(platform::linux_error(io::Error::last_os_error()));
        };

        let ret = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                old_fd.raw(),
                oldname.as_ptr(),
                new_fd.raw(),
                newname.as_ptr(),
                flags,
            )
        };
        if ret < 0 {
            if let Some((fd, _)) = target_probe {
                unsafe { libc::close(fd) };
            }
            return Err(platform::linux_error(io::Error::last_os_error()));
        }

        let old_alias = NamespaceAlias::new(olddir, oldname.to_bytes());
        let new_alias = NamespaceAlias::new(newdir, newname.to_bytes());
        let mut inodes = fs.inodes.write().unwrap();
        let source_data = inodes.get_alt(&source_key).cloned();

        if flags & RENAME_EXCHANGE != 0 {
            if let Some((fd, target_key)) = target_probe.as_ref()
                && *target_key == source_key
            {
                unsafe { libc::close(*fd) };
                return Ok(());
            }

            if let Some(source) = source_data.as_ref() {
                let _ = inode::remove_alias_locked(&mut inodes, source, &old_alias);
                inode::register_alias_locked(&mut inodes, source, new_alias.clone());
            }

            if let Some((fd, target_key)) = target_probe {
                if let Some(target) = inodes.get_alt(&target_key).cloned() {
                    let _ = inode::remove_alias_locked(&mut inodes, &target, &new_alias);
                    inode::register_alias_locked(&mut inodes, &target, old_alias);
                }
                unsafe { libc::close(fd) };
            }
            if let Some(tags) = fs.tags() {
                tags.evict(olddir, oldname.to_bytes());
                tags.evict(newdir, newname.to_bytes());
            }
        } else {
            if let Some(source) = source_data.as_ref() {
                let _ = inode::remove_alias_locked(&mut inodes, source, &old_alias);
                inode::register_alias_locked(&mut inodes, source, new_alias.clone());
            }

            if let Some((fd, target_key)) = target_probe {
                let source_inode = source_data.as_ref().map(|data| data.inode);
                if let Some(target) = inodes.get_alt(&target_key).cloned() {
                    if Some(target.inode) != source_inode {
                        let detached = inode::remove_alias_locked(&mut inodes, &target, &new_alias);
                        if detached {
                            inode::store_unlinked_fd(&target, fd);
                        } else {
                            unsafe { libc::close(fd) };
                        }
                    } else {
                        unsafe { libc::close(fd) };
                    }
                } else {
                    unsafe { libc::close(fd) };
                }
            }
            if let Some(tags) = fs.tags() {
                tags.evict(olddir, oldname.to_bytes());
                tags.evict(newdir, newname.to_bytes());
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        if flags == 0 {
            let ret = unsafe {
                libc::renameat(
                    old_fd.raw(),
                    oldname.as_ptr(),
                    new_fd.raw(),
                    newname.as_ptr(),
                )
            };
            if ret < 0 {
                return Err(platform::linux_error(io::Error::last_os_error()));
            }
        } else {
            // macOS uses renamex_np for RENAME_SWAP and RENAME_EXCL.
            // Map Linux flags to macOS equivalents.
            let mut macos_flags: libc::c_uint = 0;

            // Linux RENAME_NOREPLACE = 1, macOS RENAME_EXCL = 0x00000004
            if flags & 1 != 0 {
                macos_flags |= 0x00000004; // RENAME_EXCL
            }
            // Linux RENAME_EXCHANGE = 2, macOS RENAME_SWAP = 0x00000002
            if flags & 2 != 0 {
                macos_flags |= 0x00000002; // RENAME_SWAP
            }

            let ret = unsafe {
                libc::renameatx_np(
                    old_fd.raw(),
                    oldname.as_ptr(),
                    new_fd.raw(),
                    newname.as_ptr(),
                    macos_flags,
                )
            };
            if ret < 0 {
                return Err(platform::linux_error(io::Error::last_os_error()));
            }
        }
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn remove_admission(fs: &PassthroughFs, parent: u64, name: &CStr) -> io::Result<bool> {
    let Some(policy) = fs.mask_policy() else {
        return Ok(false);
    };
    let path =
        inode::lexical_child_path(fs, parent, name.to_bytes()).ok_or_else(platform::enoent)?;
    let path = super::mount_policy::LexicalPath::new(&path).map_err(|_| platform::enoent())?;
    if policy.is_protected(&path) {
        return Err(platform::enoent());
    }
    if !matches!(
        policy.decide(&path).decision,
        super::mount_policy::Decision::Masked
    ) {
        return Ok(false);
    }
    if !fs.tagged_visible(parent, name.to_bytes()) {
        return Err(platform::enoent());
    }
    Ok(true)
}

#[cfg(target_os = "linux")]
fn rmdir_admission(fs: &PassthroughFs, parent: u64, name: &CStr) -> io::Result<bool> {
    let Some(policy) = fs.mask_policy() else {
        return Ok(false);
    };
    let path =
        inode::lexical_child_path(fs, parent, name.to_bytes()).ok_or_else(platform::enoent)?;
    let path = super::mount_policy::LexicalPath::new(&path).map_err(|_| platform::enoent())?;
    if policy.is_protected(&path) {
        return Err(platform::enoent());
    }
    if !matches!(
        policy.decide(&path).decision,
        super::mount_policy::Decision::Masked
    ) {
        return Ok(false);
    }
    if fs.tagged_visible(parent, name.to_bytes()) {
        return Ok(true);
    }
    // An untagged masked directory is still eligible for the fail-closed
    // cascade only when the policy masks descendants too. A plain masked
    // directory must remain indistinguishable from a missing name.
    if matches!(
        policy
            .decide_child(&path, "__mount_policy_probe__")
            .decision,
        super::mount_policy::Decision::Masked | super::mount_policy::Decision::TraversalOnly
    ) {
        let host_path = fs.cfg.root_dir.join(path.as_str().unwrap_or_default());
        if std::fs::read_dir(host_path)
            .map(|mut entries| entries.next().is_none())
            .unwrap_or(true)
        {
            return Err(platform::enoent());
        }
        return Ok(false);
    }
    Err(platform::enoent())
}

#[cfg(target_os = "linux")]
fn rename_admission(
    fs: &PassthroughFs,
    olddir: u64,
    oldname: &CStr,
    newdir: u64,
    newname: &CStr,
) -> io::Result<()> {
    let Some(policy) = fs.mask_policy() else {
        return Ok(());
    };
    let src =
        inode::lexical_child_path(fs, olddir, oldname.to_bytes()).ok_or_else(platform::enoent)?;
    let dst =
        inode::lexical_child_path(fs, newdir, newname.to_bytes()).ok_or_else(platform::enoent)?;
    let src = super::mount_policy::LexicalPath::new(&src).map_err(|_| platform::enoent())?;
    let dst = super::mount_policy::LexicalPath::new(&dst).map_err(|_| platform::enoent())?;
    if policy.is_protected(&src)
        || (matches!(
            policy.decide(&src).decision,
            super::mount_policy::Decision::Masked
        ) && !fs.tagged_visible(olddir, oldname.to_bytes()))
    {
        return Err(platform::enoent());
    }
    if policy.is_protected(&dst) {
        return Err(platform::enoent());
    }
    if matches!(
        policy.decide_write(&dst).decision,
        super::mount_policy::WriteDecision::Deny
    ) {
        return Err(platform::eacces());
    }
    Ok(())
}
