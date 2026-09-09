//! Type-aware admission for the immutable Linux mount read policy.
//!
//! Path evaluation conservatively identifies possible traversal ancestors. Only
//! actual no-follow directories receive traversal access; other objects need the
//! same identity-bound visibility tag as a masked path. Already-issued handles
//! are not revalidated here.

use std::io;
use std::os::fd::RawFd;

use super::{
    PassthroughFs, inode,
    mount_policy::{Decision, LexicalPath},
};
use crate::backends::shared::{inode_table::InodeAltKey, platform};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Refine a path-only decision using the opened object's raw, no-follow type.
pub(super) fn is_masked(decision: Decision, host_mode: libc::mode_t) -> bool {
    match decision {
        Decision::Visible => false,
        Decision::Masked => true,
        Decision::TraversalOnly => host_mode & libc::S_IFMT != libc::S_IFDIR,
    }
}

/// Check an opened child before publishing its name or inode to the guest.
pub(super) fn check_child(
    fs: &PassthroughFs,
    parent: u64,
    name: &[u8],
    host_mode: libc::mode_t,
    identity: InodeAltKey,
) -> io::Result<()> {
    let Some(policy) = fs.mask_policy() else {
        return Ok(());
    };
    let path = inode::lexical_child_path(fs, parent, name).ok_or_else(platform::enoent)?;
    let path = LexicalPath::new(&path).map_err(|_| platform::enoent())?;
    if policy.is_protected(&path) {
        return Err(platform::enoent());
    }
    if is_masked(policy.decide(&path).decision, host_mode)
        && !tag_matches(fs, parent, name, identity)?
    {
        return Err(platform::enoent());
    }
    Ok(())
}

/// Check a new inode-based read admission without revoking existing handles.
pub(super) fn check_inode(fs: &PassthroughFs, ino: u64) -> io::Result<()> {
    if fs.mask_policy().is_none() || ino == 1 || fs.is_virtual_init_inode(ino) {
        return Ok(());
    }
    let fd = inode::get_inode_fd(fs, ino)?;
    check_inode_fd(fs, ino, fd.raw())
}

/// Check visibility against the actual object pinned by a caller's inode fd.
pub(super) fn check_inode_fd(fs: &PassthroughFs, ino: u64, fd: RawFd) -> io::Result<()> {
    let Some(policy) = fs.mask_policy() else {
        return Ok(());
    };
    // The mount root and synthetic init inode are established by the backend,
    // rather than admitted through a policy-controlled child lookup.
    if ino == 1 || fs.is_virtual_init_inode(ino) {
        return Ok(());
    }
    let path = inode::lexical_inode_path(fs, ino).ok_or_else(platform::enoent)?;
    let path = LexicalPath::new(&path).map_err(|_| platform::enoent())?;
    if policy.is_protected(&path) {
        return Err(platform::enoent());
    }
    let st = platform::fstat(fd)?;
    if is_masked(policy.decide(&path).decision, st.st_mode) {
        let alias = inode::current_anchor_alias_for_policy(fs, ino).ok_or_else(platform::enoent)?;
        if !tag_matches(
            fs,
            alias.parent,
            &alias.name,
            inode::linux_alt_key_from_fd(fd)?,
        )? {
            return Err(platform::enoent());
        }
    }
    Ok(())
}

/// Validate an alias tag against the observed object, evicting stale identities.
///
/// An absent tag is distinct from a stale tag: an authorized write-open may
/// create a tag, but must not mutate a replacement using a stale authorization.
pub(super) fn tag_matches(
    fs: &PassthroughFs,
    parent: u64,
    name: &[u8],
    actual: InodeAltKey,
) -> io::Result<bool> {
    let Some(tags) = fs.tags() else {
        return Ok(false);
    };
    let Some(stored) = tags.get_identity(parent, name) else {
        return Ok(false);
    };
    if actual != stored {
        tags.evict(parent, name);
        return Err(platform::enoent());
    }
    Ok(true)
}
