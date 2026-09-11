#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::os::unix::fs::{MetadataExt, symlink};
use std::sync::Arc;

use super::mount_policy::{
    CaseSensitivity, CompiledRuleSet, MountPolicyProgram, PathPolicyRule, Pattern, RuleEffect,
    RuleOrigin, ScopeKind,
};
use super::*;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn sandbox(mode: StatVirtualization, readonly: bool) -> TestSandbox {
    let origin = RuleOrigin {
        layer: "mount".to_string(),
        file: PathBuf::from("mount-policy.json"),
        scope_kind: ScopeKind::Workload,
    };
    let rules = [(RuleEffect::Mask, "**"), (RuleEffect::Unmask, "**/public")]
        .into_iter()
        .map(|(effect, pattern)| PathPolicyRule {
            effect,
            pattern: Pattern::parse(pattern).unwrap(),
            overridable: true,
            origin: origin.clone(),
        })
        .collect();
    TestSandbox::with_config(|mut cfg| {
        cfg.mask_policy = Some(Arc::new(MountPolicyProgram {
            version: 1,
            rules,
            protect: Vec::new(),
            writes: CompiledRuleSet::default(),
            case_sensitivity: CaseSensitivity::Sensitive,
        }));
        cfg.stat_virtualization = mode;
        cfg.readonly = readonly;
        cfg.inject_init = false;
        cfg
    })
}

fn cached_host_inode(sb: &mut TestSandbox, name: &str) -> u64 {
    // Seed an adversarial cached inode without granting a guest-created identity tag.
    // This is a fixture mechanism, not an assertion that policy hot reload is supported.
    let policy = sb.fs.cfg.mask_policy.take();
    let inode = sb.lookup_root(name).unwrap().inode;
    sb.fs.cfg.mask_policy = policy;
    inode
}

fn assert_cached_read_denied(sb: &TestSandbox, inode: u64) {
    for ctx in [sb.ctx(), sb.ctx_as(1000, 1000)] {
        TestSandbox::assert_errno(
            sb.fs.open(ctx, inode, false, libc::O_RDONLY as u32),
            LINUX_ENOENT,
        );
        TestSandbox::assert_errno(sb.fs.getattr(ctx, inode, None), LINUX_ENOENT);
        for mask in [libc::F_OK, libc::R_OK, libc::X_OK, libc::R_OK | libc::X_OK] {
            TestSandbox::assert_errno(sb.fs.access(ctx, inode, mask as u32), LINUX_ENOENT);
        }
    }
}

fn names(sb: &TestSandbox, inode: u64) -> Vec<Vec<u8>> {
    let handle = sb.fuse_opendir(inode).unwrap();
    let entries = sb.fs.readdir(sb.ctx(), inode, handle, 65536, 0).unwrap();
    sb.fs.releasedir(sb.ctx(), inode, 0, handle).unwrap();
    entries
        .into_iter()
        .map(|entry| entry.name.to_vec())
        .collect()
}

fn assert_public_only(entries: &[(Vec<u8>, u64)], include_dots: bool) {
    let mut actual: Vec<_> = entries.iter().map(|(name, _)| name.clone()).collect();
    actual.sort();
    let mut expected = vec![b"branch".to_vec(), b"public".to_vec()];
    if include_dots {
        expected.extend([b".".to_vec(), b"..".to_vec()]);
    }
    expected.sort();
    assert_eq!(actual, expected);
    assert!(entries.windows(2).all(|pair| pair[0].1 < pair[1].1));
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn cached_regular_file_read_admission_is_type_aware_in_every_stat_mode() {
    for mode in [
        StatVirtualization::Off,
        StatVirtualization::Relaxed,
        StatVirtualization::Strict,
    ] {
        let mut sb = sandbox(mode, true);
        sb.host_create_file("secret", b"synthetic private bytes");
        sb.host_create_file("public", b"public control");
        let hidden = cached_host_inode(&mut sb, "secret");
        assert!(!sb.fs.tagged_visible(ROOT_INODE, b"secret"));
        assert_cached_read_denied(&sb, hidden);
        TestSandbox::assert_errno(sb.lookup_root("secret"), LINUX_ENOENT);

        let public = sb.lookup_root("public").unwrap();
        let handle = sb.fuse_open(public.inode, libc::O_RDONLY as u32).unwrap();
        assert_eq!(
            sb.fuse_read(public.inode, handle, 4096, 0).unwrap(),
            b"public control"
        );
        assert!(sb.fs.getattr(sb.ctx(), public.inode, None).is_ok());
        assert!(
            sb.fs
                .access(sb.ctx(), public.inode, libc::R_OK as u32)
                .is_ok()
        );
    }
}

#[test]
fn real_symlinks_to_files_and_directories_are_not_traversal_directories() {
    let mut sb = sandbox(StatVirtualization::Off, true);
    sb.host_create_file("public", b"public control");
    sb.host_create_dir("branch");
    sb.host_create_file("branch/public", b"nested public");
    symlink("public", sb.root.join("file-link")).unwrap();
    symlink("branch", sb.root.join("dir-link")).unwrap();
    for name in ["file-link", "dir-link"] {
        assert!(
            std::fs::symlink_metadata(sb.root.join(name))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        let inode = cached_host_inode(&mut sb, name);
        assert_cached_read_denied(&sb, inode);
        TestSandbox::assert_errno(sb.fs.readlink(sb.ctx(), inode), LINUX_ENOENT);
        TestSandbox::assert_errno(sb.lookup_root(name), LINUX_ENOENT);
        assert!(
            !names(&sb, ROOT_INODE)
                .iter()
                .any(|listed| listed == name.as_bytes())
        );
    }
    let branch = sb.lookup_root("branch").unwrap();
    let nested = sb.lookup(branch.inode, "public").unwrap();
    let handle = sb.fuse_open(nested.inode, libc::O_RDONLY as u32).unwrap();
    assert_eq!(
        sb.fuse_read(nested.inode, handle, 4096, 0).unwrap(),
        b"nested public"
    );
}

#[test]
fn visible_real_symlink_keeps_readlink_and_nofollow_open_behavior() {
    let sb = sandbox(StatVirtualization::Off, true);
    sb.host_create_file("target", b"synthetic target");
    symlink("target", sb.root.join("public")).unwrap();
    let public = sb.lookup_root("public").unwrap();
    assert_eq!(sb.fs.readlink(sb.ctx(), public.inode).unwrap(), b"target");
    TestSandbox::assert_errno(
        sb.fuse_open(public.inode, libc::O_RDONLY as u32),
        LINUX_ELOOP,
    );
    TestSandbox::assert_errno(sb.lookup_root("target"), LINUX_ENOENT);
}

#[test]
fn strict_file_backed_symlink_requires_visibility_or_an_exact_creation_tag() {
    let mut sb = sandbox(StatVirtualization::Strict, false);
    let policy = sb.fs.cfg.mask_policy.take();
    let hidden = sb
        .fs
        .symlink(
            sb.ctx(),
            &TestSandbox::cstr("synthetic-target"),
            ROOT_INODE,
            &TestSandbox::cstr("hidden-link"),
            Extensions::default(),
        )
        .unwrap();
    sb.fs.cfg.mask_policy = policy;
    assert!(
        std::fs::symlink_metadata(sb.root.join("hidden-link"))
            .unwrap()
            .file_type()
            .is_file()
    );
    assert_eq!(hidden.attr.st_mode & libc::S_IFMT, libc::S_IFLNK);
    assert!(!sb.fs.tagged_visible(ROOT_INODE, b"hidden-link"));
    assert_cached_read_denied(&sb, hidden.inode);
    TestSandbox::assert_errno(sb.fs.readlink(sb.ctx(), hidden.inode), LINUX_ENOENT);
    TestSandbox::assert_errno(sb.lookup_root("hidden-link"), LINUX_ENOENT);

    let created = sb
        .fs
        .symlink(
            sb.ctx(),
            &TestSandbox::cstr("synthetic-target"),
            ROOT_INODE,
            &TestSandbox::cstr("created-link"),
            Extensions::default(),
        )
        .unwrap();
    assert!(sb.fs.tagged_visible(ROOT_INODE, b"created-link"));
    assert_eq!(
        sb.fs.readlink(sb.ctx(), created.inode).unwrap(),
        b"synthetic-target"
    );
    assert!(sb.lookup_root("created-link").is_ok());
    let listed = names(&sb, ROOT_INODE);
    assert!(listed.iter().any(|name| name == b"created-link"));
    assert!(!listed.iter().any(|name| name == b"hidden-link"));
}

#[test]
fn all_readdir_variants_filter_types_and_resume_without_hidden_offsets() {
    let sb = sandbox(StatVirtualization::Off, true);
    sb.host_create_file("secret", b"private");
    sb.host_create_file("public", b"public");
    sb.host_create_dir("branch");
    symlink("public", sb.root.join("file-link")).unwrap();
    symlink("branch", sb.root.join("dir-link")).unwrap();

    let handle = sb.fuse_opendir(ROOT_INODE).unwrap();
    let ordinary: Vec<_> = sb
        .fs
        .readdir(sb.ctx(), ROOT_INODE, handle, 65536, 0)
        .unwrap()
        .into_iter()
        .map(|entry| (entry.name.to_vec(), entry.offset))
        .collect();
    assert_public_only(&ordinary, true);
    assert_eq!(
        ordinary
            .iter()
            .map(|(_, offset)| *offset)
            .collect::<Vec<_>>(),
        vec![1, 2, 3, 4]
    );

    let plus = sb
        .fs
        .readdirplus(sb.ctx(), ROOT_INODE, handle, 65536, 0)
        .unwrap();
    let plus_names: Vec<_> = plus
        .iter()
        .map(|(entry, _)| (entry.name.to_vec(), entry.offset))
        .collect();
    assert_public_only(&plus_names, false);
    for (_, entry) in plus {
        assert_ne!(entry.inode, 0);
        sb.fs.forget(sb.ctx(), entry.inode, 1);
    }

    for with_attributes in [false, true] {
        let mut emitted = Vec::new();
        let mut offset = 0;
        // One accepted entry per callback page exercises the rejected-entry/refcount path.
        for _ in 0..8 {
            let mut page = Vec::new();
            if with_attributes {
                let mut accepted_inode = None;
                sb.fs
                    .readdirplus_for_each(
                        sb.ctx(),
                        ROOT_INODE,
                        handle,
                        65536,
                        offset,
                        &mut |entry, attr| {
                            if !page.is_empty() {
                                return Ok(0);
                            }
                            assert_ne!(attr.inode, 0);
                            accepted_inode = Some(attr.inode);
                            page.push((entry.name.to_vec(), entry.offset));
                            Ok(1)
                        },
                    )
                    .unwrap();
                if let Some(inode) = accepted_inode {
                    sb.fs.forget(sb.ctx(), inode, 1);
                }
            } else {
                sb.fs
                    .readdir_for_each(sb.ctx(), ROOT_INODE, handle, 65536, offset, &mut |entry| {
                        if !page.is_empty() {
                            return Ok(0);
                        }
                        page.push((entry.name.to_vec(), entry.offset));
                        Ok(1)
                    })
                    .unwrap();
            }
            if page.is_empty() {
                break;
            }
            offset = page.last().unwrap().1;
            emitted.extend(page);
        }
        assert_eq!(
            emitted,
            if with_attributes {
                plus_names.clone()
            } else {
                ordinary.clone()
            }
        );
    }
    sb.fs.releasedir(sb.ctx(), ROOT_INODE, 0, handle).unwrap();
    TestSandbox::assert_errno(
        sb.fs.readdir(sb.ctx(), ROOT_INODE, handle, 65536, 0),
        LINUX_EBADF,
    );
}

#[test]
fn readdirplus_rejected_or_failed_callbacks_do_not_leak_lookup_references() {
    for fail in [false, true] {
        let sb = sandbox(StatVirtualization::Off, true);
        sb.host_create_file("public", b"public");
        sb.host_create_file("secret", b"private");
        let public = sb.lookup_root("public").unwrap();
        let handle = sb.fuse_opendir(ROOT_INODE).unwrap();
        let result =
            sb.fs
                .readdirplus_for_each(sb.ctx(), ROOT_INODE, handle, 65536, 0, &mut |entry, _| {
                    assert_eq!(entry.name, b"public");
                    if fail {
                        Err(io::Error::from_raw_os_error(LINUX_EIO))
                    } else {
                        Ok(0)
                    }
                });
        if fail {
            TestSandbox::assert_errno(result, LINUX_EIO);
        } else {
            result.unwrap();
        }
        sb.fs.forget(sb.ctx(), public.inode, 1);
        assert!(sb.fs.getattr(sb.ctx(), public.inode, None).is_err());
        sb.fs.releasedir(sb.ctx(), ROOT_INODE, 0, handle).unwrap();
    }
}

#[test]
fn guest_created_regular_file_is_readable_by_its_exact_identity_tag() {
    let sb = sandbox(StatVirtualization::Off, false);
    let (created, handle) = sb.fuse_create_root("created").unwrap();
    sb.fuse_write(created.inode, handle, b"guest content", 0)
        .unwrap();
    assert!(sb.fs.tagged_visible(ROOT_INODE, b"created"));
    let readable = sb.fuse_open(created.inode, libc::O_RDONLY as u32).unwrap();
    assert_eq!(
        sb.fuse_read(created.inode, readable, 4096, 0).unwrap(),
        b"guest content"
    );
    assert!(sb.lookup_root("created").is_ok());
    assert!(sb.fs.getattr(sb.ctx(), created.inode, None).is_ok());
    assert!(
        sb.fs
            .access(sb.ctx(), created.inode, libc::R_OK as u32)
            .is_ok()
    );
    assert!(names(&sb, ROOT_INODE).iter().any(|name| name == b"created"));
}

#[test]
fn host_replacement_does_not_inherit_a_guest_creation_tag() {
    let sb = sandbox(StatVirtualization::Off, false);
    let (created, handle) = sb.fuse_create_root("created").unwrap();
    sb.fuse_write(created.inode, handle, b"original guest content", 0)
        .unwrap();
    let original_identity = std::fs::metadata(sb.root.join("created")).unwrap().ino();
    sb.host_create_file("replacement", b"host replacement private bytes");
    std::fs::rename(sb.root.join("replacement"), sb.root.join("created")).unwrap();
    assert_ne!(
        std::fs::metadata(sb.root.join("created")).unwrap().ino(),
        original_identity
    );
    assert!(!names(&sb, ROOT_INODE).iter().any(|name| name == b"created"));
    TestSandbox::assert_errno(sb.lookup_root("created"), LINUX_ENOENT);
    assert!(!sb.fs.tagged_visible(ROOT_INODE, b"created"));
    // A previously admitted handle still names its old object, not the replacement.
    assert_eq!(
        sb.fuse_read(created.inode, handle, 4096, 0).unwrap(),
        b"original guest content"
    );
    assert_eq!(
        sb.fs
            .getattr(sb.ctx(), created.inode, Some(handle))
            .unwrap()
            .0
            .st_size,
        22
    );
}

#[test]
fn admitted_handle_survives_new_inode_read_admission_failure() {
    let mut sb = sandbox(StatVirtualization::Off, true);
    sb.host_create_file("secret", b"previously admitted bytes");
    let policy = sb.fs.cfg.mask_policy.take();
    let inode = sb.lookup_root("secret").unwrap().inode;
    let handle = sb.fuse_open(inode, libc::O_RDONLY as u32).unwrap();
    sb.fs.cfg.mask_policy = policy;
    // As above, fixture-only cache seeding does not define a live policy-reload API.
    assert_cached_read_denied(&sb, inode);
    assert_eq!(
        sb.fuse_read(inode, handle, 4096, 0).unwrap(),
        b"previously admitted bytes"
    );
    assert_eq!(
        sb.fs
            .getattr(sb.ctx(), inode, Some(handle))
            .unwrap()
            .0
            .st_size,
        25
    );
    sb.fs
        .release(sb.ctx(), inode, 0, handle, false, false, None)
        .unwrap();
    TestSandbox::assert_errno(sb.fuse_read(inode, handle, 4096, 0), LINUX_EBADF);
}

#[test]
fn authorized_cached_write_open_adopts_the_exact_hidden_file_identity() {
    let mut sb = sandbox(StatVirtualization::Off, false);
    sb.host_create_file("adopted", b"host content");
    let inode = cached_host_inode(&mut sb, "adopted");
    assert_cached_read_denied(&sb, inode);
    assert!(!sb.fs.tagged_visible(ROOT_INODE, b"adopted"));

    let writable = sb.fuse_open(inode, libc::O_WRONLY as u32).unwrap();
    assert!(sb.fs.tagged_visible(ROOT_INODE, b"adopted"));
    assert_eq!(sb.lookup_root("adopted").unwrap().inode, inode);
    let readable = sb.fuse_open(inode, libc::O_RDONLY as u32).unwrap();
    assert_eq!(
        sb.fuse_read(inode, readable, 4096, 0).unwrap(),
        b"host content"
    );
    sb.fuse_write(inode, writable, b"guest", 0).unwrap();
    assert_eq!(
        sb.fuse_read(inode, readable, 4096, 0).unwrap(),
        b"guestcontent"
    );
    assert!(names(&sb, ROOT_INODE).iter().any(|name| name == b"adopted"));
}

#[test]
fn readonly_write_attempt_does_not_tag_or_truncate_a_hidden_cached_file() {
    let mut sb = sandbox(StatVirtualization::Off, true);
    sb.host_create_file("secret", b"unchanged synthetic bytes");
    let inode = cached_host_inode(&mut sb, "secret");
    for flags in [libc::O_WRONLY, libc::O_RDWR, libc::O_WRONLY | libc::O_TRUNC] {
        TestSandbox::assert_errno(sb.fuse_open(inode, flags as u32), LINUX_EROFS);
    }
    assert!(!sb.fs.tagged_visible(ROOT_INODE, b"secret"));
    assert_eq!(
        std::fs::read(sb.root.join("secret")).unwrap(),
        b"unchanged synthetic bytes"
    );
    assert_cached_read_denied(&sb, inode);
}
