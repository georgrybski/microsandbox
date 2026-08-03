#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{path::PathBuf, sync::Arc};

use super::mount_policy::{
    CaseSensitivity, CompiledRuleSet, MountPolicyProgram, PathPolicyRule, Pattern, RuleEffect,
    RuleOrigin, ScopeKind,
};
use super::*;

fn program(
    mask: &[&str],
    unmask: &[&str],
    protect: &[&str],
    write_allow: &[&str],
    write_deny: &[&str],
) -> MountPolicyProgram {
    let origin = RuleOrigin {
        layer: "test".into(),
        file: PathBuf::from("test.json"),
        scope_kind: ScopeKind::Workload,
    };
    let rule = |effect, pattern: &&str| PathPolicyRule {
        effect,
        pattern: Pattern::parse(pattern).unwrap(),
        overridable: true,
        origin: origin.clone(),
    };
    MountPolicyProgram {
        version: 1,
        rules: mask
            .iter()
            .map(|pattern| rule(RuleEffect::Mask, pattern))
            .chain(
                unmask
                    .iter()
                    .map(|pattern| rule(RuleEffect::Unmask, pattern)),
            )
            .collect(),
        protect: protect
            .iter()
            .map(|pattern| rule(RuleEffect::Mask, pattern))
            .collect(),
        writes: CompiledRuleSet {
            allow: write_allow
                .iter()
                .map(|pattern| rule(RuleEffect::Unmask, pattern))
                .collect(),
            deny: write_deny
                .iter()
                .map(|pattern| rule(RuleEffect::Mask, pattern))
                .collect(),
        },
        case_sensitivity: CaseSensitivity::Sensitive,
    }
}

fn sandbox(policy: MountPolicyProgram) -> TestSandbox {
    let policy = Arc::new(policy);
    TestSandbox::with_config(|mut cfg| {
        cfg.mask_policy = Some(policy);
        cfg
    })
}

// A host-created inode is not normally discoverable through a masked lookup. This
// models an inode already cached by the guest before the policy was installed.
fn host_inode(sb: &mut TestSandbox, name: &str) -> u64 {
    let policy = sb.fs.cfg.mask_policy.take();
    let inode = sb.lookup_root(name).unwrap().inode;
    sb.fs.cfg.mask_policy = policy;
    inode
}

fn host_child_inode(sb: &mut TestSandbox, parent: u64, name: &str) -> u64 {
    let policy = sb.fs.cfg.mask_policy.take();
    let inode = sb.lookup(parent, name).unwrap().inode;
    sb.fs.cfg.mask_policy = policy;
    inode
}

fn names(sb: &TestSandbox, inode: u64) -> Vec<Vec<u8>> {
    let handle = sb.fuse_opendir(inode).unwrap();
    sb.fs
        .readdir(sb.ctx(), inode, handle, 65536, 0)
        .unwrap()
        .into_iter()
        .map(|entry| entry.name.to_vec())
        .collect()
}

fn rename(sb: &TestSandbox, old: &str, new: &str) -> std::io::Result<()> {
    sb.fs.rename(
        sb.ctx(),
        ROOT_INODE,
        &TestSandbox::cstr(old),
        ROOT_INODE,
        &TestSandbox::cstr(new),
        0,
    )
}

#[test]
fn create_at_masked_path_tags_it() {
    let sb = sandbox(program(&[".env"], &[], &[], &[], &[]));
    sb.fuse_create_root(".env").unwrap();
    assert!(sb.lookup_root(".env").is_ok());
    assert!(names(&sb, ROOT_INODE).iter().any(|name| name == b".env"));
}

#[test]
fn write_open_existing_masked_tags_it() {
    let mut sb = sandbox(program(&[".env"], &[], &[], &[], &[]));
    sb.host_create_file(".env", b"old");
    let inode = host_inode(&mut sb, ".env");
    sb.fuse_open(inode, libc::O_WRONLY as u32).unwrap();
    assert!(sb.lookup_root(".env").is_ok());
}

#[test]
fn read_open_untagged_masked_is_enoent() {
    let mut sb = sandbox(program(&[".env"], &[], &[], &[], &[]));
    sb.host_create_file(".env", b"old");
    let inode = host_inode(&mut sb, ".env");
    TestSandbox::assert_errno(sb.fuse_open(inode, libc::O_RDONLY as u32), LINUX_ENOENT);
}

#[test]
fn unlink_untagged_masked_is_enoent_no_host_mutation() {
    let sb = sandbox(program(&[".env"], &[], &[], &[], &[]));
    sb.host_create_file(".env", b"old");
    TestSandbox::assert_errno(
        sb.fs
            .unlink(sb.ctx(), ROOT_INODE, &TestSandbox::cstr(".env")),
        LINUX_ENOENT,
    );
    assert!(sb.root.join(".env").exists());
}

#[test]
fn unlink_tagged_masked_succeeds_and_evicts() {
    let sb = sandbox(program(&[".env"], &[], &[], &[], &[]));
    sb.fuse_create_root(".env").unwrap();
    sb.fs
        .unlink(sb.ctx(), ROOT_INODE, &TestSandbox::cstr(".env"))
        .unwrap();
    assert!(!sb.root.join(".env").exists());
    sb.host_create_file(".env", b"new");
    TestSandbox::assert_errno(sb.lookup_root(".env"), LINUX_ENOENT);
}

#[test]
fn rmdir_untagged_masked_is_enoent() {
    let sb = sandbox(program(&["secrets"], &[], &[], &[], &[]));
    sb.host_create_dir("secrets");
    TestSandbox::assert_errno(
        sb.fs
            .rmdir(sb.ctx(), ROOT_INODE, &TestSandbox::cstr("secrets")),
        LINUX_ENOENT,
    );
    assert!(sb.root.join("secrets").is_dir());
}

#[test]
fn cascade_delete_removes_only_untagged_masked() {
    let mut sb = sandbox(program(
        &["dir/**", "onlymasked/**"],
        &["dir/keep.txt"],
        &[],
        &[],
        &[],
    ));
    sb.host_create_file("dir/a.txt", b"a");
    sb.host_create_file("dir/sub/b.txt", b"b");
    sb.host_create_file("dir/keep.txt", b"keep");
    let dir = host_inode(&mut sb, "dir");
    TestSandbox::assert_errno(
        sb.fs.rmdir(sb.ctx(), ROOT_INODE, &TestSandbox::cstr("dir")),
        LINUX_ENOTEMPTY,
    );
    assert!(sb.root.join("dir/keep.txt").exists());
    assert!(dir > 0);

    sb.host_create_file("onlymasked/a.txt", b"a");
    sb.host_create_file("onlymasked/sub/b.txt", b"b");
    sb.host_create_dir("onlymasked");
    sb.fs
        .rmdir(sb.ctx(), ROOT_INODE, &TestSandbox::cstr("onlymasked"))
        .unwrap();
    assert!(!sb.root.join("onlymasked").exists());
}

#[test]
fn cascade_blocked_by_protected_no_name_leak() {
    let mut sb = sandbox(program(&["dir/**"], &[], &["dir/prot.txt"], &[], &[]));
    sb.host_create_file("dir/a.txt", b"a");
    sb.host_create_file("dir/prot.txt", b"p");
    host_inode(&mut sb, "dir");
    TestSandbox::assert_errno(
        sb.fs.rmdir(sb.ctx(), ROOT_INODE, &TestSandbox::cstr("dir")),
        LINUX_ENOTEMPTY,
    );
}

#[test]
fn cascade_blocked_by_tagged_descendant_no_data_loss() {
    let mut sb = sandbox(program(
        &["dir/secrets", "dir/secrets/**"],
        &[],
        &[],
        &[],
        &[],
    ));
    sb.host_create_dir("dir");
    sb.host_create_dir("dir/secrets");
    sb.host_create_file("dir/secrets/untagged.txt", b"host data");
    let dir = host_inode(&mut sb, "dir");
    let secrets = host_child_inode(&mut sb, dir, "secrets");

    // Creating through the guest tags this masked child under the real secrets inode.
    sb.fuse_create(secrets, "tagged.txt", 0o644).unwrap();
    assert!(sb.fs.tagged_visible(secrets, b"tagged.txt"));

    TestSandbox::assert_errno(
        sb.fs.rmdir(sb.ctx(), dir, &TestSandbox::cstr("secrets")),
        LINUX_ENOTEMPTY,
    );
    assert!(sb.root.join("dir/secrets/tagged.txt").exists());
}

#[test]
fn cascade_uses_correct_parent_for_tagged_check() {
    let mut sb = sandbox(program(
        &["dir/secrets", "dir/secrets/**"],
        &[],
        &[],
        &[],
        &[],
    ));
    sb.host_create_dir("dir");
    sb.host_create_dir("dir/secrets");
    let dir = host_inode(&mut sb, "dir");
    let secrets = host_child_inode(&mut sb, dir, "secrets");
    sb.fuse_create(secrets, "tagged.txt", 0o644).unwrap();

    assert!(sb.fs.tagged_visible(secrets, b"tagged.txt"));
    assert!(!sb.fs.tagged_visible(0, b"tagged.txt"));
    // Before the fix, cascade_remove used parent 0 and deleted this file.
    TestSandbox::assert_errno(
        sb.fs.rmdir(sb.ctx(), dir, &TestSandbox::cstr("secrets")),
        LINUX_ENOTEMPTY,
    );
    assert!(sb.root.join("dir/secrets/tagged.txt").exists());
}

#[test]
fn cascade_evicts_descendant_tags() {
    let mut sb = sandbox(program(&["dir/**"], &[], &[], &[], &[]));
    sb.host_create_dir("dir");
    sb.host_create_file("dir/untagged.txt", b"host");
    let dir = host_inode(&mut sb, "dir");
    sb.fuse_create(dir, "tagged.txt", 0o644).unwrap();
    assert!(sb.fs.tagged_visible(dir, b"tagged.txt"));

    sb.fs
        .unlink(sb.ctx(), dir, &TestSandbox::cstr("tagged.txt"))
        .unwrap();
    assert!(!sb.fs.tagged_visible(dir, b"tagged.txt"));
    sb.fs
        .rmdir(sb.ctx(), ROOT_INODE, &TestSandbox::cstr("dir"))
        .unwrap();
    assert!(!sb.root.join("dir").exists());
    assert!(!sb.fs.tagged_visible(dir, b"tagged.txt"));
}

#[test]
fn rename_masked_untagged_source_is_enoent_anti_laundering() {
    let sb = sandbox(program(&[".env"], &[], &[], &[], &[]));
    sb.host_create_file(".env", b"secret");
    TestSandbox::assert_errno(rename(&sb, ".env", "visible.txt"), LINUX_ENOENT);
    assert!(sb.root.join(".env").exists());
    assert!(!sb.root.join("visible.txt").exists());
}

#[test]
fn rename_masked_tagged_source_allowed_tag_invalidates() {
    let sb = sandbox(program(&[".env", ".env2"], &[], &[], &[], &[]));
    sb.fuse_create_root(".env").unwrap();
    rename(&sb, ".env", "dst.txt").unwrap();
    assert!(sb.lookup_root("dst.txt").is_ok());
    TestSandbox::assert_errno(sb.lookup_root(".env"), LINUX_ENOENT);
    rename(&sb, "dst.txt", ".env2").unwrap();
    TestSandbox::assert_errno(sb.lookup_root(".env2"), LINUX_ENOENT);
}

#[test]
fn rename_overwrite_invalidates_target_tag() {
    let mut sb = sandbox(program(&[".env"], &[], &[], &[], &[]));
    let (target, _) = sb.fuse_create_root(".env").unwrap();
    sb.host_create_file("other.txt", b"source");
    let source = host_inode(&mut sb, "other.txt");
    rename(&sb, "other.txt", ".env").unwrap();
    assert_eq!(std::fs::read(sb.root.join(".env")).unwrap(), b"source");
    assert_ne!(target.inode, source);
    TestSandbox::assert_errno(sb.lookup_root(".env"), LINUX_ENOENT);
}

#[cfg(target_os = "linux")]
#[test]
fn rename_exchange_identical_identity_evicts_tags() {
    let sb = sandbox(program(&[".env", ".env2"], &[], &[], &[], &[]));
    let (entry, _handle) = sb.fuse_create_root(".env").unwrap();
    sb.fs
        .link(
            sb.ctx(),
            entry.inode,
            ROOT_INODE,
            &TestSandbox::cstr(".env2"),
        )
        .unwrap();
    assert!(sb.fs.tagged_visible(ROOT_INODE, b".env"));

    sb.fs
        .rename(
            sb.ctx(),
            ROOT_INODE,
            &TestSandbox::cstr(".env"),
            ROOT_INODE,
            &TestSandbox::cstr(".env2"),
            2,
        )
        .unwrap();
    assert!(!sb.fs.tagged_visible(ROOT_INODE, b".env"));
    assert!(!sb.fs.tagged_visible(ROOT_INODE, b".env2"));
    TestSandbox::assert_errno(sb.lookup_root(".env"), LINUX_ENOENT);
    TestSandbox::assert_errno(sb.lookup_root(".env2"), LINUX_ENOENT);
}

#[test]
fn protect_is_untouchable_and_never_tagged() {
    let mut sb = sandbox(program(&[], &[], &[".workestrate"], &[], &[]));
    sb.host_create_dir(".workestrate");
    let inode = host_inode(&mut sb, ".workestrate");
    TestSandbox::assert_errno(sb.lookup_root(".workestrate"), LINUX_ENOENT);
    assert!(
        !names(&sb, ROOT_INODE)
            .iter()
            .any(|name| name == b".workestrate")
    );
    TestSandbox::assert_errno(sb.fuse_create_root(".workestrate"), LINUX_EACCES);
    TestSandbox::assert_errno(sb.fuse_open(inode, libc::O_WRONLY as u32), LINUX_EACCES);
    TestSandbox::assert_errno(
        sb.fs
            .unlink(sb.ctx(), ROOT_INODE, &TestSandbox::cstr(".workestrate")),
        LINUX_ENOENT,
    );
    TestSandbox::assert_errno(rename(&sb, ".workestrate", "x"), LINUX_ENOENT);
    TestSandbox::assert_errno(rename(&sb, "x", ".workestrate"), LINUX_ENOENT);
    TestSandbox::assert_errno(sb.lookup_root(".workestrate"), LINUX_ENOENT);
}

#[test]
fn write_rule_deny_blocks_create_no_host_file() {
    let mut sb = sandbox(program(&["out/**"], &[], &[], &[], &["out/secret"]));
    sb.host_create_dir("out");
    let out = host_inode(&mut sb, "out");
    TestSandbox::assert_errno(sb.fuse_create(out, "secret", 0o644), LINUX_EACCES);
    sb.fuse_create(out, "other", 0o644).unwrap();
    TestSandbox::assert_errno(sb.lookup(out, "secret"), LINUX_ENOENT);
    assert!(!sb.root.join("out/secret").exists());
    assert!(sb.root.join("out/other").exists());
}

#[test]
fn unlink_visible_write_denied_is_eacces() {
    let sb = sandbox(program(&[], &[], &[], &[], &["blocked.txt"]));
    sb.host_create_file("blocked.txt", b"x");
    TestSandbox::assert_errno(
        sb.fs
            .unlink(sb.ctx(), ROOT_INODE, &TestSandbox::cstr("blocked.txt")),
        LINUX_EACCES,
    );
    assert!(sb.root.join("blocked.txt").exists());
}

#[test]
fn rmdir_visible_write_denied_is_eacces() {
    let sb = sandbox(program(&[], &[], &[], &[], &["blockeddir"]));
    sb.host_create_dir("blockeddir");
    TestSandbox::assert_errno(
        sb.fs
            .rmdir(sb.ctx(), ROOT_INODE, &TestSandbox::cstr("blockeddir")),
        LINUX_EACCES,
    );
    assert!(sb.root.join("blockeddir").is_dir());
}

#[test]
fn unlink_masked_untagged_write_denied_is_enoent_precedence() {
    let sb = sandbox(program(&[".env"], &[], &[], &[], &[".env"]));
    sb.host_create_file(".env", b"x");
    TestSandbox::assert_errno(
        sb.fs
            .unlink(sb.ctx(), ROOT_INODE, &TestSandbox::cstr(".env")),
        LINUX_ENOENT,
    );
    assert!(sb.root.join(".env").exists());
}

#[test]
fn unlink_tagged_masked_write_denied_is_eacces() {
    let mut sb = sandbox(program(&[".env"], &[], &[], &[], &[]));
    sb.fuse_create_root(".env").unwrap();
    sb.fs.cfg.mask_policy = Some(Arc::new(program(&[".env"], &[], &[], &[], &[".env"])));
    TestSandbox::assert_errno(
        sb.fs
            .unlink(sb.ctx(), ROOT_INODE, &TestSandbox::cstr(".env")),
        LINUX_EACCES,
    );
    assert!(sb.root.join(".env").exists());
}

#[test]
fn rmdir_tagged_masked_write_denied_is_eacces() {
    let mut sb = sandbox(program(&["d"], &[], &[], &[], &[]));
    sb.fuse_mkdir_root("d").unwrap();
    sb.fs.tag_child(ROOT_INODE, b"d");
    sb.fs.cfg.mask_policy = Some(Arc::new(program(&["d"], &[], &[], &[], &["d"])));
    TestSandbox::assert_errno(
        sb.fs.rmdir(sb.ctx(), ROOT_INODE, &TestSandbox::cstr("d")),
        LINUX_EACCES,
    );
}

#[test]
fn open_visible_write_denied_is_eacces() {
    let mut sb = sandbox(program(&[], &[], &[], &[], &["blocked.txt"]));
    sb.host_create_file("blocked.txt", b"x");
    let inode = host_inode(&mut sb, "blocked.txt");
    TestSandbox::assert_errno(sb.fuse_open(inode, libc::O_WRONLY as u32), LINUX_EACCES);
    TestSandbox::assert_errno(sb.fuse_open(inode, libc::O_RDWR as u32), LINUX_EACCES);
    assert!(sb.fuse_open(inode, libc::O_RDONLY as u32).is_ok());
}

#[test]
fn write_tagged_masked_write_denied_is_eacces() {
    let mut sb = sandbox(program(&[".env"], &[], &[], &[], &[]));
    let (entry, handle) = sb.fuse_create_root(".env").unwrap();
    sb.fs.cfg.mask_policy = Some(Arc::new(program(&[".env"], &[], &[], &[], &[".env"])));
    TestSandbox::assert_errno(sb.fuse_write(entry.inode, handle, b"more", 0), LINUX_EACCES);
    TestSandbox::assert_errno(
        sb.fuse_open(entry.inode, libc::O_WRONLY as u32),
        LINUX_EACCES,
    );
}

#[test]
fn write_visible_not_denied_succeeds() {
    let mut sb = sandbox(program(&[], &[], &[], &[], &["blocked.txt"]));
    sb.host_create_file("ok.txt", b"old");
    let inode = host_inode(&mut sb, "ok.txt");
    let handle = sb.fuse_open(inode, libc::O_RDWR as u32).unwrap();
    sb.fuse_write(inode, handle, b"new", 0).unwrap();
}

#[test]
fn read_visible_write_denied_succeeds() {
    let mut sb = sandbox(program(&[], &[], &[], &[], &["blocked.txt"]));
    sb.host_create_file("blocked.txt", b"content");
    let inode = host_inode(&mut sb, "blocked.txt");
    let handle = sb.fuse_open(inode, libc::O_RDONLY as u32).unwrap();
    let data = sb.fuse_read(inode, handle, 4096, 0).unwrap();
    assert_eq!(&data[..], b"content");
}

#[test]
fn leak_freedom_denied_ops() {
    let mut sb = sandbox(program(
        &["masked", "rename-me"],
        &[],
        &["protected"],
        &[],
        &["masked/denied"],
    ));
    sb.host_create_dir("masked");
    sb.host_create_file("rename-me", b"keep");
    let masked = host_inode(&mut sb, "masked");
    TestSandbox::assert_errno(sb.fuse_create_root("protected"), LINUX_EACCES);
    TestSandbox::assert_errno(sb.fuse_create(masked, "denied", 0o644), LINUX_EACCES);
    TestSandbox::assert_errno(
        sb.fs
            .unlink(sb.ctx(), ROOT_INODE, &TestSandbox::cstr("rename-me")),
        LINUX_ENOENT,
    );
    TestSandbox::assert_errno(rename(&sb, "rename-me", "renamed"), LINUX_ENOENT);
    assert!(!sb.root.join("protected").exists());
    assert!(sb.root.join("rename-me").exists());
    assert!(!sb.root.join("renamed").exists());
    assert!(!sb.root.join("masked/denied").exists());
}

#[test]
fn mutation_byte_identical_off_when_policy_none() {
    let configured = TestSandbox::with_config(|mut cfg| {
        cfg.mask_policy = None;
        cfg
    });
    let default = TestSandbox::new();
    for sb in [&configured, &default] {
        sb.fuse_create_root("a").unwrap();
        rename(sb, "a", "b").unwrap();
        sb.fs
            .unlink(sb.ctx(), ROOT_INODE, &TestSandbox::cstr("b"))
            .unwrap();
    }
    assert!(!configured.root.join("a").exists());
    assert!(!configured.root.join("b").exists());
    assert!(!default.root.join("a").exists());
    assert!(!default.root.join("b").exists());
}

#[test]
fn identity_revalidation_evicts_on_host_replace() {
    let sb = sandbox(program(&[".env"], &[], &[], &[], &[]));
    sb.fuse_create_root(".env").unwrap();
    std::fs::remove_file(sb.root.join(".env")).unwrap();
    sb.host_create_file(".env", b"replacement");
    TestSandbox::assert_errno(sb.lookup_root(".env"), LINUX_ENOENT);
}
