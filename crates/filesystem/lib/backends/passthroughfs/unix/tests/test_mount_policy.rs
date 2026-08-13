use super::mount_policy::{
    CaseSensitivity, CompiledRuleSet, Decision, LexicalPath, MountPolicyProgram, PathPolicyRule,
    Pattern, RuleEffect, RuleOrigin, ScopeKind,
};
use super::*;
use std::path::PathBuf;
use std::sync::Arc;

#[allow(clippy::expect_used, clippy::unwrap_used)]
#[cfg(test)]
mod snapshot_tests {
    use super::*;

    fn names_and_offsets(sb: &TestSandbox, inode: u64) -> (Vec<Vec<u8>>, Vec<u64>) {
        let handle = sb.fuse_opendir(inode).unwrap();
        let entries = sb.fs.readdir(sb.ctx(), inode, handle, 65536, 0).unwrap();
        (
            entries.iter().map(|entry| entry.name.to_vec()).collect(),
            entries.iter().map(|entry| entry.offset).collect(),
        )
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn masked_entries_are_omitted_from_readdir() {
        let policy = Arc::new(program(&[".env", ".git"], &[]));
        let sb = TestSandbox::with_config(|mut cfg| {
            cfg.mask_policy = Some(policy);
            cfg
        });
        sb.host_create_file(".env", b"secret");
        sb.host_create_file("visible.txt", b"visible");
        sb.host_create_dir(".git");

        let (names, _) = names_and_offsets(&sb, ROOT_INODE);
        assert!(!names.iter().any(|name| name == b".env"));
        assert!(!names.iter().any(|name| name == b".git"));
        assert!(names.iter().any(|name| name == b"visible.txt"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn traversal_only_directory_is_listed_and_masks_secret_children() {
        let policy = Arc::new(program(&["private/**"], &["private/public/**"]));
        let sb = TestSandbox::with_config(|mut cfg| {
            cfg.mask_policy = Some(policy);
            cfg
        });
        sb.host_create_dir("private/public");
        sb.host_create_file("private/secret.txt", b"secret");

        let private = sb.lookup_root("private").unwrap();
        let (root_names, _) = names_and_offsets(&sb, ROOT_INODE);
        assert!(root_names.iter().any(|name| name == b"private"));

        let (private_names, _) = names_and_offsets(&sb, private.inode);
        assert!(private_names.iter().any(|name| name == b"public"));
        assert!(!private_names.iter().any(|name| name == b"secret.txt"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn host_created_entries_are_filtered_at_snapshot_time() {
        let policy = Arc::new(program(&[".env"], &[]));
        let sb = TestSandbox::with_config(|mut cfg| {
            cfg.mask_policy = Some(policy);
            cfg
        });
        sb.host_create_file(".env", b"secret");
        sb.host_create_file("host-visible.txt", b"visible");

        let (names, _) = names_and_offsets(&sb, ROOT_INODE);
        assert!(!names.iter().any(|name| name == b".env"));
        assert!(names.iter().any(|name| name == b"host-visible.txt"));
    }

    #[test]
    fn absent_mask_policy_is_byte_identical_to_default() {
        let configured = TestSandbox::with_config(|mut cfg| {
            cfg.mask_policy = None;
            cfg
        });
        let default = TestSandbox::new();
        for sandbox in [&configured, &default] {
            sandbox.host_create_file(".env", b"secret");
            sandbox.host_create_file("visible.txt", b"visible");
        }

        let (mut configured_names, _) = names_and_offsets(&configured, ROOT_INODE);
        let (mut default_names, _) = names_and_offsets(&default, ROOT_INODE);
        configured_names.sort();
        default_names.sort();
        assert_eq!(configured_names, default_names);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn filtered_snapshot_offsets_are_contiguous() {
        let policy = Arc::new(program(&[".env", ".git"], &[]));
        let sb = TestSandbox::with_config(|mut cfg| {
            cfg.mask_policy = Some(policy);
            cfg
        });
        sb.host_create_file(".env", b"secret");
        sb.host_create_file("visible.txt", b"visible");
        sb.host_create_dir(".git");
        sb.host_create_file("another.txt", b"visible");

        let (_, offsets) = names_and_offsets(&sb, ROOT_INODE);
        let expected: Vec<u64> = (1..=offsets.len() as u64).collect();
        assert_eq!(offsets, expected);
    }
}

fn program(mask: &[&str], unmask: &[&str]) -> MountPolicyProgram {
    let origin = RuleOrigin {
        layer: "test".to_string(),
        file: PathBuf::from("test.json"),
        scope_kind: ScopeKind::Workload,
    };
    let rules = mask
        .iter()
        .map(|pattern| PathPolicyRule {
            effect: RuleEffect::Mask,
            pattern: Pattern::parse(pattern).unwrap(),
            overridable: true,
            origin: origin.clone(),
        })
        .chain(unmask.iter().map(|pattern| PathPolicyRule {
            effect: RuleEffect::Unmask,
            pattern: Pattern::parse(pattern).unwrap(),
            overridable: true,
            origin: origin.clone(),
        }))
        .collect();
    MountPolicyProgram {
        version: 1,
        rules,
        protect: Vec::new(),
        writes: CompiledRuleSet::default(),
        case_sensitivity: CaseSensitivity::Sensitive,
    }
}

fn decide(policy: &MountPolicyProgram, path: &str) -> Decision {
    policy.decide(&LexicalPath::new(path).unwrap()).decision
}

#[test]
fn traversal_only_and_masked_descendants_are_distinct() {
    let policy = program(&["private/**"], &["private/public/**"]);
    assert_eq!(decide(&policy, "private"), Decision::TraversalOnly);
    assert_eq!(decide(&policy, "private/public/file"), Decision::Visible);
    assert_eq!(decide(&policy, "private/other/file"), Decision::Masked);
}

#[test]
fn literal_prefix_and_floating_patterns_are_conservative() {
    let policy = program(&["a/**"], &["a/b/**"]);
    assert!(policy.may_unmask_descendant(&LexicalPath::new("a").unwrap()));
    assert!(!policy.may_unmask_descendant(&LexicalPath::new("docs").unwrap()));
    let floating = program(&["a/**"], &["**/x"]);
    assert!(floating.may_unmask_descendant(&LexicalPath::new("any/dir").unwrap()));
}

#[test]
fn non_utf8_paths_fail_closed_and_children_validate() {
    let policy = program(&[".env"], &[]);
    let path = LexicalPath::from_bytes(b"\xff").unwrap();
    let result = policy.decide(&path);
    assert_eq!(result.decision, Decision::Masked);
    assert!(result.fail_closed_non_utf8);
    assert_eq!(
        policy
            .decide_child(&LexicalPath::new("dir").unwrap(), "..")
            .decision,
        Decision::Masked
    );
}

#[test]
fn json_round_trip_preserves_wire_and_decisions() {
    let policy = program(&[".env"], &[]);
    let json = serde_json::to_value(&policy).unwrap();
    assert_eq!(json["version"], 1);
    assert_eq!(json["rules"][0]["pattern"], ".env");
    let back: MountPolicyProgram = serde_json::from_value(json.clone()).unwrap();
    assert_eq!(back, policy);
    assert_eq!(decide(&back, ".env"), decide(&policy, ".env"));
    let mut missing = json.clone();
    missing.as_object_mut().unwrap().remove("version");
    assert!(serde_json::from_value::<MountPolicyProgram>(missing).is_err());
    let mut unsupported = json.clone();
    unsupported["version"] = serde_json::json!(2);
    assert!(serde_json::from_value::<MountPolicyProgram>(unsupported).is_err());
    let mut unknown = json;
    unknown["extra"] = serde_json::json!(true);
    assert!(serde_json::from_value::<MountPolicyProgram>(unknown).is_err());
}

#[test]
fn case_insensitive_pattern_matches_different_case() {
    let json = r#"{
        "version": 1,
        "rules": [{"effect":"mask","pattern":"**/.ENV","overridable":true,"origin":{"layer":"test","file":"test.json","scope_kind":"workload"}}],
        "protect": [],
        "writes": {"allow": [], "deny": []},
        "case_sensitivity": "insensitive"
    }"#;
    let policy: MountPolicyProgram = serde_json::from_str(json).unwrap();
    assert_eq!(decide(&policy, ".env"), Decision::Masked);
    assert_eq!(decide(&policy, "subdir/.env"), Decision::Masked);
}

#[cfg(target_os = "linux")]
#[test]
fn lookup_masks_policy_path_and_none_is_byte_identical_off() {
    let masked = Arc::new(program(&[".env"], &[]));
    let masked_sb = TestSandbox::with_config(|mut cfg| {
        cfg.mask_policy = Some(masked);
        cfg
    });
    masked_sb.host_create_file(".env", b"secret");
    masked_sb.host_create_file("visible.txt", b"visible");
    TestSandbox::assert_errno(masked_sb.lookup_root(".env"), LINUX_ENOENT);
    assert!(masked_sb.lookup_root("visible.txt").is_ok());

    let absent_sb = TestSandbox::new();
    absent_sb.host_create_file(".env", b"secret");
    absent_sb.host_create_file("visible.txt", b"visible");
    assert!(absent_sb.lookup_root(".env").is_ok());
    assert!(absent_sb.lookup_root("visible.txt").is_ok());
}
