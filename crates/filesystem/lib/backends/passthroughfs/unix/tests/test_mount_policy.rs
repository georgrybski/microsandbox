use super::mount_policy::{
    CaseSensitivity, CompiledRuleSet, Decision, LexicalPath, MountPolicyProgram, PathPolicyRule,
    Pattern, RuleEffect, RuleOrigin, ScopeKind, WriteDecision, WriteRuleEffect,
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

fn write_rule(pattern: &str, scope_kind: ScopeKind, overridable: bool) -> PathPolicyRule {
    PathPolicyRule {
        effect: RuleEffect::Mask,
        pattern: Pattern::parse(pattern).unwrap(),
        overridable,
        origin: RuleOrigin {
            layer: "test".to_string(),
            file: PathBuf::from("test.json"),
            scope_kind,
        },
    }
}

fn write_program(
    protect: &[&str],
    allow: &[(&str, ScopeKind, bool)],
    deny: &[(&str, ScopeKind, bool)],
) -> MountPolicyProgram {
    MountPolicyProgram {
        version: 1,
        rules: Vec::new(),
        protect: protect
            .iter()
            .map(|pattern| write_rule(pattern, ScopeKind::Workload, true))
            .collect(),
        writes: CompiledRuleSet {
            allow: allow
                .iter()
                .map(|(pattern, scope_kind, overridable)| {
                    write_rule(pattern, *scope_kind, *overridable)
                })
                .collect(),
            deny: deny
                .iter()
                .map(|(pattern, scope_kind, overridable)| {
                    write_rule(pattern, *scope_kind, *overridable)
                })
                .collect(),
        },
        case_sensitivity: CaseSensitivity::Sensitive,
    }
}

fn decide_write(policy: &MountPolicyProgram, path: &str) -> WriteDecision {
    policy
        .decide_write(&LexicalPath::new(path).unwrap())
        .decision
}

#[test]
fn write_allow_carves_exception_within_same_scope() {
    let policy = write_program(
        &[],
        &[("secrets/public.txt", ScopeKind::Workload, true)],
        &[("secrets/**", ScopeKind::Workload, true)],
    );
    assert_eq!(
        decide_write(&policy, "secrets/public.txt"),
        WriteDecision::Allow
    );
    assert_eq!(
        decide_write(&policy, "secrets/key.pem"),
        WriteDecision::Deny
    );
}

#[test]
fn write_allow_rule_is_active_and_recorded() {
    let policy = write_program(&[], &[("docs/**", ScopeKind::Workload, true)], &[]);
    let explained = policy.decide_write(&LexicalPath::new("docs/a.txt").unwrap());
    assert_eq!(explained.decision, WriteDecision::Allow);
    assert_eq!(explained.matches.len(), 1);
    assert_eq!(explained.matches[0].effect, WriteRuleEffect::Allow);
    assert!(!explained.matches[0].frozen_out);
}

#[test]
fn higher_authority_write_rule_wins_regardless_of_bucket() {
    let deny_wins = write_program(
        &[],
        &[("f.txt", ScopeKind::Workload, true)],
        &[("f.txt", ScopeKind::HomeRegistry, true)],
    );
    assert_eq!(decide_write(&deny_wins, "f.txt"), WriteDecision::Deny);

    let allow_wins = write_program(
        &[],
        &[("f.txt", ScopeKind::HomeRegistry, true)],
        &[("f.txt", ScopeKind::Workload, true)],
    );
    assert_eq!(decide_write(&allow_wins, "f.txt"), WriteDecision::Allow);
}

#[test]
fn terminal_write_deny_cannot_be_allowed_over() {
    let policy = write_program(
        &[],
        &[("f.txt", ScopeKind::HomeRegistry, true)],
        &[("f.txt", ScopeKind::Workload, false)],
    );
    let explained = policy.decide_write(&LexicalPath::new("f.txt").unwrap());
    assert_eq!(explained.decision, WriteDecision::Deny);
    assert_eq!(
        explained.frozen_by,
        Some(RuleOrigin {
            layer: "test".to_string(),
            file: PathBuf::from("test.json"),
            scope_kind: ScopeKind::Workload,
        })
    );
    let allow_match = explained
        .matches
        .iter()
        .find(|m| m.effect == WriteRuleEffect::Allow)
        .unwrap();
    assert!(allow_match.frozen_out);
}

#[test]
fn terminal_write_allow_cannot_be_denied_over() {
    let policy = write_program(
        &[],
        &[("f.txt", ScopeKind::Workload, false)],
        &[("f.txt", ScopeKind::HomeRegistry, true)],
    );
    let explained = policy.decide_write(&LexicalPath::new("f.txt").unwrap());
    assert_eq!(explained.decision, WriteDecision::Allow);
    let deny_match = explained
        .matches
        .iter()
        .find(|m| m.effect == WriteRuleEffect::Deny)
        .unwrap();
    assert!(deny_match.frozen_out);
}

#[test]
fn protect_short_circuits_write_allow() {
    let policy = write_program(
        &[".secret"],
        &[
            (".secret", ScopeKind::HomeRegistry, true),
            (".secret", ScopeKind::Workload, false),
        ],
        &[],
    );
    let explained = policy.decide_write(&LexicalPath::new(".secret").unwrap());
    assert_eq!(explained.decision, WriteDecision::Deny);
    assert_eq!(explained.matches[0].effect, WriteRuleEffect::Protect);
    assert_eq!(
        explained
            .matches
            .iter()
            .filter(|m| m.effect == WriteRuleEffect::Allow)
            .count(),
        2
    );
}

#[test]
fn write_default_allow_and_non_utf8_fail_closed() {
    let policy = write_program(&[], &[], &[("blocked.txt", ScopeKind::Workload, true)]);
    assert_eq!(decide_write(&policy, "other.txt"), WriteDecision::Allow);

    let path = LexicalPath::from_bytes(b"\xff").unwrap();
    let result = policy.decide_write(&path);
    assert_eq!(result.decision, WriteDecision::Deny);
    assert!(result.fail_closed_non_utf8);
}
