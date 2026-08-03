use super::mount_policy::{
    CaseSensitivity, CompiledRuleSet, Decision, LexicalPath, MountPolicyProgram, PathPolicyRule,
    Pattern, RuleEffect, RuleOrigin, ScopeKind,
};
use super::*;
use std::path::PathBuf;
use std::sync::Arc;

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
