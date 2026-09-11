# STATUS — microsandbox mount path policy feature

> **STATUS: CURRENT (2026-08-04, HEAD `2eaddae1`; feat branch rebased onto fork main `b43d7522`; compile gate green, runtime tests blocked on libcap-ng in this container)**
> See-also: [NEXT-SESSION.md](NEXT-SESSION.md) · [DEVELOPMENT.md](DEVELOPMENT.md) · [AGENTS.md](AGENTS.md)

This file is the self-contained status report for the
`feat/passthrough-mount-path-policy` branch in the microsandbox fork
(`github.com/rybskiworks/microsandbox`; upstream
`github.com/superradcompany/microsandbox`). It is the mount path policy
feature (spec 22 consumer surface) that workestrate consumes via its SDK.

---

## Branch state (2026-08-04)

- **Branch:** `feat/passthrough-mount-path-policy`
- **HEAD:** `2eaddae1` (after rebase onto fork main)
- **Base:** `b43d7522` — fork main, "fix(filesystem): allow staged agentd in
  offline builds (#1)". This is the rewritten agentd fix merged as PR #1. The
  original superseded agentd fix (`d9b4d12e`) has been **dropped** from the feat
  branch history via rebase.
- **Commits:** 32 mount-masking commits on top of `b43d7522`.
- **Backup:** `backup/feat-pre-rebase-onto-main` (`ccceb48a`) preserves the
  pre-rebase state.

### Rebase note

A trial rebase previously existed at `/tmp/msb-rebase-trial` on branch
`trial/rebase-onto-6d7b52ea`. It rebased the 32 commits onto `6d7b52ea` (a
merge commit on the fork's `fix/filesystem-agentd-path-override` branch),
which was the **wrong base**. The real rebase (this branch) corrected the
target to fork main `b43d7522`. The trial and the real rebase agree on all 32
commit subjects (only SHAs and base differ). `/tmp` is ephemeral — the trial
may not survive a container restart.

---

## Feature: dynamic mount path policy in PassthroughFs

A bind mount can carry a compiled **mount path policy** that hides or protects
host paths from the guest without changing the underlying directory. Use the
`policy=<path>` mount token to point at a policy program JSON file resolved
beneath the sandbox's approved runtime state directory.

### What's implemented

- **Mount path-policy evaluation core** —
  `crates/filesystem/lib/backends/passthroughfs/unix/mount_policy/`
  (modules: `mod.rs`, `lexical.rs`, `pattern.rs`, `program.rs`, `rule.rs`).
  Pure compiled policy types and evaluator.
- **Masking semantics** — lookup → `ENOENT`, readdir → omit, create/rename →
  `EACCES`, traversal-only, write-deny, protect.
- **Tag store + bounded cascade removal** — tags evicted on identical-identity
  rename exchange; descendant tags evicted during masked cascade removal; real
  parent inode used in cascade tag check; fd-relative operations in
  `cascade_remove`.
- **Write ACL** — `writes.deny` enforced on mutation and writes, and on
  `fallocate` / `copy_file_range` / `ftruncate` / `setattr`.
- **Protect** — the `protect` effect prevents guest mutation of masked paths.
- **Fail-closed loader** — approved state dir, `O_NOFOLLOW`, parse-once;
  malformed / unknown-field / unsupported-version refuse to start. Typed error
  for `load_mount_policy`.
- **Threading** — mount path policy threaded to passthrough via
  types/sdk/runtime; all `VolumeMount::Bind` construction sites updated for
  `mount_policy`.
- **Docs** — "Mount path policy" section in `docs/sandboxes/volumes.mdx`
  (`policy=<path>` token, masking semantics, fail-closed loader, `version:1`
  JSON program format, platform support). Changelog entry for the week of
  July 31, 2026.

### Platform support

Linux-first. On macOS the `policy=` token and the `mount_policy` builder field
are accepted for API compatibility, but enforcement is a no-op (paths are
visible). On Windows the field is not supported.

---

## Validation state

- **Unit tests exist:** `crates/filesystem/lib/backends/passthroughfs/unix/tests/test_mount_policy.rs`
  and `test_mutation_policy.rs` (plus the broader passthroughfs test suite).
- **Compile gate:** `cargo check --workspace --all-targets` is **GREEN** on the
  rebased tree (43s; rustc 1.97.1 via the nix store toolchain). Only a benign
  future-incompat warning about transitive dep `proc-macro-error2 v2.0.1` (not
  our code).
- **Runtime tests BLOCKED in this container:** tests may not link due to
  **libcap-ng** (the link gate is not satisfied here). Report honestly — the
  runtime test suite has not been run in this environment.
- **HOST-KVM end-to-end:** PENDING (requires the host; depends on workestrate's
  SDK switch).

---

## Integration state

- Based on fork main (`b43d7522`) with the rewritten agentd fix. The original
  superseded agentd fix (`d9b4d12e`) is dropped from the feat branch.
- **Pending:** commit signing (host-side, requires the operator's signing key),
  squash decision, and the upstream PR post (the agentd fix PR to
  `superradcompany/microsandbox`, followed by the mount path policy feature PR).

---

## Relationship to workestrate

The mount path policy feature is the spec 22 consumer surface that workestrate
consumes via its SDK. workestrate's HOST-KVM end-to-end validation depends on
workestrate's SDK switch to consume this feature.
