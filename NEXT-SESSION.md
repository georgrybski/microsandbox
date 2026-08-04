# NEXT-SESSION — microsandbox mount path policy resumption

> **STATUS: HANDOFF (2026-08-04, HEAD `2eaddae1`; rebase complete, compile green, runtime + signing + PR pending)**
> See-also: [STATUS.md](STATUS.md) · [DEVELOPMENT.md](DEVELOPMENT.md)

This file is the self-contained handoff for the next session working the
`feat/passthrough-mount-path-policy` branch in the microsandbox fork. It
assumes no prior conversation. State details are in `STATUS.md`; this doc
carries what remains.

---

## What remains (ordered)

1. **Commit signing (host).** The 32 feat-branch commits are unsigned. The
   repo's `AGENTS.md` requires `git commit -S`. The operator must re-sign the
   commits on the host with their signing key before the upstream PR. (A
   `backup/feat-pre-rebase-onto-main` ref at `ccceb48a` preserves the
   pre-rebase state if a re-sign requires a rewrite.)

2. **libcap-ng runtime test run.** The unit tests exist
   (`test_mount_policy.rs`, `test_mutation_policy.rs`, and the broader
   passthroughfs suite) but the runtime/link tests are blocked in this
   container on **libcap-ng** (the link gate is not satisfied here). Run the
   full test suite (`cargo test --workspace`) in an environment where
   libcap-ng links — the host, or a container with libcap-ng dev headers.

3. **Upstream PR post.** Post the agentd fix PR to
   `superradcompany/microsandbox` (the rewritten fix, currently merged to the
   fork as PR #1 / `b43d7522`). The mount path policy feature PR follows once
   the commits are signed.

4. **HOST-KVM end-to-end via workestrate.** Depends on workestrate's SDK
   switch to consume the mount path policy feature. This is the end-to-end
   validation gate for the feature.

5. **Flake packaging track (spec 23).** Deferred. Not part of this feature
   branch.

---

## Pre-flight for the next session

- Verify the branch is still at `2eaddae1` on `b43d7522`:
  `git log --oneline sibling/main..HEAD` should list 32 commits.
- The trial at `/tmp/msb-rebase-trial` is ephemeral and may be gone after a
  container restart; the real rebase on this branch is the source of truth.
- Compile gate re-run: `cargo check --workspace --all-targets` (green as of
  2026-08-04; rustc 1.97.1).
