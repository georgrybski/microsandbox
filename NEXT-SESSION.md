# NEXT-SESSION — microsandbox fork nix packaging + nested-virt handover (2026-09-06)

> **STATUS: HANDOFF (2026-09-06, fork `feat/nested-virt-port @8f6c110f` clean; workestrate `migration/tool-model @dff8824` clean; personal `main @e1d4f39` ahead 1 unpushed; 8 fork commits (7 session + 1 handover) + 1 personal (e1d4f39) = 9 total UNSIGNED — host re-sign required; gates green except unit DEFERRED + pure-check RED BY DESIGN + deny-full RED; nested boot proof deferred to dblab42)**
> See-also: `/home/node/Development/agent-workbench/handovers/evidence-msb-deny-baseline.log` (408965 bytes, 7141 lines, 2026-09-06)

This file is the self-contained handoff for the next session working the
microsandbox fork (`feat/nested-virt-port`), the workestrate
`migration/tool-model` flip, and prime nested-virt activation. It assumes no
prior conversation. Paste this file as the next-session prompt. Verified
in-container this session: SHAs via git log, file contents, deny log lines,
prime toml, stale-string sites. Claimed — host must re-verify per §5a:
clippy GREEN execution, disk numbers, upstream CI status, .so symbol
evidence, 71265190/21cb6dce config =y, origin push state. Execute the host
steps in §5 first — do not treat claimed items as verified.

Container this was written in: NO `/dev/kvm`, no gh auth/ssh (push = host
only), disk 9.0G free (98% used overlay; `/nix/store` ~15G; no gc allowed),
`~/.workestrate` is a RO mirror — the canonical writable config repo is the
nested git repo at `config-repos/personal` (dev-home `.gitignore` ignores
`/config-repos`; respect the nested-repo boundary).

---

## 1. Status header (2026-09-06)

- Fork repo: `/home/node/Development/agent-workbench/forks/microsandbox/repo`,
  branch `feat/nested-virt-port`, HEAD `8f6c110f` (post-handover;
  pre-handover tip was `9fc82059`), clean.
- 7 UNSIGNED session commits on top of `8e53de7e` (all `%G? = N`):
  `f9aa9d91`, `e17326a0`, `9c421a7e`, `cf0358ce`, `5b600ac`, `a34153a`,
  `9fc8205`, plus this handover commit `8f6c110f` (UNSIGNED,
  `--no-gpg-sign` — no host key in container). Total re-sign debt in fork
  after this commit: **8**. Plus personal `e1d4f39` = **9** total unsigned.
- Workestrate repo: `/home/node/Development/agent-workbench/workestrate`,
  `migration/tool-model` clean @ `dff8824` (== `origin/migration/tool-model`
  == `origin/HEAD` per container refs; **host must confirm push state** —
  container has no auth).
- Personal config repo (NESTED repo at
  `/home/node/Development/agent-workbench/workestrate-dev-home/config-repos/personal`;
  dev-home `.gitignore` ignores `/config-repos`): `main @ e1d4f39`
  `"feat(config): require nested virtualization for prime"`, UNSIGNED (N),
  ahead 1 of `origin/main (1c30089)`, unpushed.
- Next work: §5 host push + re-sign + deferred gates + nested boot proof on
  dblab42, then §6 `integration/fork-flake` flip. Ordering: prime activation
  FIRST (done), flip SECOND (flip adds nothing runtime; bisect-clean).

---

## 2. What landed (per repo, SHAs exact)

Fork `feat/nested-virt-port` (base `8e53de7e`), oldest → newest:

- `f9aa9d91` — deny.toml parse fix (unglue comment from
  confidence-threshold).
- `e17326a0` — flake + `nix/packages/{agentd,microsandbox}`, follows to
  `nix-tooling@18f8b85`, `packages/checks/devshell`.
- `9c421a7e` — CODEOWNERS `@georgrybski` + PR template.
- `cf0358ce` — `DOWNSTREAM.md`.
- `5b600ac` — gitlink comment `21cb6dce` (full
  `21cb6dce19a615f63e41ecb913334d18560c1364`, correct
  `vendor/libkrunfw` pointer).
- `a34153a` — sandbox-safe `MSB_HOME` in `stageAgentd` (check-gate fix).
- `9fc8205` (`9fc82059` full, pre-handover tip) — `--impure` doc (devenv pure-eval
  requirement documented at the devenv import).

Workestrate `migration/tool-model @ dff8824`: clean, no new commits this
session. Holds the pre-flip integration analysis (§4/§6) and the prime
activation consumer.

Personal `main @ e1d4f39`: one commit ahead of `origin/main (1c30089)` —
`"feat(config): require nested virtualization for prime"`. UNSIGNED,
unpushed. This IS the prime-activation step (flip adds nothing runtime).

---

## 3. Gate status

| Gate | Verdict | Notes |
|---|---|---|
| `nix build .#microsandbox` / `.#agentd` (fork) | GREEN | Layout verified |
| `checks.fmt` (fork) | GREEN | — |
| `checks.deny` bans+sources (fork) | GREEN | Bans + sources only |
| `checks.clippy` (fork) | GREEN | Post-`a34153a`, incl. musl agentd |
| `checks.unit` (fork) | DEFERRED | Disk <12G free (9.0G); same `stageAgentd` path as clippy, unproven — run on host: `nix build .#checks.x86_64-linux.unit --impure -L` with >=12G |
| Pure `nix flake check` (fork) | RED BY DESIGN | `devenv-root` pure-eval failure; use `--impure` — documented at the devenv import in `9fc8205` |
| Devshell fmt / clippy | GREEN | — |
| Devshell `cargo test --workspace` | 3049 pass / 0 fail / 138 ignored | Pre-cleanup run; NOT re-confirmed post-cleanup (disk) |
| `deny` FULL baseline (licenses+advisories+bans+sources) | RED | Licenses: 0BSD x2 via smoltcp/managed, Apache-2.0 WITH LLVM-exception x2 via target-lexicon/winx; Advisories: h2 RUSTSEC-2026-0258, pyo3 x2 RUSTSEC-2026-0176/0177, rsa RUSTSEC-2023-0071 Marvin no-safe-upgrade, proc-macro-error2 unmaintained RUSTSEC-2026-0173; bans/sources ok; 5 yanked warnings. Full log: `/home/node/Development/agent-workbench/handovers/evidence-msb-deny-baseline.log` (408965 B, 7141 lines, 2026-09-06; confirm: `wc -l` expect 7141 + `stat -c%s` expect 408965) |

Workestrate-side deferred (host, §5c; workestrate subcommands run inside
`just shell`): `just shell -c 'cargo test -p workestrate nested'`, `just
shell -c 'workestrate validate-config'`, `just shell -c 'workestrate workload
plan prime'` (expect KVM-less warn + continue), `just shell -c 'workestrate
schemas update --check'`, the two negative parse controls (verbatim in §5c).

---

## 4. Verified findings

- **Firmware verdict — "nested inert until firmware CONFIG_KVM" is STALE.**
  Upstream enabled `CONFIG_KVM=y` (intel+amd) 2026-05-12 (`71265190`,
  `github.com/superradcompany/libkrunfw/commit/71265190` — TODO-host:
  confirm repo path); pinned submodule rev `21cb6dce` (full
  `21cb6dce19a615f63e41ecb913334d18560c1364`) has `=y` at
  `config-libkrunfw_x86_64` (`grep CONFIG_KVM` expect `=y` x3); shipped
  Branch A `.so` (v0.6.8 tar, kernel 6.12.98) contains KVM host symbols
  (`kvm_intel.nested`, `kvm_amd.nested`, `vmx_*`; host re-verify: `nm -D
  result/lib/libkrunfw.so.5.6.1 | grep -c kvm_` or `strings` fallback —
  TODO-host if artifact absent). Old `# CONFIG_KVM is not set` exists only
  at tag `v5.2.1`. Firmware believed READY — but symbol-presence !=
  boot-proof; guest boot proof (§5d) still required. Stale-string sites to
  fix (flip or follow-up, NOT ad-hoc upstream-owned edits): `doctor.rs`
  `PIN_NOTE`, `nested.rs` header, `scripts/kvm-tests.sh` SKIP note, ADR
  0036 D6/status.
- **138 ignored, nothing hidden:** 81 `#[msb_test]` KVM-gated (31 lifecycle +
  38 network + 12 cli) + 4 e2fsprogs resizer + 53 doctest fences. Upstream
  default CI skips the same; upstream self-hosted KVM lane covers ~65/81
  (not ssh 4, not cli 12, resizer manual-only).
- **Upstream `superradcompany/microsandbox`:** push-CI green (Check x3, HEAD
  `e25cae3` 2026-09-04); scheduled Fuzz failing 2x on HEAD; v0.6.17 release
  failed only at npm-publish (GitHub binaries OK); no open test-failure
  issues.
- **agentd structuring FULLY migrated to fork flake** — flip is mechanical.
  Images: no layer impact (msb is host tooling; nix2container dead;
  `dockerTools.buildLayeredImage` live). Migrations/state: NO coupling (new
  `MSB_PATH` hash → new generation key → converge whitelist by design;
  rollback preserved).
- **Flip shape (detail in §6):** delete workestrate's 3 duplicated derivations
  (`agentd.nix`, `microsandbox.nix`, `microsandbox-filesystem-patched.nix`) +
  consume `inputs.microsandbox-fork.packages.${system}.{microsandbox,agentd}`
  + replace filesystem-patched with `inputs.microsandbox-fork.outPath`
  passthrough (DROP `sourceRoot="source"` everywhere);
  `check-msb-versions.sh` R1 (original.rev requirement) + R2 (40-hex url
  regex) BREAK on branch-tracking `flake=true` — rewrite in the SAME commit
  as the flip; `ci.yml` vendor steps are flip-proof (locked.rev reader).

---

## 5. Immediate host steps (in order; exact commands)

### (a) Push (host only — container has no gh auth/ssh) + confirm state

```bash
# fork (host):
cd /home/node/Development/agent-workbench/forks/microsandbox/repo \
  && git status --short --branch \
  && git log --oneline -9 \
  && git push origin feat/nested-virt-port
# personal config repo (host; nested repo — run INSIDE config-repos/personal):
cd /home/node/Development/agent-workbench/workestrate-dev-home/config-repos/personal \
  && git status --short --branch \
  && git log --oneline -3 \
  && git push origin main
# workestrate push-state confirm (host; container refs say 0/0 — verify):
cd /home/node/Development/agent-workbench/workestrate \
  && git status --short --branch \
  && git rev-parse HEAD origin/migration/tool-model origin/HEAD \
  && git log origin/migration/tool-model..HEAD --oneline \
  && git rev-list --left-right --count origin/migration/tool-model...HEAD
# expect: `git rev-parse HEAD origin/migration/tool-model` equal;
# `git rev-list --left-right --count origin/migration/tool-model...HEAD` → `0 0`.
```

### (b) Re-sign (host key; container commits are `--no-gpg-sign` by necessity)

```bash
# fork (host): backup BEFORE any rewrite, then re-sign 8e53de7e..HEAD
# (7 session commits + this handover commit):
cd /home/node/Development/agent-workbench/forks/microsandbox/repo \
  && git branch backup/feat-nested-virt-pre-resign HEAD \
  && git rebase --exec 'git commit --amend --no-edit -S' 8e53de7e..HEAD
# personal (host): backup then re-sign e1d4f39:
cd /home/node/Development/agent-workbench/workestrate-dev-home/config-repos/personal \
  && git branch backup/main-pre-resign HEAD \
  && git rebase --exec 'git commit --amend --no-edit -S' 1c30089..HEAD
```

If a re-sign rewrite is needed later (e.g. stale-string fix), take a new
`backup/<branch>-pre-<reason>` ref at the pre-rewrite tip first (rebase may
need `--no-verify` if hooks block the rewrite — be aware, do not bake it
in). Re-sign rewrite MOVES the tip → `flake.lock`/pins referencing the old
tip rev must be relocked/re-pointed AFTER re-sign (this is why re-sign
precedes the integration branch). Do NOT rewrite after the integration
branch is cut without coordinating the pin.

### (c) Deferred validations (host, disk >=12G)

```bash
# fork unit gate (host, needs >=12G free):
cd /home/node/Development/agent-workbench/forks/microsandbox/repo \
  && nix build .#checks.x86_64-linux.unit --impure -L
# workestrate nested + config gates (host; workestrate subcommands run inside `just shell`):
cd /home/node/Development/agent-workbench/workestrate \
  && just shell -c 'cargo test -p workestrate nested' \
  && just shell -c 'workestrate validate-config' \
  && just shell -c 'workestrate workload plan prime'
# expect: `workestrate workload plan prime` warns "requires nested
# virtualization … plan continues; up will refuse — see ADR 0036 §4"
# (KVM-less host continues plan; no /dev/kvm on plain host)
```

```bash
cd /home/node/Development/agent-workbench/workestrate \
  && just shell -c 'workestrate schemas update --check'
# negative parse controls (verbatim; discard copies afterwards):
cp /home/node/Development/agent-workbench/workestrate-dev-home/config-repos/personal/workestrate/workloads/prime/workload.toml /tmp/prime-neg-variant.toml
# edit /tmp/prime-neg-variant.toml: set `nested = "on"` under [virtualization]:
sed -i 's/nested = "require"/nested = "on"/' /tmp/prime-neg-variant.toml
cd /home/node/Development/agent-workbench/workestrate \
  && just shell -c 'workestrate validate-config --config /tmp/prime-neg-variant.toml'
# expect: unknown-variant parse error for `nested = "on"`
rm /tmp/prime-neg-variant.toml
cp /home/node/Development/agent-workbench/workestrate-dev-home/config-repos/personal/workestrate/workloads/prime/workload.toml /tmp/prime-neg-unknown-field.toml
# edit /tmp/prime-neg-unknown-field.toml: add `frobnicate = true` under [virtualization]:
sed -i '/^\[virtualization\]/a frobnicate = true' /tmp/prime-neg-unknown-field.toml
cd /home/node/Development/agent-workbench/workestrate \
  && just shell -c 'workestrate validate-config --config /tmp/prime-neg-unknown-field.toml'
# expect: unknown-field error (deny_unknown_fields) for `frobnicate`
rm /tmp/prime-neg-unknown-field.toml
```

### (d) Nested boot proof on dblab42 (firmware believed READY — expect pass)

```bash
# host gate (dblab42 host, NOT guest):
ls -l /dev/kvm
cat /sys/module/kvm_intel/parameters/nested 2>/dev/null || cat /sys/module/kvm_amd/parameters/nested
# expect: host /dev/kvm present, nested=Y (N/y)
# bring up prime (host; workestrate subcommands run inside `just shell`):
cd /home/node/Development/agent-workbench/workestrate \
  && just shell -c 'workestrate workload up prime'
# guest probe INSIDE the guest after up (expect /dev/kvm in guest + API version 12):
cd /home/node/Development/agent-workbench/workestrate \
  && just shell -c 'workestrate workload exec prime -- ls -l /dev/kvm'
# and (in-guest KVM_GET_API_VERSION=12 assertion via NESTED_GUEST_TEST lane):
NESTED_GUEST_TEST=1 bash scripts/kvm-tests.sh
# (script reads `${NESTED_GUEST_TEST:-0}` at kvm-tests.sh:161; asserts
# KVM_GET_API_VERSION=12 in-guest; guest-exec equivalent also acceptable)
```

If guest `/dev/kvm` is absent despite `CONFIG_KVM=y` at `21cb6dce` (full
`21cb6dce19a615f63e41ecb913334d18560c1364`) → Branch B kernel-rebuild spike
(scope, T6): populate `vendor/libkrunfw` submodule @ `21cb6dce` (full
`21cb6dce19a615f63e41ecb913334d18560c1364`), `make`, add
`nix/packages/libkrunfw.nix`, swap the `fetchurl` for the built firmware. Do
NOT start Branch B on a KVM-less host — it needs dblab42.

---

## 6. Integration branch plan (next major work: the flip)

Cut `integration/fork-flake` from pushed `migration/tool-model` (after §5a+§5b
— re-sign BEFORE cutting so the pin does not move twice).

1. **Input:** add `inputs.microsandbox-fork` to workestrate flake. DECISION
   (§7): branch-tracking `flake=true` (recommend) vs rev-pinned. Relock on
   host (`nix flake lock`); container cannot (disk/auth).
2. **Outputs rewire:** consume
   `inputs.microsandbox-fork.packages.${system}.{microsandbox,agentd}`.
3. **Delete the 3 duplicated derivations** in workestrate: `agentd.nix`,
   `microsandbox.nix`, `microsandbox-filesystem-patched.nix`.
4. **Filesystem passthrough:** replace filesystem-patched derivation with
   `inputs.microsandbox-fork.outPath` passthrough; DROP
   `sourceRoot="source"` everywhere it appears.
5. **Same-commit script rewrite:** `check-msb-versions.sh` R1
   (`original.rev` requirement) + R2 (40-hex url regex) BREAK on
   branch-tracking `flake=true` — rewrite in the SAME commit as the flip
   (never land the flip with a red version gate).
6. **Same-edit pin sites:** `versions.rs` `FORK_REV_PIN` + `doctor.rs`
   `PIN_NOTE` (also fixes the stale-string site) + pin tests — one edit.
7. **`ci.yml`:** unchanged except the rev value (vendor steps use the
   locked.rev reader — flip-proof).

Validation sequence (host; cwd annotated — fork repo vs workestrate repo):
(fork repo) `nix flake check --impure` → (fork repo) `nix build
.#microsandbox` + (workestrate repo) `nix build .#workestrate` + smoke →
(workestrate repo) `just verify` → (workestrate repo) `just shell -c 'cargo
test -p workestrate nested'` → (workestrate repo) image e2e (non-ignored) →
(workestrate repo) KVM lane + generation-converge dry-run → (workestrate
repo) `diff-closure` old-vs-new (expect only msb/agentd subtree deltas; no
image-layer deltas).

---

## 7. Decisions needed (recommendations)

- **Flip ref strategy:** branch-tracking (`flake=true`) vs rev-pinned.
  RECOMMEND branch-tracking + same-commit `check-msb-versions.sh` rewrite
  (tracks fork during integration; script must change anyway).
- **Re-sign timing:** RECOMMEND re-sign (§5b) BEFORE cutting
  `integration/fork-flake` (avoid double pin bump).
- **`outPath` passthrough:** simple vs filtered. RECOMMEND simple, measure;
  filter only if closure proves bloat.
- **`packages.microsandbox` alias:** RECOMMEND keep (downstream consumers
  expect it).
- **`PIN_NOTE`:** literal update vs generalize. RECOMMEND literal now
  (unblocks flip review), generalize later.
- **Deny triage (full baseline RED, §3):** allow 0BSD (x2) + LLVM-exception
  (x2) with justification vs replace crates; h2/pyo3 `cargo update`; rsa
  no-fix → ignore-with-justification or replace; proc-macro-error2
  RUSTSEC-2026-0173 replace/ignore; yanked warnings batch-update. No
  decision this session — bans/sources gate stays green regardless.

---

## 8. Do-not list

- NO `nix gc` / `/nix/store` deletes (disk pressure is managed by host, not
  by store surgery from this workstream).
- NO edits to upstream-owned files (stale strings in §4 are fixed via the
  flip/same-edit sites, not ad-hoc).
- UNSIGNED commits: container MUST use `--no-gpg-sign` and flag it in the
  body; host MUST re-sign (§5b). Never fake `%G?` status.
- Disk <3G free → ABORT gates, report, do not retry (unit gate needs >=12G;
  current 9.0G already defers it).
- `~/.workestrate` is a RO mirror — do not write there; config edits go in
  `config-repos/personal` (nested-repo boundary: commit inside the nested
  repo, never in the wrapping dev-home repo).
- Pure `nix flake check` (no `--impure`) is RED BY DESIGN here — always use
  `--impure` (devenv-root); do not "fix" by downgrading devenv.
- Do not push from the container (no auth/ssh); do not cut the integration
  branch before §5a+§5b.

---

## 9. Open questions / uncertainties

- Tar provenance: shipped Branch A `.so` symbol-presence proves KVM host
  symbols in the artifact, NOT which source commit built the tar (commit
  unproven).
- Symbol-presence != boot-proof: `CONFIG_KVM=y` + symbols strongly imply
  nested-capable firmware, but only the dblab42 guest boot (§5d) proves
  nested "works".
- Unit gate unproven post-`a34153a` (same `stageAgentd` path passed clippy,
  but `checks.unit` never ran — disk).
- Devshell `cargo test --workspace` 3049/0/138 is the pre-cleanup run —
  counts NOT re-confirmed post-cleanup (disk).
- Workestrate container refs claim `dff8824 == origin/migration/tool-model ==
  origin/HEAD` (0/0) — host must confirm (§5a); if the host shows ahead,
  push before cutting integration.
- The two negative parse controls are captured verbatim in §5c (unknown-variant `nested = "on"`, unknown-field `frobnicate`; discard /tmp copies) — run as written on host.
