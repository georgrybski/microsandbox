# nix/ — downstream packaging and the msb state model

Downstream-owned. `docs/` is upstream-owned — nix behavior is documented here,
never there. Fork delta and the two-contract CI model: `DOWNSTREAM.md`.

## Three-layer msb state model

| # | Layer | Purity | Location | Lifetime |
|---|-------|--------|----------|----------|
| 1 | Build inputs | pure | nix store | pinned per rev via `flake.lock` |
| 2 | Build/check state | ephemeral | `$TMPDIR/.microsandbox` | per-derivation scratch, deleted after |
| 3 | Runtime state | impure by design, user-owned | `$HOME/.microsandbox` generations | persistent, converged by the consumer |

Rule: state flows down (1 → 2 → 3) only. Build/check state must NEVER touch
`$HOME` or the user's real state.

### Layer 1 — build inputs (pure)

Everything byte-pinned via `flake.lock`:

| Input | Derivation | Pin |
|-------|------------|-----|
| `agentd` | `nix/packages/agentd.nix` — musl static via `pkgsStatic`, built from this flake's locked fork source (`src = self`) | flake rev |
| `libkrunfw` (Branch A, current) | `nix/packages/microsandbox.nix:57-60` — `fetchurl` + `sha256` of the upstream v0.6.8 release tarball, `libkrunfw.so*` only | SRI hash in-tree |
| `libkrunfw` (Branch B, future) | `nix/packages/microsandbox.nix:45-52` — `fetchGit` derivation built from `vendor/libkrunfw`; NOT implemented | submodule gitlink |
| toolchain | fenix `stable` via the shared nix-tooling pin (`flake.nix:9-18,75`) | `flake.lock` |

### Layer 2 — build/check state (ephemeral)

`MSB_HOME="$TMPDIR/.microsandbox"`, set in the shared `stageAgentd` snippet
(`flake.nix:105-116`) used as `preBuild` by `checks.clippy` and `checks.unit`
only. `$TMPDIR` is the nix sandbox's per-derivation scratch — writable during
the build, deleted after. The snippet also stages `build/agentd` and exports
`MSB_AGENTD_PATH` (commit `a34153a`).

### Layer 3 — runtime state (consumer-owned)

Runtime state belongs to the consumer (workestrate), not this flake:
`$HOME/.microsandbox/current` → `generations/<hash12>/`, keyed by the
`MSB_PATH` store-path hash. The converge script migrates the whitelist (`db`,
`sandboxes`, `volumes`, `snapshots`, `secrets`, `tls`, `ssh`, `mount-policy`,
`config.json`) between generations; delivery-mechanism changes (e.g. consuming
this fork flake) create a NEW generation key by design — never corrupts state,
rollback preserved. Reference: workestrate ADR 0037,
`scripts/msb-generation-converge.sh`,
`control/agentctl/src/microsandbox/generation.rs`.

## The homeless shelter

Nix sandboxed builds set `HOME=/homeless-shelter` — a path that deliberately
does not exist and cannot be created. It is a canary: any build writing to
`$HOME` dies loudly, exposing hidden environment dependence. The name is nix
stdenv's own, deliberately absurd: the build is "homeless" (no home dir), and
the "-shelter" is the joke — the path exists precisely to prevent the build
from settling anywhere. Failures read `Permission denied: /homeless-shelter`,
so logs are self-explanatory and greppable. Never "fix" it by creating the
directory or overriding `HOME` globally — redirect the app's state dir instead
(`MSB_HOME`), which is exactly what `stageAgentd` now does
(`flake.nix:105-116`, commit `a34153a`). The writer was `sdk/rust/build.rs:72-73`
(`create_dir_all` on `{bin,lib}/` under `resolve_home()` from
`crates/utils/lib/lib.rs:178`).

## Fail-closed contract for nix builds (contract; implementation queued)

`crates/filesystem/build.rs` (`build_agentd`, `prebuilt` feature) resolves the
guest agentd in this order: `build/agentd` → `MSB_AGENTD_PATH` → cached
`OUT_DIR` copy → GitHub release download (`agentd_download_url(PREBUILT_VERSION)`,
`PREBUILT_VERSION = CARGO_PKG_VERSION`, i.e. the v0.6.16 asset). The download
leg is a build-time network fetch — forbidden under the nix contract. Rule:
nix check `preBuild` must assert `MSB_AGENTD_PATH` is set (fail-closed) so the
fallback can never silently fire; upstream keeps the fallback for its no-nix
`cargo build` contract (Contract A) — the fork's nix contract (Contract B)
refuses it. Same pattern as the workestrate `ci.yml` e2e-nix fail-closed env
asserts. This section documents the CONTRACT ONLY — implementation is a queued
follow-up, deliberately NOT implemented here.

## Devshell state isolation (proposal; queued)

Devshell experimentation should never write the user's real
`~/.microsandbox/current`. Proposal (not implemented): a dev-scoped `MSB_HOME`
(e.g. `$PWD/.devenv/msb-home`, gitignored) for devshell use. Today the devshell
`enterShell` (`flake.nix:282-287`) deliberately exports only `MSB_AGENTD_PATH`
— no second runtime home — so this proposal extends that posture.
