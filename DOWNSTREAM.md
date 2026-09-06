# DOWNSTREAM.md — rybskiworks/microsandbox fork

This is a downstream fork of [superradcompany/microsandbox](https://github.com/superradcompany/microsandbox),
maintained as the microVM substrate for workestrate.

## Upstream base

- Merge base: `d32705d9`, at upstream v0.6.16 (`e36792d`).
- As of 2026-09-06, `upstream/main` has since advanced ~11 commits to
  `e25cae31` (per local refs; not yet merged here).

## Downstream delta

- Mount-path policy (hierarchical allow/deny evaluator; see MOUNT-POLICY.md).
- SingleFileFs honor fix.
- Nested virtualization as a first-class, default-off spec option
  (`nested_virt` / `--nested-virt`).
- agentd offline-build fix (staged-agentd path override for nix builds).

## CI model: two contracts

- **Upstream CI** (unchanged upstream workflows): the "still microsandbox"
  oracle. It must keep passing so the fork remains a viable upstream citizen.
- **Downstream nix CI** (`flake.nix`, `nix/`): the "valid workestrate
  substrate" contract. `nix build .#microsandbox` / `.#agentd` must succeed;
  `nix flake check` gates fmt and cargo-deny (bans/sources), with heavier
  clippy/unit checks defined for hosts that can afford them. Pure eval of the
  devshell needs the `devenv-root` override — see the input comment in
  flake.nix.

Upstream-bound changes must not contain downstream-owned files (flake.nix,
nix/, downstream workflows, this file).

## Licensing

- Upstream code remains Apache-2.0; this fork preserves that license (LICENSE
  is unmodified).
- The built msb package redistributes libkrunfw, which embeds a
  GPL-2.0-licensed Linux kernel image. Corresponding source per GPL-2.0 §3:
  https://github.com/superradcompany/libkrunfw (branch krunfw), pinned as the
  `vendor/libkrunfw` submodule gitlink (`c5503d82`). See the provenance
  comment block in `nix/packages/microsandbox.nix`.
