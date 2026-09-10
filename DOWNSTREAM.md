# DOWNSTREAM.md — rybskiworks/microsandbox fork

This is a downstream fork of [superradcompany/microsandbox](https://github.com/superradcompany/microsandbox),
maintained as the microVM substrate for workestrate.

## Upstream base

- Upstream 0.6.18 at `fa3e43902e9bc49e1d85cc0a7298e13fe2374026` is merged
  into this branch with its ancestry preserved.

## Downstream delta

- Mount-path policy (hierarchical allow/deny evaluator; see MOUNT-POLICY.md).
- SingleFileFs honor fix.
- Nested virtualization as a first-class, default-off spec option
  (`nested_virt` / `--nested-virt`).
- agentd offline-build fix (staged-agentd path override for nix builds).
- Pinned fork runtime and source-built firmware with shared Nix tooling inputs.
- A credential-free KVM lifecycle smoke app (`nix run .#test-runtime`).

The terminating SSH broker integration is incomplete. In particular, the
existing TCP forwarding path chooses diversion after exposing upstream bytes;
passing its current unit tests does not establish working stock-client SSH
custody. Treat this as an implementation gap, not an operational guarantee.

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

## Nix state model

The nix build keeps three state layers strictly separate: pure build inputs
(flake.lock-pinned), ephemeral build/check state (`$TMPDIR/.microsandbox`),
and user-owned runtime state (generation-keyed `$HOME/.microsandbox`). Full
model, homeless-shelter rationale, and the fail-closed nix contract:
`nix/README.md`.

## Licensing

- Upstream code remains Apache-2.0; this fork preserves that license (LICENSE
  is unmodified).
- The Nix runtime links libkrunfw, which embeds a GPL-2.0-licensed Linux kernel.
  Its source is the `rybskiworks/libkrunfw` revision selected by the `libkrunfw`
  input in `flake.lock`; that flake pins the kernel tarball and applies its
  in-tree patches. See `nix/README.md` and `nix/packages/microsandbox.nix`.
  The upstream `vendor/libkrunfw` submodule and prebuilt release downloads are
  separate input paths, not the firmware provenance of this Nix package.
