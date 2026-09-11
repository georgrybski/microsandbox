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

Flake inputs are pinned via `flake.lock`; Cargo Git sources also have
fixed-output hashes in the package definitions:

| Input | Derivation | Pin |
|-------|------------|-----|
| `agentd` | `nix/packages/agentd.nix` — musl static via `pkgsStatic`, built from the filtered Rust workspace source | flake rev |
| `brokerd` | `nix/packages/brokerd.nix` — ordinary service binary using the same Fenix Rust toolchain as the host CLI; its Nix runtime closure belongs in the guest image | flake rev |
| Cargo dependencies | `nix/cargo-lock.nix` — shared by packages and Cargo checks; fixed-output hashes cover the locked libkrun and rust-vmm checkouts, including their pinned submodules | `Cargo.lock` and `outputHashes` |
| `libkrunfw` | The fork's source-built `libkrunfw` flake input; its tooling, nixpkgs and flake-parts follow this flake's shared inputs | immutable revision in `flake.lock` |
| toolchain | fenix `stable` via the shared nix-tooling pin (`flake.nix:9-18,75`) | `flake.lock` |

`nix/packages/cli.nix` compiles the CLI with the matching static agent embedded,
without a firmware dependency. `nix/packages/microsandbox.nix` assembles that
CLI, the same guest agent and the pinned firmware into the existing runtime
layout. A firmware-only change therefore does not enter the CLI derivation's
inputs. No upstream prebuilt runtime or release firmware archive is selected.
The runtime's existing `src` attribute remains the same filtered workspace as
the CLI source, so consumers can build the matching SDK without a separate tree.
This is a dependency boundary, not a measured cache-hit guarantee on a cold
builder.

The assembled `bin/msb` is a regular copy of the source-built CLI, not a
symlink to its CLI-only output. The CLI derives `MSB_PATH` from its actual
executable and resolves firmware from the sibling `lib/` directory; the full
runtime must remain the executable's prefix. Cargo's non-prebuilt build keeps
the source-matched guest agent embedded. Its RPATH contains only the pinned
host dynamic libraries, not either package's own output path.

The runtime copies the pinned firmware and its configuration, release, source
and patch hashes into `lib/` and `share/libkrunfw`. Its `libkrunfw` attribute
still exposes the exact source-built derivation to consumers. The pinned
Linux 6.12.109 kernel includes the opt-in libkrun platform power-off handler,
which uses the existing emulated-device exit contract after normal kernel
shutdown, not a guest reboot. Package checks verify matching bytes, ABI 5 and
installed configuration, but do not establish completed guest shutdown.
Runtime validation must observe guest flush and normal VMM exit before host
fallback. Existing running VMs retain their loaded kernel; this package does
not live-replace firmware, migrate state or restart them. Fresh Linux x86_64
guests are the validation target; old-state or snapshot resume, downgrade,
other platforms and nested guests require separate coverage.

Cargo applies `[patch.crates-io]` only from the consuming workspace root. This
workspace therefore pins `msb-vm-memory` to the same rust-vmm revision as
libkrun, so the runtime and image backend use the same memory types. Applications
consuming this SDK from another workspace must also apply that root patch and
lock it consistently; the patch is not inherited from this dependency. The
standalone Ruby extension has its own Cargo workspace and dependency pins and
is not covered by the Linux runtime package checks.

### Layer 2 — build/check state (ephemeral)

`MSB_HOME="$TMPDIR/.microsandbox"`, set in the shared `stageAgentd` snippet
used as `preBuild` by `checks.clippy` and `checks.unit` only. `$TMPDIR` is the
nix sandbox's per-derivation scratch — writable during the build, deleted
after. The snippet stages `build/agentd`, exports `MSB_AGENTD_PATH`, and copies
the matching built CLI and firmware into the scratch home's `bin/` and `lib/`.

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

## Offline builds and checks

The SDK's default `prebuilt` build script accepts `MSB_BUILD_RUNTIME` as a
build-time-only, read-only runtime prefix. Set it to the fork's `microsandbox`
package output, containing `bin/msb` and `lib/<platform firmware filename>`.
The build validates both files and requires `msb --version` to match the SDK's
prebuilt version. An explicit empty, relative, missing, or incompatible prefix
is an error: it never falls back to downloading or installing under `MSB_HOME`.
It does not select runtime state or change the runtime binary-resolution API.
When unset, the existing prebuilt installation behavior remains unchanged.

This separates immutable compiler inputs from an application's mutable
`MSB_HOME`. The guest agent still uses the independent `MSB_AGENTD_PATH`
contract. `checks.build-runtime` exercises the read-only validation with
matching, missing, non-executable, and incompatible fixtures.

`crates/filesystem/build.rs` (`build_agentd`, `prebuilt` feature) resolves the
guest agentd in this order: `build/agentd` → `MSB_AGENTD_PATH` → cached
`OUT_DIR` copy → GitHub release download (`agentd_download_url(PREBUILT_VERSION)`,
`PREBUILT_VERSION = CARGO_PKG_VERSION`, matching the workspace release). The download
leg is a build-time network fetch, which Nix sandboxed builds cannot use.
The host package stages the separately built guest daemon and disables the
`prebuilt` feature. Workspace checks stage both the daemon and the matching
host runtime before compiling default features. Their SDK build script finds
the expected runtime version locally, so it does not download a release.
Cargo build, lint, dependency-policy and unit checks use vendored sources;
the custom checks pass `--locked --offline` explicitly.
The unit check also supplies the Nix CA bundle explicitly so TLS client
construction does not depend on host trust-store discovery.

Build the public outputs without entering the development shell:

```sh
nix build .#microsandbox .#agentd .#brokerd --no-link --no-write-lock-file
nix build .#checks.x86_64-linux.package --no-link --no-write-lock-file
nix build .#checks.x86_64-linux.fmt .#checks.x86_64-linux.deny --no-link --no-write-lock-file
```

The guest package verifies that its installed ELF has neither an interpreter
nor shared-library dependencies. The package check verifies the CLI version,
the shipped guest daemon, and dynamic loading of the firmware's required kernel
export. The public package names are `agentd`, `brokerd`,
`microsandbox`, `msb`, and `default` (`msb` and `default` alias `microsandbox`).
Consumers should obtain SDK paths from the same flake input that supplies
these packages.

`brokerd` is independently consumable: its package does not build or embed the
host CLI, guest agent, or firmware. Include its complete Nix closure in the
shared guest image; copying only the dynamically linked binary is insufficient.
The service does not own the image's init system or Nix daemon. The package's
install check executes only `brokerd service --help`, which returns before
credentials, listeners or legacy init are touched. Broker policy
uses its direct management transport, not the guest agent console. Packaging
alone does not establish a running service, provision credentials, or validate
the host-to-guest SSH route. Those require separate runtime acceptance.

`checks.x86_64-linux.ssh-termination` supplies pinned OpenSSH, Git and Bash and
explicitly runs legacy and managed SSH/Git tests, including the normally
ignored stock-client fixtures. The managed fixture uses separate synthetic
upstream keys for concurrent launches and checks that retiring one launch does
not terminate the others. The Git fixture checks clone, fetch and push against
two disposable repositories, exact object identities, and denied cross-repository
operations without upstream effects. This check uses local transports, not a
guest VM.

Package and check versions are read from `[workspace.package]` in `Cargo.toml`.
The host runtime and guest daemon must stay on that same release when upstream
changes are merged; packaging does not maintain a separate hardcoded version.

Evaluation reads `Cargo.lock` directly from the immutable flake input, separately
from the filtered Rust compilation source. This lets read-only derivation
queries work before the filtered source has been copied into the store; the
dependency versions and fixed-output hashes are unchanged.

### Workspace test requirements

`checks.unit` runs the full workspace with the existing upstream KVM ignore
markers; it does not exclude filesystem tests. Those tests exercise strict
stat virtualization using the `user.msb._probe` and `user.msb.override_stat`
extended attributes. [Nix's default Linux syscall filter](https://github.com/NixOS/nix/blob/2.34.7/src/libstore/unix/build/linux-derivation-builder.cc#L104)
returns `ENOTSUP` for
extended-attribute reads and writes, including on writable scratch files.
On such builders this gate fails at the filesystem capability probe and the
complete suite needs a separately isolated host test environment. Changing
the runtime's strict behavior or automatically disabling the syscall filter
is not part of the package build.

### Runtime acceptance on Linux

`nix run .#test-runtime` requires readable/writable `/dev/kvm` and a host
filesystem supporting the runtime's extended attributes. Unlike pure package
checks, this explicitly boots a real microVM outside the Nix build sandbox.
Missing KVM fails the test rather than reporting a skipped pass.

The app builds a small credential-free OCI fixture using the same nixpkgs pin,
loads it locally, and allocates a new temporary HOME/XDG/MSB context. It neither
uses existing sandboxes nor inherits registry credentials. Guest networking is
default-denied. The suite checks the packaged firmware's exact kernel release,
agent readiness, command output/error/exit status, persistent root-disk data
across a cold stop/start and guest shutdown before the host-exit fallback. It
does not establish saved-memory restore, systemd/NixOS support, nested
virtualization or SSH custody.

Each run prints an artifact directory containing command output, runtime
shutdown logs and a JSON result. Successful runs remove their disposable
sandbox; artifacts remain for inspection. Failed runs attempt force-stop only
inside their fresh context and report cleanup failures. The optional
`--scratch-parent` must stay short enough for Unix socket paths; the default
`/tmp` is intentional. `packages.x86_64-linux.runtime-smoke-image` exposes the
same uncompressed image archive for other explicitly isolated tests.

The fixture also includes a static `/bin/guest-cid` probe that reads the kernel's
actual vsock CID. The SDK's `guest_cid` integration target creates a new isolated
local backend, loads this archive with image pulls disabled, boots two guests,
replaces one with a fresh reserved CID and checks that the other's CID remains
unchanged. Networking is disabled; the configured local vsock route only enables
the device. No SSH custody or generation authorization is inferred from this test.

Run it against the matching built runtime with `MSB_PATH` set to its absolute
`bin/msb`, `MSB_LIBKRUNFW_PATH` set to that package's `lib/libkrunfw.so`,
`MSB_TEST_IMAGE_ARCHIVE` set to the built smoke archive, and
`MSB_CONFIG_PATH` set to an absolute nonexistent test path (the test refuses an
existing configuration):

```sh
cargo test --locked --offline -p microsandbox --test guest_cid -- --ignored --nocapture
```

The test preserves its fresh artifact directory and cleans up only its two
named guests. A successful guest-CID test does not validate host-global CID
reservation; that remains the embedding supervisor's responsibility.

The same offline image includes `/bin/vsock-guest-probe`, a static test fixture
using brokerd's production `VsockListener::accept` host-CID check. With the same
explicit environment and `MSB_TEST_OLD_RUNTIME` pointing to an actual runtime
that supports `guest-cid-v1` but predates `host-vsock-listen-v1`, run:

```sh
cargo test --locked --offline -p microsandbox --test host_vsock_listener -- --ignored --nocapture
```

This test creates two network-disabled guests with independent host listeners,
exchanges generated binary payloads across fragmentation/size cases, rejects a
colliding listener launch, replaces one guest with a fresh CID/path, and checks
the unaffected guest remains usable. Normal shutdown must remove the old owned
endpoint. The test keeps diagnostics and cleans up only its own named guests.
It tests the real host-to-broker transport accept path, not SSH authentication,
generation policy, certificate trust or Git operations.
The separate older-runtime case requires an explicit unsupported-capability
refusal before binding or creating the runtime directory, not just a generic
launch failure.

## Devshell state isolation (proposal; queued)

Devshell experimentation should never write the user's real
`~/.microsandbox/current`. Proposal (not implemented): a dev-scoped `MSB_HOME`
(e.g. `$PWD/.devenv/msb-home`, gitignored) for devshell use. Today the devshell
`enterShell` (`flake.nix:282-287`) deliberately exports only `MSB_AGENTD_PATH`
— no second runtime home — so this proposal extends that posture.
