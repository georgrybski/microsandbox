{
  description = "microsandbox (rybskiworks fork) — self-contained nix packaging on shared nix-tooling pins";

  inputs = {
    # Shared tooling pin — mirrors workestrate/flake.nix exactly.
    # For local iteration: `--override-input tooling path:../nix-tooling` (or
    # the absolute path). Do NOT follow-override tooling's owned pins
    # (fenix rev / tombi); only nixpkgs-class inputs are shared via follows.
    tooling.url = "github:rybskiworks/nix-tooling/18f8b85f6777240a0ecef4e93ebee69313802aed";

    # ONE pin universe: every shared input follows tooling. Do NOT declare
    # own revs for any of these — bumps happen in nix-tooling only.
    nixpkgs.follows = "tooling/nixpkgs";
    fenix.follows = "tooling/fenix";
    flake-parts.follows = "tooling/flake-parts";
    devenv.follows = "tooling/devenv";
    treefmt-nix.follows = "tooling/treefmt-nix";
    git-hooks.follows = "tooling/git-hooks";

    # Required by devenv's flakeModule (containers/mk-shell-bin support is
    # wired unconditionally there; nix-tooling pruned these, so they are
    # declared here with the same revs workestrate uses). Not used directly.
    nix2container = {
      url = "github:nlewo/nix2container/76be9608a7f4d6c985d28b0e7be903ae2547df3e";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    mk-shell-bin.url = "github:rrbutani/nix-mk-shell-bin/ff5d8bd4d68a347be5042e2f16caee391cd75887";

    # Placeholder for pure evaluation: devenv's auto-imported readDevenvRoot
    # module sets devenv.root from builtins.readFile of this input when the
    # content is non-empty; /dev/null reads as "" (override inert, keeps
    # `nix flake show/check`-style eval of OTHER outputs working). Enter the
    # shell via
    #   nix develop --override-input devenv-root "file+file://<rootfile>"
    # where <rootfile> is a FILE containing the worktree abs path (NOT the
    # directory), or via `nix develop --impure` (falls back to PWD).
    devenv-root = {
      url = "file+file:///dev/null";
      flake = false;
    };
  };

  outputs =
    inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      # NOTE: tooling's treefmt-nix / git-hooks flakeModules are deliberately
      # NOT imported here. The fork already has .pre-commit-config.yaml and
      # .taplo.toml, and the pinned tooling's treefmt rustfmt predates the
      # edition-2024 default fix (nix-tooling@a9bd083). The Rust fmt gate is
      # covered by checks.fmt (cargo fmt, which honors .rustfmt.toml).
      # Deferred: revisit after the tooling pin is bumped past a9bd083.
      imports = [
        # NOTE(pure-eval): devenv.root defaults to $PWD, which is blank under
        # pure evaluation, so plain `nix flake show/check` fails by design with
        # "devenv was not able to determine the current directory" (upstream
        # devenv behavior, see devenv.sh "using with flakes" guide). Use
        # `nix flake show/check --impure` (or --override-input devenv-root
        # with a file containing $PWD, as direnv does). Do NOT hard-code
        # devenv.root to a fixed path — non-portable between machines.
        inputs.devenv.flakeModule
      ];

      systems = [ "x86_64-linux" ];

      perSystem =
        { system, ... }:
        let
          pkgs = import inputs.nixpkgs {
            inherit system;
            overlays = [ inputs.fenix.overlays.default ];
            config.allowUnfree = true;
          };

          # Pinned Rust toolchain via fenix (owned pin — see inputs above).
          rustToolchain = inputs.fenix.packages.${system}.stable;

          # The flake root IS the workspace root. Flake git semantics already
          # exclude untracked/ignored files (target/, .devenv/, the
          # unpopulated vendor/libkrunfw submodule contents), so a plain
          # `src = self` is acceptable — no cleanSourceWith filter needed.
          src = inputs.self;

          rustPlatform = pkgs.makeRustPlatform {
            inherit (rustToolchain) cargo;
            inherit (rustToolchain) rustc;
          };

          agentd = pkgs.callPackage ./nix/packages/agentd.nix { inherit src; };
          msb = pkgs.callPackage ./nix/packages/microsandbox.nix {
            inherit src rustToolchain agentd;
          };

          # Toolchain with the musl std for the agentd musl clippy gate
          # (mirrors upstream check.yml: clippy --target x86_64-unknown-linux-musl).
          clippyToolchain = inputs.fenix.packages.${system}.combine [
            inputs.fenix.packages.${system}.stable.cargo
            inputs.fenix.packages.${system}.stable.rustc
            inputs.fenix.packages.${system}.stable.clippy
            inputs.fenix.packages.${system}.targets.x86_64-unknown-linux-musl.stable.rust-std
          ];

          # Shared staging for checks whose build.rs needs agentd (the
          # filesystem crate's build.rs requires <workspace>/build/agentd in
          # the non-prebuilt branch and prefers it in the prebuilt branch).
          stageAgentd = ''
            mkdir -p build
            cp ${agentd}/libexec/agentd build/agentd
            touch build/agentd
            export MSB_AGENTD_PATH="${agentd}/libexec/agentd"
            # Sandbox-safe MSB_HOME for check gates only: nix sandbox sets
            # HOME=/homeless-shelter, so resolve_home() (sdk/rust/build.rs via
            # crates/utils resolve_home()) would fail creating bin/ and lib/ dirs.
            # Point at writable TMPDIR instead. Scoped here — do NOT copy to
            # devenv enterShell ergonomics.
            export MSB_HOME="$TMPDIR/.microsandbox"
          '';
        in
        {
          _module.args.pkgs = pkgs;

          packages = {
            inherit agentd msb;
            # workestrate consumes `packages.${system}.microsandbox`.
            microsandbox = msb;
            default = msb;
          };

          # TODO(apps): test-kvm / test-nested-virt runner apps are deferred —
          # they need /dev/kvm and a nested-virt-capable host, so they are not
          # meaningfully wrappable as flake apps in this container. Revisit
          # with workestrate's scripts/kvm-tests.sh as the reference.

          checks = {
            # Rust formatting gate — fenix toolchain; cargo fmt honors the
            # fork's .rustfmt.toml (edition = "2024").
            fmt =
              pkgs.runCommand "cargo-fmt-check"
                {
                  nativeBuildInputs = [
                    rustToolchain.cargo
                    rustToolchain.rustfmt
                  ];
                }
                ''
                  cd ${src}
                  cargo fmt --all -- --check
                  mkdir -p $out
                '';

            # cargo-deny gate. Scoped to `bans sources` (the currently-green
            # checks): the 2026-09-06 baseline of `cargo deny --locked check`
            # has licenses FAILED (0BSD via managed/smoltcp, Apache-2.0 WITH
            # LLVM-exception via target-lexicon/winx) and advisories FAILED
            # (h2, pyo3, rsa, proc-macro-error2). Widen to `licenses` and
            # `advisories` once the upstream baseline is fixed; see the TODO
            # at bans.wildcards in deny.toml.
            deny =
              pkgs.runCommand "cargo-deny-check"
                {
                  nativeBuildInputs = [
                    pkgs.cargo-deny
                    rustToolchain.cargo
                    rustToolchain.rustc
                  ];
                }
                ''
                  export CARGO_HOME=$TMPDIR/cargo-home
                  cd ${src}
                  cargo deny --locked check bans sources
                  mkdir -p $out
                '';

            # Heavy check (allowed to be expensive): upstream's clippy gates
            # from .github/workflows/check.yml —
            #   cargo clippy --workspace --exclude microsandbox-agentd -- -D warnings
            #   cargo clippy --manifest-path crates/agentd/Cargo.toml \
            #     --target x86_64-unknown-linux-musl -- -D warnings
            clippy = rustPlatform.buildRustPackage {
              pname = "microsandbox-clippy";
              version = "0.6.16";
              inherit src;
              cargoLock.lockFile = src + "/Cargo.lock";
              cargo = clippyToolchain;
              rustc = clippyToolchain;
              nativeBuildInputs = [
                pkgs.pkg-config
                clippyToolchain
              ];
              buildInputs = with pkgs; [
                libcap_ng
                stdenv.cc.cc.lib
              ];
              preBuild = stageAgentd;
              buildPhase = ''
                runHook preBuild
                cargo clippy --workspace --exclude microsandbox-agentd -- -D warnings
                cargo clippy --manifest-path crates/agentd/Cargo.toml \
                  --target x86_64-unknown-linux-musl -- -D warnings
                runHook postBuild
              '';
              installPhase = ''
                mkdir -p $out
              '';
              doCheck = false;
            };

            # Heavy check (allowed to be expensive): unit tests. Empirical
            # baseline (2026-09-06, devshell, no /dev/kvm): full
            # `cargo test --workspace` is green WITHOUT scoping — 3049
            # passed, 0 failed, 138 ignored across 108 test binaries; the
            # KVM-dependent tests are already #[ignore]d upstream, so no
            # exclusion list is needed. libcap-ng comes from buildInputs.
            unit = rustPlatform.buildRustPackage {
              pname = "microsandbox-unit-tests";
              version = "0.6.16";
              inherit src;
              cargoLock.lockFile = src + "/Cargo.lock";
              nativeBuildInputs = [ pkgs.pkg-config ];
              buildInputs = with pkgs; [
                libcap_ng
                stdenv.cc.cc.lib
              ];
              preBuild = stageAgentd;
              buildPhase = ''
                runHook preBuild
                cargo test --workspace
                runHook postBuild
              '';
              installPhase = ''
                mkdir -p $out
              '';
              doCheck = false;
            };
          };

          # Devenv shell: dogfoods tooling modules + fork-specific build deps.
          # devenv.root is intentionally NOT set here — see the devenv-root
          # input comment above for the pure-eval entry pattern.
          devenv.shells.default = {
            imports = [
              inputs.tooling.devenvModules.base
              inputs.tooling.devenvModules.nix
              inputs.tooling.devenvModules.toml
              inputs.tooling.devenvModules.rust
            ];

            # Mirrors upstream's `just _install-dev-deps` (build-essential,
            # flex, bison, libelf-dev, python3-pyelftools, pkg-config,
            # libcap-ng-dev, pre-commit) in nix form. NOTE: upstream's
            # musl-tools is deliberately NOT mirrored as pkgs.musl — its
            # -L.../musl/lib in NIX_LDFLAGS shadows glibc and breaks host
            # linking. agentd musl builds go through nix (pkgsStatic) and the
            # musl clippy gate through checks.clippy's fenix combined
            # toolchain instead.
            packages = with pkgs; [
              cargo-deny
              flex
              bison
              gcc
              just
              libcap_ng
              libelf
              pkg-config
              pre-commit
              (python3.withPackages (p: [ p.pyelftools ]))
            ];

            # The fork already has .pre-commit-config.yaml (upstream's hook
            # battery, incl. Python SDK builds). devenv's git-hooks
            # integration picks that file up and RUNS it on shell entry,
            # which fails in this environment and mutates hook state — the
            # anticipated fight. Disable devenv-side git-hooks entirely;
            # upstream's pre-commit stays the repo-level hook system.
            git-hooks.enable = false;

            # Likewise, devenv's treefmt runs on shell entry and tooling's
            # tombi wrapper requires a tombi.toml, which this fork does not
            # have (it uses .taplo.toml + cargo fmt). Disable devenv-side
            # treefmt; the fmt gate lives in checks.fmt.
            treefmt.enable = false;

            enterShell = ''
              echo "microsandbox (fork) dev shell"
              # build.rs (prebuilt branch) and local recipes consume a staged
              # agentd; point at the nix-built musl binary.
              export MSB_AGENTD_PATH="${agentd}/libexec/agentd"
            '';
          };
        };
    };
}
