{
  description = "microsandbox (rybskiworks fork) — self-contained nix packaging on shared nix-tooling pins";

  inputs = {
    # Shared tooling owns the toolchain and dependency versions.
    # For local iteration, override tooling with a Git-filtered checkout:
    # `--override-input tooling git+file:///absolute/path/to/nix-tooling`.
    # Keep its owned pins intact; consumers follow the shared input graph.
    tooling.url = "github:rybskiworks/nix-tooling/1120aa22cddf4a9a3424f38aadbebadd8a963c4b";

    # ONE pin universe: every shared input follows tooling. Do NOT declare
    # own revs for any of these — bumps happen in nix-tooling only.
    nixpkgs.follows = "tooling/nixpkgs";
    fenix.follows = "tooling/fenix";
    flake-parts.follows = "tooling/flake-parts";
    devenv.follows = "tooling/devenv";
    treefmt-nix.follows = "tooling/treefmt-nix";
    git-hooks.follows = "tooling/git-hooks";

    libkrunfw = {
      url = "github:rybskiworks/libkrunfw/d575b13e79368b23246be3d93d7935899dec5a3b";
      inputs.tooling.follows = "tooling";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.flake-parts.follows = "flake-parts";
    };

    # Inputs for devenv's default container outputs. Not used directly by the
    # packages; these can be removed if the unused container outputs are disabled.
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
    # directory).
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
      # .taplo.toml. The Rust fmt gate is covered by checks.fmt (cargo fmt,
      # which honors .rustfmt.toml).
      imports = [
        # NOTE(pure-eval): devenv.root defaults to $PWD, which is blank under
        # pure evaluation, so plain `nix flake show/check` fails by design with
        # "devenv was not able to determine the current directory" (upstream
        # devenv behavior, see devenv.sh "using with flakes" guide). Use
        # --override-input devenv-root with a file containing the worktree
        # path, as direnv does. Do NOT hard-code
        # devenv.root to a fixed path — non-portable between machines.
        inputs.devenv.flakeModule
      ];

      systems = [ "x86_64-linux" ];

      perSystem =
        { config, system, ... }:
        let
          pkgs = import inputs.nixpkgs {
            inherit system;
            overlays = [ inputs.fenix.overlays.default ];
            config.allowUnfree = true;
          };

          # Pinned Rust toolchain via fenix (owned pin — see inputs above).
          rustToolchain = inputs.fenix.packages.${system}.stable;

          # Only Rust workspace inputs affect package sources. Exclude local
          # build caches even when the flake is supplied as a path override.
          src = pkgs.lib.cleanSourceWith {
            src = inputs.self;
            filter =
              path: type:
              let
                relative = pkgs.lib.removePrefix "${inputs.self}/" path;
                root = builtins.head (pkgs.lib.splitString "/" relative);
              in
              builtins.elem root [
                "Cargo.toml"
                "Cargo.lock"
                ".cargo"
                ".rustfmt.toml"
                "crates"
                "sdk"
                "packages"
                "examples"
                "assets"
                "README.md"
                "LICENSE"
                "deny.toml"
              ]
              && pkgs.lib.cleanSourceFilter path type
              && !(builtins.elem (builtins.baseNameOf path) [
                "target"
                "build"
                ".devenv"
                ".direnv"
                ".venv"
                "node_modules"
              ]);
          };

          rustPlatform = pkgs.makeRustPlatform {
            inherit (rustToolchain) cargo;
            inherit (rustToolchain) rustc;
          };

          # Evaluation reads metadata from the already-fetched flake input;
          # the filtered compilation source need not exist in the store yet.
          cargoLock = import ./nix/cargo-lock.nix { lockFile = ./Cargo.lock; };
          version = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).workspace.package.version;

          agentd = pkgs.callPackage ./nix/packages/agentd.nix { inherit src cargoLock version; };
          brokerd = pkgs.callPackage ./nix/packages/brokerd.nix {
            inherit
              rustPlatform
              src
              cargoLock
              version
              ;
          };
          libkrunfw = inputs.libkrunfw.packages.${system}.default;
          vsockProbe = pkgs.callPackage ./nix/packages/guest-vsock-probe.nix {
            inherit src cargoLock version;
          };
          runtimeSmokeImage = pkgs.callPackage ./nix/packages/runtime-smoke-image.nix { inherit vsockProbe; };
          cli = pkgs.callPackage ./nix/packages/cli.nix {
            inherit
              src
              rustToolchain
              agentd
              cargoLock
              version
              ;
          };
          msb = pkgs.callPackage ./nix/packages/microsandbox.nix {
            inherit cli agentd libkrunfw;
          };
          handoffSource = pkgs.lib.fileset.toSource {
            root = ./scripts/smoke/cli;
            fileset = pkgs.lib.fileset.unions [
              ./scripts/smoke/cli/runtime-handoff.py
              ./scripts/smoke/cli/test_runtime_handoff.py
            ];
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
            export MSB_BUILD_RUNTIME="${msb}"
            # Sandbox-safe MSB_HOME for check gates only: nix sandbox sets
            # HOME=/homeless-shelter, so resolve_home() (sdk/rust/build.rs via
            # crates/utils resolve_home()) would fail creating bin/ and lib/ dirs.
            # Point at writable TMPDIR instead. Scoped here — do NOT copy to
            # devenv enterShell ergonomics.
            export MSB_HOME="$TMPDIR/.microsandbox"
            # The SDK's default `prebuilt` feature verifies the runtime here.
            # Supply the matching package so checks never download a release.
            mkdir -p "$MSB_HOME/bin" "$MSB_HOME/lib"
            cp ${msb}/bin/msb "$MSB_HOME/bin/"
            cp -P ${msb}/lib/libkrunfw.so* "$MSB_HOME/lib/"
          '';
        in
        {
          _module.args.pkgs = pkgs;

          packages = {
            inherit agentd brokerd msb;
            runtime-smoke-image = runtimeSmokeImage;
            runtime-handoff-image = inputs.tooling.packages.${system}.guest-determinate-base;
            # workestrate consumes `packages.${system}.microsandbox`.
            microsandbox = msb;
            default = msb;
          };

          # KVM acceptance runs outside the Nix build sandbox, with its own
          # disposable state. It never becomes an implicitly skipped check.
          apps.test-runtime = {
            type = "app";
            program = "${
              pkgs.writeShellApplication {
                name = "msb-test-runtime";
                runtimeInputs = [ pkgs.python3 ];
                text = ''
                  exec python3 ${./scripts/smoke/cli/runtime-firmware.py} \
                    --msb ${msb}/bin/msb --image ${runtimeSmokeImage} \
                    --kernel-release ${libkrunfw}/share/libkrunfw/kernel.release "$@"
                '';
              }
            }/bin/msb-test-runtime";
          };

          apps.test-runtime-handoff = {
            type = "app";
            program = "${
              pkgs.writeShellApplication {
                name = "msb-test-runtime-handoff";
                runtimeInputs = [ pkgs.python3 ];
                text = ''
                  exec python3 -I -B ${handoffSource}/runtime-handoff.py "$@" \
                    --support ${inputs.tooling}/tests/nixos-image \
                    --spec ${inputs.tooling.legacyPackages.${system}.nixosImages.smokeSpec} \
                    --msb ${msb}/bin/msb --expected-version ${version} \
                    --runtime-revision ${
                      inputs.self.rev or (throw "test-runtime-handoff requires a committed Git flake")
                    }
                '';
              }
            }/bin/msb-test-runtime-handoff";
          };

          checks = {
            runtime-handoff-contract =
              pkgs.runCommand "microsandbox-runtime-handoff-contract"
                {
                  nativeBuildInputs = [ pkgs.python3 ];
                  MSB_HANDOFF_SUPPORT = "${inputs.tooling}/tests/nixos-image";
                }
                ''
                  python3 -I -B ${handoffSource}/test_runtime_handoff.py -v
                  mkdir -p "$out"
                  touch "$out/ok"
                '';

            runtime-shutdown = config.checks.unit.overrideAttrs {
              pname = "microsandbox-runtime-shutdown-tests";
              buildPhase = ''
                runHook preBuild
                cargo test --jobs "$NIX_BUILD_CORES" --locked --offline \
                  -p microsandbox-runtime --lib guest_shutdown_flush_timeout -- --test-threads=1
                runHook postBuild
              '';
            };

            # Protocol-level custody acceptance uses real OpenSSH, synthetic
            # keys and loopback only; it does not depend on KVM or guest images.
            ssh-termination = rustPlatform.buildRustPackage {
              pname = "microsandbox-ssh-termination-tests";
              inherit version src cargoLock;
              MSB_TEST_SSH = "${pkgs.openssh}/bin/ssh";
              MSB_TEST_GIT = "${pkgs.git}/bin/git";
              MSB_TEST_SHELL = "${pkgs.bash}/bin/bash";
              buildPhase = ''
                runHook preBuild
                cargo test --jobs "$NIX_BUILD_CORES" --locked --offline \
                  -p microsandbox-brokerd --lib --test divert_e2e
                cargo test --jobs "$NIX_BUILD_CORES" --locked --offline \
                  -p microsandbox-brokerd --test ssh_openssh --test managed_openssh \
                  --test managed_git -- --include-ignored --test-threads=1
                runHook postBuild
              '';
              installPhase = ''
                mkdir -p $out
              '';
              doCheck = false;
            };

            build-runtime =
              pkgs.runCommand "microsandbox-build-runtime-check"
                {
                  nativeBuildInputs = [
                    rustToolchain.rustc
                    pkgs.stdenv.cc
                  ];
                }
                ''
                  rustc --edition=2024 --test ${src}/sdk/rust/build_support/runtime.rs -o build-runtime-tests
                  ./build-runtime-tests
                  mkdir -p $out
                '';

            package =
              assert pkgs.lib.assertMsg (
                toString msb.src == toString cli.src && toString msb.src == toString src
              ) "runtime must preserve the canonical filtered SDK source";
              pkgs.runCommand "microsandbox-package-check"
                {
                  nativeBuildInputs = [ pkgs.python3 ];
                }
                ''
                  export MSB_HOME="$TMPDIR/.microsandbox"
                  ${msb}/bin/msb --version | grep -Fx 'msb ${msb.version}'
                  test ! -L ${msb}/bin/msb
                  cmp ${msb}/bin/msb ${cli}/bin/msb
                  cmp ${msb}/libexec/agentd ${agentd}/libexec/agentd
                  test -e ${msb}/lib/libkrunfw.so
                  cmp ${msb}/lib/libkrunfw.so.5.6.1 ${libkrunfw}/lib/libkrunfw.so.5.6.1
                  for name in kernel.config kernel.release kernel-source.sha256 kernel-patches.sha256; do
                    cmp ${msb}/share/libkrunfw/$name ${libkrunfw}/share/libkrunfw/$name
                  done
                  grep -Fx 'CONFIG_POWER_RESET_LIBKRUN=y' ${msb}/share/libkrunfw/kernel.config
                  python - <<'PY'
                  import ctypes

                  firmware = ctypes.CDLL("${msb}/lib/libkrunfw.so.5.6.1")
                  version = firmware.krunfw_get_version
                  version.argtypes = []
                  version.restype = ctypes.c_uint32
                  assert version() == 5
                  kernel = firmware.krunfw_get_kernel
                  kernel.argtypes = [ctypes.POINTER(ctypes.c_size_t)] * 3
                  kernel.restype = ctypes.c_void_p
                  load, entry, size = ctypes.c_size_t(), ctypes.c_size_t(), ctypes.c_size_t()
                  address = kernel(ctypes.byref(load), ctypes.byref(entry), ctypes.byref(size))
                  assert address and address % 65536 == 0
                  assert load.value and entry.value and size.value and size.value % 65536 == 0
                  PY
                  mkdir -p $out
                '';

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
            deny = rustPlatform.buildRustPackage {
              pname = "microsandbox-deny";
              inherit version;
              inherit src cargoLock;
              nativeBuildInputs = [ pkgs.cargo-deny ];
              buildPhase = ''
                runHook preBuild
                cargo deny --locked --offline check bans sources
                runHook postBuild
              '';
              installPhase = ''
                mkdir -p $out
              '';
              doCheck = false;
            };

            # Heavy check (allowed to be expensive): upstream's clippy gates
            # from .github/workflows/check.yml —
            #   cargo clippy --workspace --exclude microsandbox-agentd -- -D warnings
            #   cargo clippy --manifest-path crates/agentd/Cargo.toml \
            #     --target x86_64-unknown-linux-musl -- -D warnings
            clippy = rustPlatform.buildRustPackage {
              pname = "microsandbox-clippy";
              inherit version;
              inherit src;
              inherit cargoLock;
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
                cargo clippy --jobs "$NIX_BUILD_CORES" --locked --offline --workspace --exclude microsandbox-agentd -- -D warnings
                cargo clippy --manifest-path crates/agentd/Cargo.toml \
                  --jobs "$NIX_BUILD_CORES" --locked --offline --target x86_64-unknown-linux-musl -- -D warnings
                runHook postBuild
              '';
              installPhase = ''
                mkdir -p $out
              '';
              doCheck = false;
            };

            # Full workspace tests retain upstream's existing KVM ignores.
            # Strict filesystem tests also require xattrs; the default Linux
            # Nix syscall filter rejects them. Keep these tests intact and use
            # an isolated host test environment when that builder policy applies.
            unit = rustPlatform.buildRustPackage {
              pname = "microsandbox-unit-tests";
              inherit version;
              inherit src;
              inherit cargoLock;
              # TLS client construction needs explicit trust roots in the sandbox.
              SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
              nativeBuildInputs = [ pkgs.pkg-config ];
              buildInputs = with pkgs; [
                libcap_ng
                stdenv.cc.cc.lib
              ];
              preBuild = stageAgentd;
              buildPhase = ''
                runHook preBuild
                cargo test --jobs "$NIX_BUILD_CORES" --locked --offline --workspace -- --test-threads "$NIX_BUILD_CORES"
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
