# microsandbox — msb CLI + runtime libraries, built from THIS flake's source.
#
# Source provenance: the fork flake supplies its filtered Rust workspace,
# excluding local build caches and unrelated files. The fork is a Rust workspace
# (edition 2024, resolver 3). msb is built from source via buildRustPackage
# with the fenix-pinned toolchain for host-toolchain consistency. agentd is
# built separately (nix/packages/agentd.nix, musl static) and assembled here.
# Firmware is built by the pinned libkrunfw flake using the same tooling inputs.

{
  pkgs,
  rustToolchain,
  agentd,
  src,
  cargoLock,
  version,
  libkrunfw,
}:

let
  # fenix-pinned toolchain so the nix build and the dev shell agree on the
  # exact rustc (1.97.1, edition 2024).
  rustPlatform = pkgs.makeRustPlatform {
    inherit (rustToolchain) rustc;
    inherit (rustToolchain) cargo;
  };

in
rustPlatform.buildRustPackage rec {
  pname = "microsandbox";
  inherit version;

  inherit src;

  inherit cargoLock;

  # Build only the cli crate. Features: net + ssh (matching the fork justfile's
  # build-msb recipe exactly) via --no-default-features, which deliberately
  # excludes `prebuilt` and `keyring`. NOTE: the CLI DOES define `prebuilt` in
  # its default feature set (crates/cli/Cargo.toml: prebuilt =
  # ["microsandbox-runtime/prebuilt", "microsandbox/prebuilt"]). With prebuilt
  # excluded, the fork's filesystem crate build.rs takes the NON-prebuilt
  # branch, which requires <workspace>/build/agentd — hence the preBuild
  # staging below is required and correct.
  cargoBuildFlags = [
    "-p"
    "microsandbox-cli"
    "--no-default-features"
    "--features"
    "net,ssh"
  ];

  # Embed the runtime search path at link time (rustc -C link-arg -> -Wl,-rpath)
  # so the msb ELF carries its dynamic deps (libcap-ng, libgcc) with no
  # patchelf and no LD_LIBRARY_PATH anywhere.
  RUSTFLAGS = "-C link-arg=-Wl,-rpath,${
    pkgs.lib.makeLibraryPath [
      pkgs.libcap_ng
      pkgs.stdenv.cc.cc.lib
    ]
  }";

  nativeBuildInputs = with pkgs; [
    pkg-config
  ];

  buildInputs = with pkgs; [
    libcap_ng
    stdenv.cc.cc.lib
  ];

  preBuild = ''
    # The fork's filesystem crate build.rs (without the 'prebuilt' feature)
    # looks for a pre-built agentd at <workspace>/build/agentd. Stage it here
    # from the agentd derivation. touch ensures the mtime is newer than the
    # source tree (the build.rs staleness check compares against crates/agentd
    # and crates/protocol mtimes — nix source files have fixed mtimes).
    mkdir -p build
    cp ${agentd}/libexec/agentd build/agentd
    touch build/agentd
  '';
  doCheck = false;

  # Assemble the runtime layout the tool expects:
  #   $out/bin/msb           — from cargo target/release/msb
  #   $out/libexec/agentd    — from the agentd derivation (musl static)
  #   $out/lib/libkrunfw.so* — links to the pinned source-built firmware
  installPhase = ''
    runHook preInstall

    mkdir -p $out/bin $out/lib $out/libexec

    install -Dm755 target/${pkgs.stdenv.hostPlatform.rust.rustcTarget}/release/msb $out/bin/msb

    # agentd (static musl — runs in the guest microVM).
    install -Dm755 ${agentd}/libexec/agentd $out/libexec/agentd

    test -f ${libkrunfw}/lib/libkrunfw.so.5.6.1
    ln -s ${libkrunfw}/lib/libkrunfw.so.5.6.1 $out/lib/libkrunfw.so.5.6.1
    ln -s libkrunfw.so.5.6.1 $out/lib/libkrunfw.so.5
    ln -s libkrunfw.so.5 $out/lib/libkrunfw.so

    runHook postInstall
  '';

  passthru = { inherit libkrunfw; };

  meta = with pkgs.lib; {
    description = "Microsandbox CLI and runtime libraries (built from fork)";
    homepage = "https://github.com/superradcompany/microsandbox";
    license = licenses.asl20;
    platforms = [ "x86_64-linux" ];
    mainProgram = "msb";
  };
}
