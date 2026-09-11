# Source-built CLI with its matching embedded static guest agent.
# Firmware selection belongs to runtime assembly, not Cargo compilation.
{
  pkgs,
  rustToolchain,
  agentd,
  src,
  cargoLock,
  version,
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
  pname = "microsandbox-cli";
  inherit version;

  inherit src;

  inherit cargoLock;

  passthru = { inherit agentd; };

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

  installPhase = ''
    runHook preInstall
    install -Dm755 target/${pkgs.stdenv.hostPlatform.rust.rustcTarget}/release/msb $out/bin/msb
    runHook postInstall
  '';

  meta = with pkgs.lib; {
    description = "Microsandbox CLI with its source-matched embedded guest agent";
    homepage = "https://github.com/superradcompany/microsandbox";
    license = licenses.asl20;
    platforms = [ "x86_64-linux" ];
    mainProgram = "msb";
  };
}
