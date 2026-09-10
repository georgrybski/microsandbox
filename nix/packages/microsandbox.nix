# microsandbox — msb CLI + runtime libraries, built from THIS flake's source.
#
# Source provenance: the fork flake supplies its filtered Rust workspace,
# excluding local build caches and unrelated files. The fork is a Rust workspace
# (edition 2024, resolver 3). msb is built from source via buildRustPackage
# with the fenix-pinned toolchain for host-toolchain consistency. agentd is
# built separately (nix/packages/agentd.nix, musl static) and assembled here.
# libkrunfw currently comes from a fixed-hash upstream release tarball;
# replacing it with a compatible source-built fork package is a follow-up.

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

  # Interim firmware input: retain the v0.6.8 release's fixed-hash firmware
  # until the fork exposes a compatible source-built package. It embeds a
  # GPL-2.0 Linux kernel, so corresponding-source provenance must be checked
  # before redistributing this assembled runtime.
  #
  # A source-built replacement must preserve the SDK's expected firmware ABI
  # and be validated together with the locked msb_krun revision. This is a
  # packaging follow-up, not merely a fallback if the release disappears.
  #
  # The fork's LIBKRUNFW_VERSION is "5.6.1" (ABI "5") — NOT 5.2.1 as in the
  # old 0.5.6 release tarball. The symlink layout must match: libkrunfw.so.5.6.1
  # <- libkrunfw.so.5 <- libkrunfw.so.
  libkrunfwTar = pkgs.fetchurl {
    url = "https://github.com/superradcompany/microsandbox/releases/download/v0.6.8/microsandbox-linux-x86_64.tar.gz";
    sha256 = "sha256-mSvmbOimGWWzrHczvOWNapioKSoXLoXIdRB0oq0W9p0=";
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
  #   $out/lib/libkrunfw.so* — from the fixed-hash upstream release tarball
  installPhase = ''
    runHook preInstall

    mkdir -p $out/bin $out/lib $out/libexec

    install -Dm755 target/${pkgs.stdenv.hostPlatform.rust.rustcTarget}/release/msb $out/bin/msb

    # agentd (static musl — runs in the guest microVM).
    install -Dm755 ${agentd}/libexec/agentd $out/libexec/agentd

    # libkrunfw: extract only firmware from the upstream release tarball.
    tar xzf ${libkrunfwTar} -C $TMPDIR
    if [ -d "$TMPDIR/lib" ]; then
      for f in "$TMPDIR"/lib/libkrunfw.so*; do
        [ -e "$f" ] && cp -P "$f" $out/lib/
      done
    fi
    # Also check the flat layout (some releases put libs at the root).
    for f in "$TMPDIR"/libkrunfw.so*; do
      [ -e "$f" ] && cp -P "$f" $out/lib/
    done

    # Ensure the libkrunfw soname symlinks exist (ABI 5, version 5.6.1).
    if [ -f "$out/lib/libkrunfw.so.5.6.1" ]; then
      ln -sfn libkrunfw.so.5.6.1 $out/lib/libkrunfw.so.5
      ln -sfn libkrunfw.so.5 $out/lib/libkrunfw.so
    elif [ -f "$out/lib/libkrunfw.so.5" ]; then
      ln -sfn libkrunfw.so.5 $out/lib/libkrunfw.so
    fi

    # Fail-closed: libkrunfw is mandatory for the microVM runtime. If the
    # release tarball didn't contain it (wrong version, missing lib/, or the
    # archive layout changed), abort loudly rather than shipping a
    # broken msb with no KVM firmware.
    if ! ls $out/lib/libkrunfw.so* >/dev/null 2>&1; then
      echo "error: libkrunfw.so* not found in the pinned release archive" >&2
      exit 1
    fi

    runHook postInstall
  '';

  meta = with pkgs.lib; {
    description = "Microsandbox CLI and runtime libraries (built from fork)";
    homepage = "https://github.com/superradcompany/microsandbox";
    license = licenses.asl20;
    platforms = [ "x86_64-linux" ];
    mainProgram = "msb";
  };
}
