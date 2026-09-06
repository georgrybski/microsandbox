# agentd — guest init/agent daemon for microsandbox microVMs.
#
# Built as a static musl binary from THIS flake's own source (`src = self`
# passed in from the fork flake — the flake root IS the workspace root, so no
# sourceRoot). agentd runs INSIDE the guest microVM, not on the host — a static
# musl binary has no library deps and works with any guest rootfs (alpine/musl
# or glibc).
#
# Uses pkgsStatic (nixpkgs' static musl build infrastructure) so the musl
# toolchain is handled automatically. nixpkgs' default rustc is used (not the
# fenix pin) — agentd is a simple guest binary and doesn't need to match the
# host toolchain. If nixpkgs' rustc is too old for edition 2024 (requires
# rustc >= 1.85), the host build will fail and we must inject the fenix
# toolchain via fenix.combine with the musl target.

{ pkgs, src }:

pkgs.pkgsStatic.rustPlatform.buildRustPackage rec {
  pname = "microsandbox-agentd";
  version = "0.6.16";

  inherit src;

  cargoLock = {
    lockFile = src + "/Cargo.lock";
  };

  # Only build the agentd crate, not the whole workspace.
  cargoBuildFlags = [
    "-p"
    "microsandbox-agentd"
  ];

  doCheck = false;

  installPhase = ''
    runHook preInstall
    # pkgsStatic sets a musl hostPlatform, so cargo may place the binary at
    # target/x86_64-unknown-linux-musl/release/agentd OR target/release/agentd
    # depending on how pkgsStatic wires the target. Find it robustly and fail
    # loudly if missing or ambiguous.
    agentd_bin=$(find target -type f -name agentd -path '*/release/*' | head -n1)
    if [ -z "$agentd_bin" ]; then
      echo "error: agentd binary not found under target/*/release/" >&2
      find target -type f -name agentd >&2 || true
      exit 1
    fi
    install -Dm755 "$agentd_bin" $out/libexec/agentd
    runHook postInstall
  '';
}
