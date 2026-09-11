{
  pkgs,
  src,
  cargoLock,
  version,
}:

pkgs.pkgsStatic.rustPlatform.buildRustPackage {
  pname = "microsandbox-guest-vsock-probe";
  inherit src cargoLock version;
  cargoBuildFlags = [
    "-p"
    "microsandbox-brokerd"
    "--example"
    "vsock-guest-probe"
  ];
  doCheck = false;
  installPhase = ''
    runHook preInstall
    install -Dm755 target/${pkgs.pkgsStatic.stdenv.hostPlatform.rust.rustcTarget}/release/examples/vsock-guest-probe \
      $out/bin/vsock-guest-probe
    runHook postInstall
  '';
  doInstallCheck = true;
  installCheckPhase = ''
    runHook preInstallCheck
    ${pkgs.buildPackages.binutils}/bin/readelf --program-headers $out/bin/vsock-guest-probe > headers
    ${pkgs.buildPackages.binutils}/bin/readelf --dynamic $out/bin/vsock-guest-probe > dynamic
    if grep -q INTERP headers || grep -q NEEDED dynamic; then
      echo "guest vsock fixture must be statically linked" >&2
      exit 1
    fi
    runHook postInstallCheck
  '';
}
