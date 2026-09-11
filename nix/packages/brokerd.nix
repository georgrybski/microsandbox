# Ordinary service for a guest with the shared NixOS runtime closure. Unlike
# agentd, brokerd does not need to be a static init binary in this deployment.
{
  lib,
  rustPlatform,
  src,
  cargoLock,
  version,
}:

rustPlatform.buildRustPackage {
  pname = "microsandbox-brokerd";
  inherit version src cargoLock;

  cargoBuildFlags = [
    "-p"
    "microsandbox-brokerd"
    "--bin"
    "brokerd"
  ];

  # SSH protocol acceptance belongs to checks.ssh-termination. Building this
  # service does not require a VM, the host CLI, firmware or a running broker.
  doCheck = false;

  # This subcommand returns before reading credentials, initializing a guest or
  # binding a listener. Exercise the installed binary, never its legacy init.
  doInstallCheck = true;
  installCheckPhase = ''
    runHook preInstallCheck
    "$out/bin/brokerd" service --help > help.txt
    grep -F 'Usage: brokerd service ' help.txt
    runHook postInstallCheck
  '';

  meta = {
    description = "Microsandbox SSH custody broker";
    homepage = "https://github.com/superradcompany/microsandbox";
    license = lib.licenses.asl20;
    platforms = [ "x86_64-linux" ];
    mainProgram = "brokerd";
  };
}
