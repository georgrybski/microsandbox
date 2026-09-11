# Assemble immutable source-built components without rebuilding the CLI.
{
  pkgs,
  cli,
  agentd,
  libkrunfw,
}:
assert cli.agentd.drvPath == agentd.drvPath;
pkgs.runCommand "microsandbox-${cli.version}"
  {
    pname = "microsandbox";
    inherit (cli) version;
    passthru = {
      inherit cli agentd libkrunfw;
      # Consumers use this canonical filtered workspace for matching SDK builds.
      inherit (cli) src;
    };
    meta = cli.meta // {
      description = "Microsandbox CLI, static guest agent and source-built firmware";
      license = with pkgs.lib.licenses; [
        asl20
        lgpl21Only
        gpl2Only
      ];
    };
  }
  ''
    # Use a regular copy: current_exe must resolve inside this complete
    # runtime, so sibling lib/ discovery cannot resolve to the CLI-only output.
    install -Dm755 ${cli}/bin/msb $out/bin/msb
    install -Dm755 ${agentd}/libexec/agentd $out/libexec/agentd
    install -Dm755 ${libkrunfw}/lib/libkrunfw.so.5.6.1 $out/lib/libkrunfw.so.5.6.1
    ln -s libkrunfw.so.5.6.1 $out/lib/libkrunfw.so.5
    ln -s libkrunfw.so.5 $out/lib/libkrunfw.so
    mkdir -p $out/share/libkrunfw
    for name in kernel.config kernel.release kernel-source.sha256 kernel-patches.sha256; do
      install -m644 ${libkrunfw}/share/libkrunfw/$name $out/share/libkrunfw/$name
    done
  ''
