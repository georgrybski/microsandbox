{ pkgs }:
let
  guestCid = pkgs.pkgsStatic.stdenv.mkDerivation {
    pname = "microsandbox-guest-cid-probe";
    version = "1";
    dontUnpack = true;
    buildPhase = ''
      $CC -O2 -Wall -Wextra -Werror ${../../scripts/smoke/cli/guest-cid.c} -o guest-cid
    '';
    installPhase = ''
      install -Dm755 guest-cid $out/bin/guest-cid
    '';
  };
  rootfs = pkgs.runCommand "microsandbox-runtime-smoke-rootfs" { } ''
    mkdir -p $out/bin $out/etc $out/tmp $out/root
    cp ${pkgs.pkgsStatic.busybox}/bin/busybox $out/bin/busybox
    cp ${guestCid}/bin/guest-cid $out/bin/guest-cid
    for applet in sh cat uname printf sync mkdir sleep; do
      ln -s busybox $out/bin/$applet
    done
    printf 'root:x:0:0:root:/root:/bin/sh\n' > $out/etc/passwd
    printf 'root:x:0:\n' > $out/etc/group
    chmod 1777 $out/tmp
  '';
in
pkgs.dockerTools.buildLayeredImage {
  name = "microsandbox-runtime-smoke";
  tag = "test";
  # The CLI archive loader consumes a plain tar stream, not gzip framing.
  compressor = "none";
  contents = [ rootfs ];
  config = {
    Cmd = [ "/bin/sh" ];
    Env = [ "PATH=/bin" ];
    WorkingDir = "/root";
  };
  maxLayers = 2;
}
