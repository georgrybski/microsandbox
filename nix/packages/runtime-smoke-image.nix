{ pkgs }:
let
  rootfs = pkgs.runCommand "microsandbox-runtime-smoke-rootfs" { } ''
    mkdir -p $out/bin $out/etc $out/tmp $out/root
    cp ${pkgs.pkgsStatic.busybox}/bin/busybox $out/bin/busybox
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
