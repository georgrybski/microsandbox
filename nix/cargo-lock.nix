{ lockFile }:
{
  inherit lockFile;
  # All msb_krun crates share this locked Git source; one hash covers the checkout.
  outputHashes."msb_krun-0.1.32" = "sha256-Wb5oaUkmp68FnrOVMxVimevXaWxfAPo34qVbuyLvKM0=";
}
