{ lockFile }:
{
  inherit lockFile;
  # All msb_krun crates share this locked Git source; one hash covers the checkout.
  outputHashes."msb_krun-0.1.34" = "sha256-p6DcL57AXPVjMLe6l7iiLkLSVlCOFdfmwcGe2Xan/PA=";
  outputHashes."msb-vm-memory-0.18.0-msb.1" = "sha256-aZc0jr3XqrZHyLnQz/NwjUCfsxy7YNAsqjVWrqHYH30=";
}
