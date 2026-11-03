Tests the `checksum` option of the `windows_pe` keyword against the Optional
header Checksum field. All test PEs have checksum 0 (typical for
non-production binaries). Verifies exact match and a negative `>0` test.
