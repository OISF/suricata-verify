Tests the `characteristics` option of the `windows_pe` keyword against the
COFF characteristics field. All test PEs have characteristics 0x0102
(EXECUTABLE_IMAGE). Verifies exact match, range comparisons, and a negative
test for the DLL flag (0x2000) which is not set.
