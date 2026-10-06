Tests the `size_of_headers` option of the `windows_pe` keyword against the
SizeOfHeaders field from the Optional header. All test PEs have
size_of_headers 512 (0x200). Verifies exact match, a negative `>1024`
test, and a range comparison (256-1024).
