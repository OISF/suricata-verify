Tests the `size` option of the `windows_pe` keyword against the
SizeOfImage field from the Optional header. The five test PEs have varying
SizeOfImage values (512, 1024, 512, 4096, 2048). Verifies greater-than,
range comparisons, and negative tests for unrealistically large values.
