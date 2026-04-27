Tests the `num_imports` option of the `windows_pe` keyword against the
number of imported DLLs. The test PEs have no import directory
(num_imports 0). Verifies exact zero match and a negative `>0` test.
