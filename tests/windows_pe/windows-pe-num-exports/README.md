Tests the `num_exports` option of the `windows_pe` keyword, which matches
against the number of exported functions in the PE export directory.

Uses three PEs: a DLL with 5 exports, a DLL with 1 export, and an EXE with
no export directory (0 exports). Tests exact match (0, 1, 5), greater-than,
less-than comparisons, a negative test for non-existent count (99), and
combination with `arch`.
