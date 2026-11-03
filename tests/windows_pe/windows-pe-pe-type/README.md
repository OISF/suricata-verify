Tests the `pe_type` option of the `windows_pe` keyword, which identifies
the PE format variant from the Optional header magic value. All test PEs
are PE32 (magic 0x10B). Verifies matching `pe_type pe32`, and negative
tests for `pe_type pe32+` and `pe_type pe64`.
