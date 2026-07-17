Tests combinations of the newer metadata fields: `pe_type`, `timestamp`,
`checksum`, `size_of_headers`, `num_imports`, and `num_exports`. Verifies
that multiple new-style options work correctly together in a single keyword
instance, including a negative test for `pe_type pe32+` on PE32 binaries.
