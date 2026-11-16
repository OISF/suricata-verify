Tests the `section_name` option of the `windows_pe` keyword, which matches
against individual section names in the PE section table. Matching is
case-insensitive.

Uses two PEs: a "packed" PE with sections .text, .UPX0, .UPX1, .rsrc; and
a "normal" PE with sections .text, .rdata, .data, .rsrc. Tests matching
unique sections (.UPX0, .rdata, .data), shared sections (.text, .rsrc),
a non-existent section (.reloc), case insensitivity (.upx0 vs .UPX0), and
combination with `arch`.
