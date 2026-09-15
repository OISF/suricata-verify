Tests the `export_name` option of the `windows_pe` keyword, which matches
against the DLL name stored in the PE export directory.

Uses two PEs: a DLL with export name "mylib.dll" (3 exported functions) and
a plain EXE with no export directory. Tests include exact match, negative
match, case insensitivity (the keyword lowercases both sides), combination
with `arch` and `num_exports`, and a wrong-arch negative test.
