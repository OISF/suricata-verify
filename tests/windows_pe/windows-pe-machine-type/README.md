Tests the `arch` option of the `windows_pe` keyword against the COFF Machine
field. All test PEs are x86 (Machine 0x014C). Verifies matching `arch x86`,
and negative tests for `arch x86_64` and `arch arm` which should not match.
