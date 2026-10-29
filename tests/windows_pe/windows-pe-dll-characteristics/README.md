Tests the `dll_characteristics` option of the `windows_pe` keyword. All test
PEs have dll_characteristics 0x8500 (HIGH_ENTROPY_VA | NX_COMPAT | NO_SEH).
Verifies exact hex match, decimal equivalent, range comparison, and a
negative test for the DYNAMIC_BASE (ASLR) flag which is not set.
