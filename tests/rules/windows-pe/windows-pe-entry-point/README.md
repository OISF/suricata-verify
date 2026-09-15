Tests the `entry_point` option of the `windows_pe` keyword against the
AddressOfEntryPoint RVA. All test PEs have entry_point 0x1000 (4096).
Verifies greater-than, less-than, range comparisons, and a negative test
for unrealistically high values.
