Tests the `sections` option of the `windows_pe` keyword against the
NumberOfSections field from the COFF header. All test PEs have 1 section.
Verifies greater-than, less-than, and range comparisons, confirming that
queries for >2 and 2-11 correctly produce zero matches.
