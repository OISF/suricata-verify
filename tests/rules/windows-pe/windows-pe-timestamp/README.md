Tests the `timestamp` option of the `windows_pe` keyword against the
TimeDateStamp field from the COFF header. All test PEs share the same
timestamp value. Verifies exact match, greater-than, range comparisons, and
a negative test for values beyond the actual timestamp.
