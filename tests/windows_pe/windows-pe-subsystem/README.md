Tests the `subsystem` option of the `windows_pe` keyword against the
Subsystem field from the Optional header. All test PEs use subsystem 3
(WINDOWS_CUI / Console). Verifies correct matching for Console (3) and
negative tests for GUI (2) and Native (1).
