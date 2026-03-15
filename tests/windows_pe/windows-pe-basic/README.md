Basic test for the `windows_pe` keyword. Verifies that bare `windows_pe`
detection (with `arch x86`) matches all five PE files in the PCAP, and that
a negative test with a non-matching content pattern produces zero alerts.
