Tests the `version_info` option of the `windows_pe` keyword against the
StringFileInfo strings of the PE VERSIONINFO resource. The fixture carries two
PEs with distinct CompanyName / ProductName / OriginalFilename / FileVersion
strings. Verifies case-insensitive substring matching, keyed `Key: Value`
matching, `/pattern/flags` regex (including a `.scr` masquerade), the AND
semantics of multiple `version_info` options versus the OR semantics of a single
alternation regex, a negative test, and the `executable.version_info` EVE object.

The `input.pcap` is a frozen fixture; see the `pe-keyword-validation` bundle's
`common/pcap-generators/gen_pe_fixtures.py` for how it is generated.
