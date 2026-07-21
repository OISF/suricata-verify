Tests the `file_version` option of the `windows_pe` keyword against the
FileVersion from the PE `VERSIONINFO` resource. The fixture carries two PEs
with versions 6.1.7601.17514 and 10.0.19041.1. Verifies numeric `<`/`>`
comparisons, an inclusive range, and the `executable.file_version` EVE field.
Files without a version resource do not match a `file_version` filter.

The `input.pcap` is a frozen fixture; see the `pe-keyword-validation` bundle's
`common/pcap-generators/gen_pe_fixtures.py` for how it is generated.
