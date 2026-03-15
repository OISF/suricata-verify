# Windows PE Detection Tests

Verification tests for the `windows_pe` detection keyword, which identifies
and inspects Windows Portable Executable (PE) files in network traffic.

## Keyword Options

The `windows_pe` keyword supports the following options, each covered by one
or more test directories below:

| Option              | Test Directory                  | Description                          |
|---------------------|---------------------------------|--------------------------------------|
| *(bare keyword)*    | `windows-pe-basic`              | Match any valid PE file              |
| `arch`              | `windows-pe-machine-type`       | COFF machine type (x86, x86_64, arm)|
| `sections`          | `windows-pe-sections`           | Number of sections                   |
| `size`              | `windows-pe-size`               | SizeOfImage field                    |
| `entry_point`       | `windows-pe-entry-point`        | Entry point RVA                      |
| `subsystem`         | `windows-pe-subsystem`          | Subsystem ID (GUI, Console, etc.)    |
| `characteristics`   | `windows-pe-characteristics`    | COFF characteristics bitmask         |
| `dll_characteristics`| `windows-pe-dll-characteristics`| DLL characteristics bitmask         |
| `pe_type`           | `windows-pe-pe-type`            | PE32 vs PE32+ (PE64)                 |
| `timestamp`         | `windows-pe-timestamp`          | TimeDateStamp from COFF header       |
| `checksum`          | `windows-pe-checksum`           | Checksum from Optional header        |
| `size_of_headers`   | `windows-pe-size-of-headers`    | SizeOfHeaders from Optional header   |
| `num_imports`       | `windows-pe-num-imports`        | Number of imported DLLs              |
| `num_exports`       | `windows-pe-num-exports`        | Number of exported functions         |
| `section_name`      | `windows-pe-section-name`       | Match a section by name              |
| `section_wx`        | `windows-pe-section-wx`         | Detect Write+Execute sections        |
| `export_name`       | `windows-pe-export-name`        | PE export directory DLL name         |
| *(DLL import)*      | `windows-pe-import`             | Match imported DLL names             |
| *(combined)*        | `windows-pe-combined`           | Multiple options in one keyword      |
| *(combined)*        | `windows-pe-new-fields-combined`| Combined new-field checks            |

## Test Structure

Each test directory contains:

- `test.yaml` — expected alert counts and EVE field checks
- `test.rules` — Suricata rules exercising the keyword option(s)
- `input.pcap` or `multi_pe.pcap` — PCAP with PE files delivered over HTTP
- `gen_pcap.py` *(optional)* — scapy script to regenerate the PCAP

## PCAP Generation

Tests that use `gen_pcap.py` build minimal but structurally valid PE32 files
and deliver them inside full TCP/HTTP sessions (3-way handshake, segmented
response, FIN teardown) so that Suricata's HTTP app-layer and file extraction
pipeline process them correctly.
