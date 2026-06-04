# LLMNR Authority and Additional Sections Test

This test specifically verifies that LLMNR authority and additional section sticky buffers work correctly.

The test includes:
1. An NXDOMAIN response with SOA record in authority section
2. A full response with answer, authority, and additional sections

Tests verify:
- `llmnr.authorities.rrname` matches authority section names
- `llmnr.additionals.rrname` matches additional section names
- Authority and additional sections are properly parsed in LLMNR responses

PCAP created with `create_pcap.py` script.
