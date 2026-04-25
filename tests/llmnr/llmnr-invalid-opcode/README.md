# LLMNR Invalid Opcode Test

This test verifies that the LLMNR parser correctly detects and alerts on invalid opcode values.

The test sends an LLMNR query with opcode=15 (invalid), which should trigger:
- An anomaly event with `llmnr.invalid_opcode`
- An alert from the rule matching the app-layer event

PCAP created with `create_pcap.py` script.
