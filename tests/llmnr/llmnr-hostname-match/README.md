# LLMNR Hostname Matching Test

This test verifies that LLMNR traffic can be matched using Suricata rules.

The test includes:
1. Matching on specific hostnames in LLMNR queries using content matching
2. Matching on specific IP addresses in LLMNR responses
3. Using flow direction to distinguish between queries and responses

PCAP created with `create_pcap.py` script.
