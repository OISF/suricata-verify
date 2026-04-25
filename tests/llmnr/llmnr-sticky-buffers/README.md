# LLMNR Sticky Buffer Test

This test verifies that LLMNR sticky buffers work correctly.

The test includes:
- `llmnr.queries.rrname`: matches query names
- `llmnr.answers.rrname`: matches answer names
- `llmnr.authorities.rrname`: matches authority section names
- `llmnr.additionals.rrname`: matches additional section names
- `llmnr.response.rrname`: matches any name in response

The test also verifies that multiple content matches work within sticky buffers.

PCAP created with `create_pcap.py` script.
