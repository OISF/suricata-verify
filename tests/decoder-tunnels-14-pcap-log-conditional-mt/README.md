# Description

Conditional pcap logging with the multi-tenant tunnel selector and
`multi-detect.default: no`.

Every ruleset, tenants and default, has rules for tunnel 2, the unknown
tunnel and not tunneled traffic. Only tunnel 2 is inspected, by tenant 2,
so only its alerting flow is logged, not the frames with the same inner
5-tuple from tunnel 1. The unknown tunnel and not tunneled traffic match
no mapping and the default tenant has no rules.

# Ticket

https://redmine.openinfosecfoundation.org/issues/7674

# PCAP

Crafted with scapy script.py, which also writes the expected pcap-log file:
frames 1 and 5 of input.pcap.

The same inner UDP 5-tuple is sent twice over each of:
- VXLAN VNI 123 from 192.168.1.3, configured as tunnel id 2
- ERSPAN II session 321 from 192.168.1.4, configured as tunnel id 1
- VXLAN VNI 999 from 192.168.1.3, not configured
- no tunnel
