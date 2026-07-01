#!/usr/bin/env python
"""Generate a tiny pcap with a single TCP packet carrying a deterministic
payload that the test rule matches on.

Used by the pcap-file-stdin SV test, which feeds this pcap to Suricata via
stdin to exercise the non-seekable file handling fix from OISF/suricata
PR #15384 and Bug #8464.
"""
from scapy.all import IP, TCP, wrpcap

payload = b"BUG8464-pcap-file-stdin-regress\n"
packet = IP(src='1.1.1.1', dst='2.2.2.2', id=8464) / TCP(
        sport=12345, dport=8080, flags='PA', seq=1) / payload

wrpcap('input.pcap', [packet])
