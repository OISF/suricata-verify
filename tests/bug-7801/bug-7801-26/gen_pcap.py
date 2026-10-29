#!/usr/bin/env python3
"""Generate PCAP for byte variables in a rule inspected on the packet path.

One UDP packet, TTL 64, payload 0x0a "x": UDP length 8 + 2 = 10.

Rule: udp.hdr produces ulen = 10 with byte_extract, ipv4.hdr produces ttl = 64
with byte_math, and the payload's first byte is compared with ulen.

No transaction is involved, so nothing is kept between packets; the rule only
needs its two variables to hold different slots. While byte_extract and
byte_math each numbered their own, both had local_id 0, ttl overwrote ulen and
the payload byte was compared with 64: 0 alerts. With one counter per
signature: 1 alert.
"""
from scapy.all import IP, UDP, Raw, wrpcap

wrpcap("input.pcap", [IP(src="10.1.1.1", dst="10.1.1.2", ttl=64) /
                      UDP(sport=5000, dport=6000) / Raw(load=b"\x0ax")])
