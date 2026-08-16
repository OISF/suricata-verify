#!/usr/bin/env python3
"""Build input.pcap for the bug-8862 tests.

Packet 1 is the frame from the report: an ICMPv4 destination-unreachable
message, byte for byte as the ticket describes it except that the header
checksums are filled in rather than left zero. Its embedded 5-tuple matches
no flow, so the hash lookup finds nothing and FlowCreateCheck() then refuses
to create a flow for it. See ../README.md for why that leaves the packet
inspectable but flowless.

Packets 2 and 3 are an ordinary UDP exchange that does get a flow. The
request carries "EVIL" as well, so the same signatures run against a packet
with a flow and the captures have somewhere to go.

Usage: python3 writepcap.py [input.pcap]
"""

import sys

from scapy.all import Ether, ICMP, IP, Raw, UDP, wrpcap

inner = (
    IP(src="9.9.9.9", dst="8.8.8.8", id=2, ttl=64)
    / UDP(sport=57005, dport=48879)
    / Raw(b"EVIL")
)
icmp_error = (
    Ether(src="02:02:02:02:02:02", dst="ff:ff:ff:ff:ff:ff")
    / IP(src="1.2.3.4", dst="5.6.7.8", id=1, ttl=64)
    / ICMP(type=3, code=1)
    / inner
)

udp_to_server = (
    Ether(src="02:02:02:02:02:03", dst="02:02:02:02:02:04")
    / IP(src="10.0.0.1", dst="10.0.0.2")
    / UDP(sport=1234, dport=5678)
    / Raw(b"hello EVIL world")
)
udp_to_client = (
    Ether(src="02:02:02:02:02:04", dst="02:02:02:02:02:03")
    / IP(src="10.0.0.2", dst="10.0.0.1")
    / UDP(sport=5678, dport=1234)
    / Raw(b"bye")
)

packets = [icmp_error, udp_to_server, udp_to_client]
for i, packet in enumerate(packets):
    packet.time = 1754400000 + i

wrpcap(sys.argv[1] if len(sys.argv) > 1 else "input.pcap", packets)
