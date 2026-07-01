#!/usr/bin/env python3

import time

from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

sip_request = """OPTIONS sip:test@example.com SIP/2.0\r
Via: SIP/2.0/UDP 192.168.1.10:5060;branch=z9hG4bK1234567890\r
From: <sip:alice@example.com>;tag=1234\r
To: <sip:test@example.com>\r
Call-ID: 1234567890@192.168.1.10\r
CSeq: 1 OPTIONS\r
Contact: <sip:alice@192.168.1.10:5060>\r
Accept: application/sdp\r
Content-Length: 0\r
\r
"""

sip_response = """SIP/2.0 200 OK\r
Via: SIP/2.0/UDP 192.168.1.10:5060;branch=z9hG4bK1234567890\r
From: <sip:alice@example.com>;tag=1234\r
To: <sip:test@example.com>;tag=5678\r
Call-ID: 1234567890@192.168.1.10\r
CSeq: 1 OPTIONS\r
Content-Length: 0\r
\r
"""

packets = []

request_pkt = (
    Ether()
    / IP(src="192.168.1.10", dst="192.168.1.20")
    / UDP(sport=5060, dport=5060)
    / sip_request
)
packets.append(request_pkt)

response_pkt = (
    Ether()
    / IP(src="192.168.1.20", dst="192.168.1.10")
    / UDP(sport=5060, dport=5060)
    / sip_response
)
packets.append(response_pkt)

wrpcap("input.pcap", packets)
print("Created pcap file")
