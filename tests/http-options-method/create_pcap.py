#!/usr/bin/env python3

import time

from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

http_request = """OPTIONS * HTTP/1.1\r
Host: example.com\r
User-Agent: Mozilla/5.0\r
Accept: */*\r
Connection: close\r
\r
"""

http_response = """HTTP/1.1 200 OK\r
Date: Mon, 01 Jan 2024 12:00:00 GMT\r
Server: Apache/2.4\r
Allow: GET, HEAD, POST, OPTIONS, DELETE\r
Content-Length: 0\r
Connection: close\r
\r
"""

packets = []

src_ip = "192.168.1.10"
dst_ip = "192.168.1.20"
src_port = 54321
dst_port = 80

syn = (
    Ether()
    / IP(src=src_ip, dst=dst_ip)
    / TCP(sport=src_port, dport=dst_port, flags="S", seq=1000)
)
packets.append(syn)

syn_ack = (
    Ether()
    / IP(src=dst_ip, dst=src_ip)
    / TCP(sport=dst_port, dport=src_port, flags="SA", seq=2000, ack=1001)
)
packets.append(syn_ack)

ack = (
    Ether()
    / IP(src=src_ip, dst=dst_ip)
    / TCP(sport=src_port, dport=dst_port, flags="A", seq=1001, ack=2001)
)
packets.append(ack)

request_pkt = (
    Ether()
    / IP(src=src_ip, dst=dst_ip)
    / TCP(sport=src_port, dport=dst_port, flags="PA", seq=1001, ack=2001)
    / http_request
)
packets.append(request_pkt)

ack2 = (
    Ether()
    / IP(src=dst_ip, dst=src_ip)
    / TCP(
        sport=dst_port,
        dport=src_port,
        flags="A",
        seq=2001,
        ack=1001 + len(http_request),
    )
)
packets.append(ack2)

response_pkt = (
    Ether()
    / IP(src=dst_ip, dst=src_ip)
    / TCP(
        sport=dst_port,
        dport=src_port,
        flags="PA",
        seq=2001,
        ack=1001 + len(http_request),
    )
    / http_response
)
packets.append(response_pkt)

ack3 = (
    Ether()
    / IP(src=src_ip, dst=dst_ip)
    / TCP(
        sport=src_port,
        dport=dst_port,
        flags="A",
        seq=1001 + len(http_request),
        ack=2001 + len(http_response),
    )
)
packets.append(ack3)

fin1 = (
    Ether()
    / IP(src=dst_ip, dst=src_ip)
    / TCP(
        sport=dst_port,
        dport=src_port,
        flags="FA",
        seq=2001 + len(http_response),
        ack=1001 + len(http_request),
    )
)
packets.append(fin1)

ack4 = (
    Ether()
    / IP(src=src_ip, dst=dst_ip)
    / TCP(
        sport=src_port,
        dport=dst_port,
        flags="A",
        seq=1001 + len(http_request),
        ack=2002 + len(http_response),
    )
)
packets.append(ack4)

fin2 = (
    Ether()
    / IP(src=src_ip, dst=dst_ip)
    / TCP(
        sport=src_port,
        dport=dst_port,
        flags="FA",
        seq=1001 + len(http_request),
        ack=2002 + len(http_response),
    )
)
packets.append(fin2)

ack5 = (
    Ether()
    / IP(src=dst_ip, dst=src_ip)
    / TCP(
        sport=dst_port,
        dport=src_port,
        flags="A",
        seq=2002 + len(http_response),
        ack=1002 + len(http_request),
    )
)
packets.append(ack5)

wrpcap("input.pcap", packets)
print("Created pcap file")
