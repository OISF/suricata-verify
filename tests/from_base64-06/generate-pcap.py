#!/usr/bin/env python3
"""
Generate input.pcap for the from_base64-06 (error passthrough) test.

Three HTTP POST requests:
  1. Invalid base64 containing "not-base64" -- SID 1 should alert
  2. Valid base64 decoding to "decoded-content" -- SID 2 should alert
  3. Invalid base64 NOT containing "missing" -- SID 3 should not alert
"""

import base64
from scapy.all import IP, TCP, Raw, wrpcap

SRC = "192.168.1.100"
DST = "192.168.1.200"
DPORT = 80

def http_post(payload: bytes) -> bytes:
    return (
        b"POST /data HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Content-Length: " + str(len(payload)).encode() + b"\r\n"
        b"\r\n" + payload
    )

def tcp_session(sport: int, payload: bytes) -> list:
    seq, ack = 1000, 2000
    pkts = []

    pkts.append(IP(src=SRC, dst=DST) / TCP(sport=sport, dport=DPORT, flags="S", seq=seq))
    pkts.append(IP(src=DST, dst=SRC) / TCP(sport=DPORT, dport=sport, flags="SA", seq=ack, ack=seq + 1))
    seq += 1
    pkts.append(IP(src=SRC, dst=DST) / TCP(sport=sport, dport=DPORT, flags="A", seq=seq, ack=ack + 1))
    ack += 1

    data = http_post(payload)
    pkts.append(IP(src=SRC, dst=DST) / TCP(sport=sport, dport=DPORT, flags="PA", seq=seq, ack=ack) / Raw(load=data))
    seq += len(data)

    pkts.append(IP(src=DST, dst=SRC) / TCP(sport=DPORT, dport=sport, flags="A", seq=ack, ack=seq))
    pkts.append(IP(src=SRC, dst=DST) / TCP(sport=sport, dport=DPORT, flags="FA", seq=seq, ack=ack))
    seq += 1
    pkts.append(IP(src=DST, dst=SRC) / TCP(sport=DPORT, dport=sport, flags="FA", seq=ack, ack=seq))
    ack += 1
    pkts.append(IP(src=SRC, dst=DST) / TCP(sport=sport, dport=DPORT, flags="A", seq=seq, ack=ack))

    return pkts

cases = [
    (12301, b"!!!not-base64!!!"),                           # SID 1: invalid, contains "not-base64"
    (12302, base64.b64encode(b"decoded-content")),          # SID 2: valid, decodes to "decoded-content"
    (12303, b"!!!invalid-but-no-useful-content!!!"),        # SID 3: invalid, no "missing"
]

packets = []
for sport, payload in cases:
    packets.extend(tcp_session(sport, payload))

wrpcap("input.pcap", packets)
print("Wrote input.pcap")
for sport, payload in cases:
    print(f"  port {sport}: {payload}")
