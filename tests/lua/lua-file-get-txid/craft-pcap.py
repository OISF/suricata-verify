#!/usr/bin/env python3
# An HTTP file download (response body with a Content-Disposition
# filename) so the lua file output logs the file: the response body is
# extracted as the file "download.bin" of the first http transaction.
from scapy.all import IP, TCP, Raw, wrpcap, Ether

def ip(s, d):
    return Ether() / IP(src=s, dst=d)

body = b"0123456789abcdef"  # 16 bytes
req = b"GET /download.bin HTTP/1.1\r\nHost: example.com\r\n\r\n"
resp = (b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Disposition: attachment; filename=\"download.bin\"\r\n"
        b"Content-Length: 16\r\n"
        b"\r\n" + body)

pkts = [
    ip("10.0.0.1", "10.0.0.2") / TCP(sport=49152, dport=80, flags="S", seq=1000),
    ip("10.0.0.2", "10.0.0.1") / TCP(sport=80, dport=49152, flags="SA", seq=5000, ack=1001),
    ip("10.0.0.1", "10.0.0.2") / TCP(sport=49152, dport=80, flags="A", seq=1001, ack=5001),
    ip("10.0.0.1", "10.0.0.2") / TCP(sport=49152, dport=80, flags="PA", seq=1001, ack=5001) /
        Raw(load=req),
    ip("10.0.0.2", "10.0.0.1") / TCP(sport=80, dport=49152, flags="PA", seq=5001, ack=1001 + len(req)) /
        Raw(load=resp),
    ip("10.0.0.1", "10.0.0.2") / TCP(sport=49152, dport=80, flags="A", seq=1001 + len(req),
        ack=5001 + len(resp)),
    ip("10.0.0.1", "10.0.0.2") / TCP(sport=49152, dport=80, flags="F", seq=1001 + len(req),
        ack=5001 + len(resp)),
    ip("10.0.0.2", "10.0.0.1") / TCP(sport=80, dport=49152, flags="FA", seq=5001 + len(resp),
        ack=1002 + len(req)),
]
wrpcap("input.pcap", pkts)
print("wrote input.pcap (%d packets)" % len(pkts))
