#!/usr/bin/env python3
"""ICMPv4 dest-unreach errors embedding an HTTP flow's SYN: one sent to the SYN's
source (10.0.0.254 -> 10.0.0.1), one sent between two unrelated hosts
(1.2.3.4 -> 5.6.7.8). Both come after the handshake and before any app-layer data."""
import sys
from scapy.all import IP, TCP, ICMP, Raw, Ether, wrpcap

out = sys.argv[1]
C, S = "10.0.0.1", "10.0.0.2"
cp, sp, ci, si = 40000, 80, 1000, 5000
req = b"GET / HTTP/1.1\r\nHost: example\r\n\r\n"
resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
syn = IP(src=C, dst=S) / TCP(sport=cp, dport=sp, flags="S", seq=ci)
pk = [
    syn,
    IP(src=S, dst=C) / TCP(sport=sp, dport=cp, flags="SA", seq=si, ack=ci + 1),
    IP(src=C, dst=S) / TCP(sport=cp, dport=sp, flags="A", seq=ci + 1, ack=si + 1),
    IP(src="10.0.0.254", dst=C) / ICMP(type=3, code=1) / bytes(syn)[:28],
    IP(src="1.2.3.4", dst="5.6.7.8") / ICMP(type=3, code=1) / bytes(syn)[:28],
    IP(src=C, dst=S) / TCP(sport=cp, dport=sp, flags="PA", seq=ci + 1, ack=si + 1) / Raw(req),
    IP(src=S, dst=C) / TCP(sport=sp, dport=cp, flags="PA", seq=si + 1, ack=ci + 1 + len(req)) / Raw(resp),
    IP(src=C, dst=S) / TCP(sport=cp, dport=sp, flags="A", seq=ci + 1 + len(req), ack=si + 1 + len(resp)),
    IP(src=S, dst=C) / TCP(sport=sp, dport=cp, flags="FA", seq=si + 1 + len(resp), ack=ci + 1 + len(req)),
    IP(src=C, dst=S) / TCP(sport=cp, dport=sp, flags="FA", seq=ci + 1 + len(req), ack=si + 2 + len(resp)),
    IP(src=S, dst=C) / TCP(sport=sp, dport=cp, flags="A", seq=si + 2 + len(resp), ack=ci + 2 + len(req)),
]
frames = []
for i, p in enumerate(pk):
    f = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02") / p
    f.time = 1700000000 + i * 0.001
    frames.append(f)
wrpcap(out, frames)
