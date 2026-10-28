#!/usr/bin/env python3
"""Write input.pcap: three copies of the HTTP flow of
ruletype-firewall-22-http-accept-tx-with-td on the same 5-tuple, each two
hours after the previous one. The flow has timed out when the next copy's SYN
arrives, so the worker evicts and frees it while looking up that SYN, before
inspecting the packet; the flow manager's timing plays no part.

    python3 writepcap.py ../ruletype-firewall-22-http-accept-tx-with-td/http-sticky-server-s8.pcap input.pcap
"""
import sys

from scapy.all import rdpcap, wrpcap

src, dst = sys.argv[1], sys.argv[2]
base = rdpcap(src)
out = []
for i in range(3):
    for pkt in base:
        p = pkt.copy()
        p.time = pkt.time + i * 7200
        out.append(p)
wrpcap(dst, out)
