#!/usr/bin/env python3
# One UDP flow of 6 datagrams carrying "DFMATCH"; datagrams 3 and 4
# also carry "PASSME".
from scapy.all import Ether, IP, UDP, Raw, wrpcap

eth = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02")
pkts = []
for i in range(1, 7):
    payload = b"DFMATCH%d" % i
    if i in (3, 4):
        payload += b" PASSME"
    pkts.append(eth / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=40000, dport=9999) / Raw(payload))

for n, p in enumerate(pkts):
    p.time = 1700000000 + n * 0.01

wrpcap("input.pcap", pkts)
