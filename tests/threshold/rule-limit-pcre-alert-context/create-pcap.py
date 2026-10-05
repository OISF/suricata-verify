#!/usr/bin/env python3
# Generate the input pcap: one flow (same 5-tuple for every packet) with 20
# requests, each carrying a different value for the pcre "alert:" capture.
from scapy.all import Ether, IP, UDP, Raw, wrpcap

eth = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02")
pkts = []
for i in range(20):
    pkts.append(
        eth / IP(src="1.2.3.4", dst="5.6.7.8") / UDP(sport=40000, dport=9999)
        / Raw(b"id=abc%02d" % i)
    )

wrpcap("input.pcap", pkts)
