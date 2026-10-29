#!/usr/bin/env python3
# Generate input.pcap: one UDP flow of 12 packets, each carrying a different
# value for the pcre "alert:" capture. Every packet ends in a drop verdict, so
# the packet alert kept for the drop log gets a fresh copy of the captured
# value 12 times while the flow keeps being processed.
from scapy.all import Ether, IP, UDP, Raw, wrpcap

eth = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02")
pkts = []
for i in range(12):
    pkts.append(
        eth / IP(src="1.2.3.4", dst="5.6.7.8") / UDP(sport=40000, dport=9999)
        / Raw(b"q=req%02d" % i)
    )

wrpcap("input.pcap", pkts)
