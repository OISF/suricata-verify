#!/usr/bin/env python3
# Generate input.pcap: one UDP flow of 12 packets, all from the same src IP so
# every packet runs the dataset lookup that builds the JSON alert info, and all
# of them end in a drop verdict. The packets after the first one make sure the
# engine recycles packets (and therefore reinitializes the packet alerts) while
# a drop with alert info is still held by the packet.
from scapy.all import Ether, IP, UDP, Raw, wrpcap

eth = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02")
pkts = []
for i in range(12):
    pkts.append(
        eth / IP(src="1.2.3.4", dst="5.6.7.8") / UDP(sport=40000, dport=9999)
        / Raw(b"q=req%02d" % i)
    )

wrpcap("input.pcap", pkts)
