#!/usr/bin/env python3
from scapy.all import Ether, IP, TCP, wrpcap

packet = (
    Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
    / IP(src="10.0.0.1", dst="10.0.0.2")
    / TCP(sport=12345, dport=80, flags="S", seq=1)
)
packet.time = 1.0
wrpcap("input.pcap", [packet])
