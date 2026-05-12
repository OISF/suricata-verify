#!/usr/bin/env python3
from scapy.all import Ether, IP, IPv6, UDP, Raw, wrpcap

eth = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02")
pkts = [
    eth/IP(src="1.2.3.4", dst="5.6.7.8")/UDP(sport=1111, dport=2222)/Raw(b"SETFLOW"),
    eth/IPv6(src="102:304::", dst="506:708::")/UDP(sport=1111, dport=2222)/Raw(b"HITFLOW"),
]
wrpcap("input.pcap", pkts)
