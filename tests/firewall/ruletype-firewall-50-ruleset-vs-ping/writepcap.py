#!/usr/bin/env python
from scapy.all import *
pkts = []
pkts += Ether(dst='05:04:03:02:01:00', src='00:01:02:03:04:05')/IP(src="10.0.0.1", dst="1.2.3.4")/ICMP(type=8, code=0, seq=123)
pkts += Ether(dst='05:04:03:02:01:00', src='00:01:02:03:04:05')/IP(src="10.0.0.1", dst="1.2.3.4")/ICMP(type=8, code=1, seq=321)
pkts += Ether(src='05:04:03:02:01:00', dst='00:01:02:03:04:05')/IP(dst="10.0.0.1", src="1.2.3.4")/ICMP(type=0, code=0, seq=123)
wrpcap('icmp-ping-plus-weird-code.pcap', pkts, snaplen=262144)
