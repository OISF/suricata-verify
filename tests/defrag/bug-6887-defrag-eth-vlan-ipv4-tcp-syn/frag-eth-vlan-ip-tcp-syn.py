#!/usr/bin/env python
from scapy.all import *

pkts = []

packet = Ether(dst='05:04:03:02:01:00', src='00:01:02:03:04:05')/Dot1Q(vlan=6)/IP(src='1.1.1.1', dst='2.2.2.2')/TCP(dport=8080,sport=12345,flags='S',seq=1,options=[('WScale', 14)])

frags = fragment(packet,fragsize=8)
wrpcap('frag-eth-vlan-ip-tcp-syn.pcap', frags)
