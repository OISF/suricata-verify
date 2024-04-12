#!/usr/bin/env python
from scapy.all import *

pkts = []

data = 'A' * 1000
packet = Ether(dst='05:04:03:02:01:00', src='00:01:02:03:04:05')/Dot1Q(vlan=6)/IPv6()/IPv6ExtHdrFragment()/TCP(dport=8080,sport=12345,flags='A',seq=1)/data

frags = fragment6(packet,512)
wrpcap('frag-eth-vlan-ipv6-tcp.pcap', frags)
