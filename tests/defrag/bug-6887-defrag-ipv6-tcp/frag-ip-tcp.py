#!/usr/bin/env python
from scapy.all import *

pkts = []

data = 'A' * 1000
packet = IPv6()/IPv6ExtHdrFragment()/TCP(dport=8080,sport=12345,flags='A',seq=1)/data

frags = fragment6(packet,512)
wrpcap('frag-ip-tcp.pcap', frags)
