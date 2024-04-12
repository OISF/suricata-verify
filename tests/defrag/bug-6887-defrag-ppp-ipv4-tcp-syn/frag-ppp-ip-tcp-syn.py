#!/usr/bin/env python
from scapy.all import *

pkts = []

packet = PPP()/IP(src='1.1.1.1', dst='2.2.2.2')/TCP(dport=8080,sport=12345,flags='S',seq=1,options=[('WScale', 14)])

frags = fragment(packet,fragsize=8)
wrpcap('frag-ppp-ip-tcp-syn.pcap', frags)
