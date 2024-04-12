#!/usr/bin/env python
from scapy.all import *

pkts = []

data = 'A' * (65535 - 20 - 8)
encap = IP(src='1.1.1.1', dst='2.2.2.2')/UDP(sport=11111,dport=9999)/data
frags = fragment(encap, 64)
for f in frags:
    pkts += Ether()/IP(src='7.7.7.7', dst='9.9.9.9')/GRE(proto=0x880b)/PPP()/f
wrpcap('eth-ip-gre-ppp-max-ip-packet.pcap', pkts, snaplen=262144)
