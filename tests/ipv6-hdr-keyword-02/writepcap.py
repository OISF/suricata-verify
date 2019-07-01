#!/usr/bin/env python
from scapy.all import *

pkts = []

pkts += Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/ \
    Dot1Q(vlan=6)/ \
    IPv6()/IPv6ExtHdrHopByHop()/IPv6ExtHdrDestOpt()/IPv6ExtHdrRouting()/UDP(dport=80)

wrpcap('input.pcap', pkts)
