#!/usr/bin/env python
from scapy.all import *

pkts = []

data = ('\x38\x35\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01\x00')

pkts += Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/ \
    Dot1Q(vlan=6)/ \
    IP(dst='1.2.3.4', src='5.6.7.8')/UDP(dport=53)/Raw(load=data)

wrpcap('input.pcap', pkts)
