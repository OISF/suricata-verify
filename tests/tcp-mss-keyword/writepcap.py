#!/usr/bin/env python
from scapy.all import *

pkts = []

pkts += Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/ \
    Dot1Q(vlan=6)/ \
    IP(dst='255.255.255.255', src='192.168.0.1')/TCP(dport=80,flags="S",options=[("MSS", 8)])

wrpcap('input.pcap', pkts)
