#!/usr/bin/env python
from scapy.all import *

pkts = []

# VLAN tagged packet
pkts += Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/ \
    Dot1Q(vlan=6)/ \
    IP(dst='255.255.255.255', src='192.168.0.1')/ICMP()

# Double-tagged VLAN (QinQ) packet
pkts += Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/ \
    Dot1Q(vlan=1)/Dot1Q(vlan=10)/ \
    IP(dst='255.255.255.255', src='192.168.0.1')/ICMP()

wrpcap('input.pcap', pkts)
