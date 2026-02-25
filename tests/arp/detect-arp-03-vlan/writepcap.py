#!/usr/bin/env python
from scapy.all import *

pkts = []

# VLAN tagged packet
pkts += Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/ \
    Dot1Q(vlan=6)/ \
    ARP()

# Double-tagged VLAN (QinQ) packet
pkts += Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/ \
    Dot1Q(vlan=1)/Dot1Q(vlan=10)/ \
    ARP()

# Triple-tagged VLAN (QinQinQ) packet
pkts += Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/ \
    Dot1Q(vlan=1)/Dot1Q(vlan=10)/Dot1Q(vlan=100)/ \
    ARP()

wrpcap('input.pcap', pkts)

