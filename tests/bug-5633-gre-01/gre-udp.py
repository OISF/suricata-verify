#!/usr/bin/env python
from scapy.all import *

pkts = []

pkt1 = Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/Dot1Q(vlan=6)/IP(dst='1.1.1.1', src='1.1.1.2')/GRE()/IP(dst='2.2.2.2', src='2.2.2.3')/UDP(dport=514,sport=12345)/"EVIL"
pkt2 = Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/Dot1Q(vlan=6)/IP(dst='1.1.1.1', src='1.1.1.2')/GRE()/IP(dst='2.2.2.2', src='2.2.2.3')/UDP(dport=514,sport=12345)/"GOOD"
pkt3 = Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/Dot1Q(vlan=6)/IP(dst='1.1.1.1', src='1.1.1.2')/GRE()/IP(dst='2.2.2.2', src='2.2.2.3')/UDP(dport=514,sport=12345)/"EVIL"

# VLAN tagged packet
pkts += pkt1
pkts += pkt2
pkts += pkt3

wrpcap('gre-udp.pcap', pkts)
