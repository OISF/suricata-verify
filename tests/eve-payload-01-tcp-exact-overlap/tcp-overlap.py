#!/usr/bin/env python
from scapy.all import *

pkts = []

pkt1 = Ether(dst='05:04:03:02:01:00', src='00:01:02:03:04:05')/Dot1Q(vlan=6)/IP(src='1.1.1.1', dst='2.2.2.2')/TCP(dport=8080,sport=12345,flags='S',seq=1,options=[('WScale', 5)])
pkt2 = Ether(src='05:04:03:02:01:00', dst='00:01:02:03:04:05')/Dot1Q(vlan=6)/IP(dst='1.1.1.1', src='2.2.2.2')/TCP(sport=8080,dport=12345,flags='SA',seq=1000,ack=2,options=[('WScale', 5)],window=4096)
pkt3 = Ether(dst='05:04:03:02:01:00', src='00:01:02:03:04:05')/Dot1Q(vlan=6)/IP(src='1.1.1.1', dst='2.2.2.2')/TCP(dport=8080,sport=12345,flags='A',seq=2,ack=1001,window=4096)
pkt4 = Ether(src='05:04:03:02:01:00', dst='00:01:02:03:04:05')/Dot1Q(vlan=6)/IP(dst='1.1.1.1', src='2.2.2.2')/TCP(sport=8080,dport=12345,flags='A',seq=1001,ack=2,window=4096)
pkt5 = Ether(dst='05:04:03:02:01:00', src='00:01:02:03:04:05')/Dot1Q(vlan=6)/IP(src='1.1.1.1', dst='2.2.2.2')/TCP(dport=8080,sport=12345,flags='A',seq=2,ack=1001,window=4096)/"GOOD"
pkt6 = Ether(dst='05:04:03:02:01:00', src='00:01:02:03:04:05')/Dot1Q(vlan=6)/IP(src='1.1.1.1', dst='2.2.2.2')/TCP(dport=8080,sport=12345,flags='A',seq=2,ack=1001,window=4096)/"EVIL"
pkt7 = Ether(src='05:04:03:02:01:00', dst='00:01:02:03:04:05')/Dot1Q(vlan=6)/IP(dst='1.1.1.1', src='2.2.2.2')/TCP(sport=8080,dport=12345,flags='A',ack=6,seq=1001,window=4096)

# VLAN tagged packet
pkts += pkt1
pkts += pkt2
pkts += pkt3
pkts += pkt4
pkts += pkt5
pkts += pkt6
pkts += pkt7

wrpcap('tcp-overlap.pcap', pkts)

pkts = []

pkt1 = Ether(dst='05:04:03:02:01:00', src='00:01:02:03:04:05')/Dot1Q(vlan=6)/IP(src='1.1.1.1', dst='2.2.2.2')/TCP(dport=8080,sport=12345,flags='S',seq=1,options=[('WScale', 5)])
pkt2 = Ether(src='05:04:03:02:01:00', dst='00:01:02:03:04:05')/Dot1Q(vlan=6)/IP(dst='1.1.1.1', src='2.2.2.2')/TCP(sport=8080,dport=12345,flags='SA',seq=1000,ack=2,options=[('WScale', 5)],window=4096)
pkt3 = Ether(dst='05:04:03:02:01:00', src='00:01:02:03:04:05')/Dot1Q(vlan=6)/IP(src='1.1.1.1', dst='2.2.2.2')/TCP(dport=8080,sport=12345,flags='A',seq=2,ack=1001,window=4096)
pkt4 = Ether(src='05:04:03:02:01:00', dst='00:01:02:03:04:05')/Dot1Q(vlan=6)/IP(dst='1.1.1.1', src='2.2.2.2')/TCP(sport=8080,dport=12345,flags='A',seq=1001,ack=2,window=4096)
pkt5 = Ether(dst='05:04:03:02:01:00', src='00:01:02:03:04:05')/Dot1Q(vlan=6)/IP(src='1.1.1.1', dst='2.2.2.2')/TCP(dport=8080,sport=12345,flags='A',seq=2,ack=1001,window=4096)/"GOOD"
pkt6 = Ether(dst='05:04:03:02:01:00', src='00:01:02:03:04:05')/Dot1Q(vlan=6)/IP(src='1.1.1.1', dst='2.2.2.2')/TCP(dport=8080,sport=12345,flags='A',seq=3, ack=1001,window=4096)/"XXX"
pkt7 = Ether(src='05:04:03:02:01:00', dst='00:01:02:03:04:05')/Dot1Q(vlan=6)/IP(dst='1.1.1.1', src='2.2.2.2')/TCP(sport=8080,dport=12345,flags='A',ack=6,seq=1001,window=4096)

# VLAN tagged packet
pkts += pkt1
pkts += pkt2
pkts += pkt3
pkts += pkt4
pkts += pkt5
pkts += pkt6
pkts += pkt7

wrpcap('tcp-overlap2.pcap', pkts)
