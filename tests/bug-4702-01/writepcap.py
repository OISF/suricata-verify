#!/usr/bin/env python
from scapy.all import *

pkts = []

pkts += Ether(dst='05:04:03:02:01:00', src='00:01:02:03:04:05')/Dot1Q(vlan=6)/IP(src='1.1.1.1', dst='2.2.2.2')/TCP(dport=8080,sport=12345,flags='S',seq=3333,options=[('WScale', 5)])
pkts += Ether(src='05:04:03:02:01:00', dst='00:01:02:03:04:05')/Dot1Q(vlan=6)/IP(dst='1.1.1.1', src='2.2.2.2')/TCP(sport=8080,dport=12345,flags='SA',seq=4444,ack=3334,options=[('Timestamp', (1000,9000))])
pkts += Ether(dst='05:04:03:02:01:00', src='00:01:02:03:04:05')/Dot1Q(vlan=6)/IP(src='1.1.1.1', dst='2.2.2.2')/TCP(dport=8080,sport=12345,flags='A',seq=3334,ack=4445,options=[('Timestamp', (9000,1001))])
pkts += Ether(dst='05:04:03:02:01:00', src='00:01:02:03:04:05')/Dot1Q(vlan=6)/IP(src='1.1.1.1', dst='2.2.2.2')/TCP(dport=8080,sport=12345,flags='A',seq=3334,ack=4445,options=[('Timestamp', (9000,1001))])/"GET /"
pkts += Ether(src='05:04:03:02:01:00', dst='00:01:02:03:04:05')/Dot1Q(vlan=6)/IP(dst='1.1.1.1', src='2.2.2.2')/TCP(sport=8080,dport=12345,flags='A',seq=4445,ack=3339,options=[('Timestamp', (1001,9000))])/"<html>hi</html>"
pkts += Ether(dst='05:04:03:02:01:00', src='00:01:02:03:04:05')/Dot1Q(vlan=6)/IP(src='1.1.1.1', dst='2.2.2.2')/TCP(dport=8080,sport=12345,flags='R',seq=3339)

wrpcap('input.pcap', pkts)

