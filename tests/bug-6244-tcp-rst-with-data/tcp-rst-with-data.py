#!/usr/bin/env python
from scapy.all import *

pkts = []

pkts += Ether(dst='05:04:03:02:01:00', src='00:01:02:03:04:05')/Dot1Q(vlan=6)/IP(src='1.1.1.1', dst='2.2.2.2')/TCP(dport=8080,sport=12345,flags='S',seq=1,options=[('WScale', 14)])
pkts += Ether(src='05:04:03:02:01:00', dst='00:01:02:03:04:05')/Dot1Q(vlan=6)/IP(dst='1.1.1.1', src='2.2.2.2')/TCP(sport=8080,dport=12345,flags='SA',seq=1000,ack=2,options=[('WScale', 14)],window=65535)
pkts += Ether(dst='05:04:03:02:01:00', src='00:01:02:03:04:05')/Dot1Q(vlan=6)/IP(src='1.1.1.1', dst='2.2.2.2')/TCP(dport=8080,sport=12345,flags='A',seq=2,ack=1001,window=65535)
pkts += Ether(src='05:04:03:02:01:00', dst='00:01:02:03:04:05')/Dot1Q(vlan=6)/IP(dst='1.1.1.1', src='2.2.2.2')/TCP(sport=8080,dport=12345,flags='AP',seq=1001,ack=2,window=65535)/"Please "
pkts += Ether(src='05:04:03:02:01:00', dst='00:01:02:03:04:05')/Dot1Q(vlan=6)/IP(dst='1.1.1.1', src='2.2.2.2')/TCP(sport=8080,dport=12345,flags='AP',seq=1008,ack=2,window=65535)/"Let "
pkts += Ether(src='05:04:03:02:01:00', dst='00:01:02:03:04:05')/Dot1Q(vlan=6)/IP(dst='1.1.1.1', src='2.2.2.2')/TCP(sport=8080,dport=12345,flags='AP',seq=1012,ack=2,window=65535)/"Me "
pkts += Ether(src='05:04:03:02:01:00', dst='00:01:02:03:04:05')/Dot1Q(vlan=6)/IP(dst='1.1.1.1', src='2.2.2.2')/TCP(sport=8080,dport=12345,flags='AP',seq=1015,ack=2,window=65535)/"In!"
pkts += Ether(dst='05:04:03:02:01:00', src='00:01:02:03:04:05')/Dot1Q(vlan=6)/IP(src='1.1.1.1', dst='2.2.2.2')/TCP(dport=8080,sport=12345,flags='RA',seq=2,ack=1018,window=65535)/"Access Denied"

wrpcap('tcp-rst-with-data.pcap', pkts)
