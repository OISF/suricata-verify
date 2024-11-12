#!/usr/bin/env python
from scapy.all import *

pkts = []

load_layer("http")
load_layer("dcerpc")
pkts += Ether(dst='05:04:03:02:01:00', src='00:01:02:03:04:05')/Dot1Q(vlan=6)/IP(src='1.1.1.1', dst='2.2.2.2')/TCP(dport=8080,sport=12345,flags='S',seq=1,options=[('WScale', 14)])
pkts += Ether(src='05:04:03:02:01:00', dst='00:01:02:03:04:05')/Dot1Q(vlan=6)/IP(dst='1.1.1.1', src='2.2.2.2')/TCP(sport=8080,dport=12345,flags='SA',seq=1000,ack=2,options=[('WScale', 14)],window=65535)
pkts += Ether(dst='05:04:03:02:01:00', src='00:01:02:03:04:05')/Dot1Q(vlan=6)/IP(src='1.1.1.1', dst='2.2.2.2')/TCP(dport=8080,sport=12345,flags='AP',seq=2,ack=1001,window=65535)/DceRpc(ptype=0, call_id=1)
pkts += Ether(src='05:04:03:02:01:00', dst='00:01:02:03:04:05')/Dot1Q(vlan=6)/IP(dst='1.1.1.1', src='2.2.2.2')/TCP(sport=8080,dport=12345,flags='AP',seq=1001,ack=18,window=65535)/HTTP()/HTTPResponse()
#pkts += Ether(src='05:04:03:02:01:00', dst='00:01:02:03:04:05')/Dot1Q(vlan=6)/IP(dst='1.1.1.1', src='2.2.2.2')/TCP(sport=8080,dport=12345,flags='AP',seq=1001,ack=2,window=65535)/HTTP()/HTTPResponse()  ## This works. Why?
pkts += Ether(dst='05:04:03:02:01:00', src='00:01:02:03:04:05')/Dot1Q(vlan=6)/IP(src='1.1.1.1', dst='2.2.2.2')/TCP(dport=8080,sport=12345,flags='A',seq=18,ack=1076,window=65535)

wrpcap('input.pcap', pkts)
