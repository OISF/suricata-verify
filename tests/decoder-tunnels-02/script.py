#!/usr/bin/env python
from scapy.all import *
from scapy.contrib.erspan import *

pkts = []

pkt1 = Ether()/IP(dst='192.168.1.2', src='192.168.1.3')/UDP()/VXLAN(vni=123, flags=8)/Ether()/IP(dst='10.1.2.3', src='10.1.2.4')/UDP(sport=12345, dport=12345)/"pxng"
pkt2 = Ether()/IP(dst='192.168.1.2', src='192.168.1.3')/UDP()/VXLAN(vni=123, flags=8)/Ether()/IP(dst='10.1.2.3', src='10.1.2.4')/UDP(sport=12345, dport=12345)/"pang"
pkt3 = Ether()/IP(dst='192.168.1.2', src='192.168.1.3')/UDP()/VXLAN(vni=123, flags=8)/Ether()/IP(dst='10.1.2.30', src='10.1.2.40')/UDP(sport=12345, dport=12345)/"pang"


pkts += pkt1
pkts += pkt2
pkts += pkt3

wrpcap('tunnels.pcap', pkts)
