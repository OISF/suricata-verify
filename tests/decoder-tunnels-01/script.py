#!/usr/bin/env python
from scapy.all import *
from scapy.contrib.erspan import *

pkts = []

pkt1 = Ether()/IP(dst='192.168.1.2', src='192.168.1.3')/UDP()/VXLAN(vni=123)/Ether()/IP(dst='10.1.2.3', src='10.1.2.4')/ICMP(type=8)/"pxng"
pkt2 = Ether()/IP(dst='192.168.1.2', src='192.168.1.4')/GRE()/ERSPAN_II(session_id=321)/Ether()/IP(dst='10.1.2.3', src='10.1.2.4')/ICMP(type=8)/"peng"


pkts += pkt1
pkts += pkt2

wrpcap('tunnels.pcap', pkts)
