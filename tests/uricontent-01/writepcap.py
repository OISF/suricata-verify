#!/usr/bin/env python
from scapy.all import *

pkts = []

pkts += Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/ \
    Dot1Q(vlan=6)/ \
    IP(dst='1.2.3.4', src='5.6.7.8')/TCP(sport=6666, dport=80, flags='P''A')/"POST /one HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\nCookie: hellocatch\r\n\r\n"

wrpcap('input.pcap', pkts)
