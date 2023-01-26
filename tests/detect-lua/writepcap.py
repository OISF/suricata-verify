#!/usr/bin/env python
from scapy.all import *

pkts = []

pkts += Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/ \
    Dot1Q(vlan=6)/ \
    IP(dst='192.168.1.1', src='192.168.1.5')/TCP(sport=53, dport=80, flags='P''A')/"POST / HTTP/1.1\r\nHost: www.emergingthreats.net\r\n\r\n"
pkts += Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/ \
    Dot1Q(vlan=6)/ \
    IP(dst='192.168.1.1', src='192.168.1.5')/TCP(sport=80, dport=53, flags='P''A')/"POST / HTTP/1.1\r\nHost: www.openinfosecfoundation.org\r\n\r\n"

wrpcap('input.pcap', pkts)
