#!/usr/bin/env python
from scapy.all import *

pkts = []

pkts += Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/ \
    Dot1Q(vlan=6)/ \
    IP(dst='1.2.3.4', src='5.6.7.8')/TCP(sport=6666, dport=80, flags='P''A')/"GET /index.html HTTP/1.0\r\nHost: This is dummy message body\r\nUser-Agent: www.openinfosecfoundation.org\r\nContent-Type: text/html\r\n\r\n"
pkts += Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/ \
    Dot1Q(vlan=6)/ \
    IP(dst='1.2.3.4', src='5.6.7.8')/TCP(sport=6060, dport=53, flags='P''A')/"HTTP/1.0 200 ok\r\nContent-Type: text/html\r\nContent-Length: 7\r\n\r\nmessage"

wrpcap('input.pcap', pkts)
