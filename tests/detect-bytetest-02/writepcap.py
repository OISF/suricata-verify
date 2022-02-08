#!/usr/bin/env python
from scapy.all import *

pkts = []

load_layer("http")
pkts += Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/ \
    Dot1Q(vlan=6)/ \
    IPv6(dst='1.2.3.4', src='5.6.7.8')/TCP(sport=6666, dport=63, flags='P''A')/HTTP()/HTTPRequest(Method='GET', Path='/AllWorkAndNoPlayMakesWillADullBoy', Http_Version='HTTP/1.0', User_Agent='Wget/1.11.4', Accept='*/*', Host='www.google.com', Connection='Keep-Alive', Date='Mon, 04 Jan 2010 17:29:39 GMT')

wrpcap('input.pcap', pkts)
