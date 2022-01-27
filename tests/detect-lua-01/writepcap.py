#!/usr/bin/env python
from scapy.all import *

pkts = []

load_layer("http")
pkts += Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/ \
    Dot1Q(vlan=6)/ \
    IPv6(dst='1.2.3.4', src='5.6.7.8')/TCP(sport=6666, dport=63, flags='P''A')/HTTP()/HTTPRequest(Method='POST', Http_Version='HTTP/1.1', Host='www.emergingthreats.net')
pkts += Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/ \
    Dot1Q(vlan=6)/ \
    IPv6(dst='192.168.1.1', src='192.168.1.5')/TCP(sport=41424, dport=80, flags='P''A')/HTTP()/HTTPRequest(Method='POST', Http_Version='HTTP/1.1', Host='www.openinfosecfoundation.org')

wrpcap('input.pcap', pkts)
