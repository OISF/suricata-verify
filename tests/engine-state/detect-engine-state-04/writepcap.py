#!/usr/bin/env python
from scapy.all import *

pkts = []

data = ('POST / HTTP/1.0\r\n')
data += ('User-Agent: Mozilla/1.0\r\nContent-Length: 10\r\n')
data += ('Cookie: dummy\r\n\r\n')
data += ('Http Body!')

data2 = ('GET /?var=val HTTP/1.1\r\n')
data2 += ('User-Agent: Firefox/1.0\r\n')
data2 += ('Cookie: dummy2\r\nContent-Length: 10\r\n\r\nHttp Body!')

load_layer("http")
pkts += Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/ \
    Dot1Q(vlan=6)/ \
    IPv6(dst='1.2.3.4', src='5.6.7.8')/TCP(sport=6666, dport=63, flags='P''A')/Raw(load=data)
pkts += Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/ \
    Dot1Q(vlan=6)/ \
    IPv6(dst='1.2.3.4', src='5.6.7.8')/TCP(sport=6666, dport=65, flags='P''A')/Raw(load=data2)

wrpcap('input.pcap', pkts)
