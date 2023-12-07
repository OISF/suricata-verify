#! /usr/bin/env python

from scapy.all import *

pkts =[]

data0 = ('POST / HTTP/1.1\r\n')
data1 = ('User-Agent: Mozilla/1.0\r\n')
data2 = ('Cookie: dummy\r\nContent-Length: 10\r\n\r\n')
data3 = ('Http Body!')


load_layer('http')

pkts += Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/ \
    Dot1Q(vlan=6)/ \
    IP(dst='1.2.3.4', src='5.6.7.8')/TCP(sport=6666, dport=65, flags='P''A')/Raw(load=data0)

pkts += Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/ \
    Dot1Q(vlan=6)/ \
    IP(dst='1.2.3.4', src='5.6.7.8')/TCP(sport=6666, dport=65, flags='P''A')/Raw(load=data1)

pkts += Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/ \
    Dot1Q(vlan=6)/ \
    IP(dst='1.2.3.4', src='5.6.7.8')/TCP(sport=6666, dport=65, flags='P''A')/Raw(load=data2)

pkts += Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/ \
    Dot1Q(vlan=6)/ \
    IP(dst='1.2.3.4', src='5.6.7.8')/TCP(sport=6666, dport=65, flags='P''A')/Raw(load=data3)

wrpcap('input.pcap', pkts)