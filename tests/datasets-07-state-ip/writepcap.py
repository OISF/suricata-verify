#!/usr/bin/env python
from scapy.all import *

pkts = []

pkts += Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/ \
    Dot1Q(vlan=6)/ \
    IP(dst='1.2.3.4', src='5.6.7.8')/UDP(dport=53)/DNS(id=1, rd=1, qd=DNSQR(qname='example.com'))
pkts += Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/ \
    Dot1Q(vlan=6)/ \
    IP(dst='1.2.3.4', src='5.6.7.8')/UDP(dport=53)/DNS(id=2, rd=1, qd=DNSQR(qname='example.com'))
pkts += Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/ \
    Dot1Q(vlan=6)/ \
    IP(dst='1.2.3.4', src='5.6.7.8')/UDP(dport=53)/DNS(id=3, rd=1, qd=DNSQR(qname='example.com'))

wrpcap('input.pcap', pkts)
