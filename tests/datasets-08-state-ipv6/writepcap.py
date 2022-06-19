#!/usr/bin/env python
from scapy.all import *

pkts = []

pkts += Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/ \
    Dot1Q(vlan=6)/ \
    IPv6(dst='2::1', src='4:5::6')/UDP(dport=53)/DNS(id=1, rd=1, qd=DNSQR(qname='example.com'))
pkts += Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/ \
    Dot1Q(vlan=6)/ \
    IPv6(dst='2::1', src='4:5::6')/UDP(dport=53)/DNS(id=2, rd=1, qd=DNSQR(qname='example.com'))
pkts += Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/ \
    Dot1Q(vlan=6)/ \
    IPv6(dst='2::1', src='7:8::9')/UDP(dport=53)/DNS(id=3, rd=1, qd=DNSQR(qname='example.com'))

wrpcap('input.pcap', pkts)
