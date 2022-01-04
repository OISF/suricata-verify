#!/usr/bin/env python
from scapy.all import *

pkts = []

pkts += Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/ \
    Dot1Q(vlan=6)/ \
    IP(dst='192.168.1.1', src='192.168.1.5')/TCP(sport=53, dport=80, flags='P''A')/"POST /one/self/ HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\nCookie: hellocatch\r\n\r\n"
pkts += Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/ \
    Dot1Q(vlan=6)/ \
    IP(dst='192.168.1.1', src='192.168.1.5')/TCP(sport=43, dport=70, flags='P''A')/"GET /%00/images.gif HTTP/1.1\r\nHost: www.ExAmPlE.cOM\r\n\r\n"
pkts += Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/ \
    Dot1Q(vlan=6)/ \
    IP(dst='192.168.1.1', src='192.168.1.5')/TCP(sport=80, dport=53, flags='P''A')/"GET /%2e%2e/one/images.gif HTTP/1.1\r\nHost: www.ExAmPlE.cOM\r\n\r\n"
pkts += Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/ \
    Dot1Q(vlan=6)/ \
    IP(dst='192.168.1.1', src='192.168.1.5')/TCP(sport=42, dport=60, flags='P''A')/"GET /./././images.gif HTTP/1.1\r\nHost: www.ExAmPlE.cOM\r\n\r\n"
pkts += Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/ \
    Dot1Q(vlan=6)/ \
    IP(dst='192.168.1.1', src='192.168.1.5')/UDP(dport=50)/DNS(rd=1, qd=DNSQR(qtype="A", qname="google.com"), an=DNSRR(rdata="123.0.0.1"))

wrpcap('input.pcap', pkts)
