#!/usr/bin/env python
from scapy.all import *

pkts = []

# should match: subdomain of .evil.com
pkts += Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05') / \
    IP(dst='1.2.3.4', src='5.6.7.8') / UDP(sport=1234, dport=53) / \
    DNS(id=1, rd=1, qd=DNSQR(qname='mail.evil.com'))

# should match: deeper subdomain of .evil.com
pkts += Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05') / \
    IP(dst='1.2.3.4', src='5.6.7.8') / UDP(sport=1235, dport=53) / \
    DNS(id=2, rd=1, qd=DNSQR(qname='sub.mail.evil.com'))

# should NOT match: different domain
pkts += Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05') / \
    IP(dst='1.2.3.4', src='5.6.7.8') / UDP(sport=1236, dport=53) / \
    DNS(id=3, rd=1, qd=DNSQR(qname='example.com'))

wrpcap('input.pcap', pkts)
