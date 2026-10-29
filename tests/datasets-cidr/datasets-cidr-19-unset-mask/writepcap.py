#!/usr/bin/env python3
from scapy.all import Ether, IP, UDP, DNS, DNSQR, wrpcap

pkts = []

# 2 packets from 192.168.1.5 (in 192.168.1.0/24)
# unset,mask 24: first masks to /24 and removes it (fires), second finds /24 gone (no fire)
pkts.append(Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05') /
    IP(src='192.168.1.5', dst='8.8.8.8') /
    UDP(sport=1234, dport=53) /
    DNS(id=1, rd=1, qd=DNSQR(qname='example.com')))

pkts.append(Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05') /
    IP(src='192.168.1.5', dst='8.8.8.8') /
    UDP(sport=1235, dport=53) /
    DNS(id=2, rd=1, qd=DNSQR(qname='example.com')))

# 2 packets from 192.168.2.1 (in 192.168.2.0/24)
# unset,mask 24: first removes /24 (fires), second finds /24 gone (no fire)
pkts.append(Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05') /
    IP(src='192.168.2.1', dst='8.8.8.8') /
    UDP(sport=1236, dport=53) /
    DNS(id=3, rd=1, qd=DNSQR(qname='example.com')))

pkts.append(Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05') /
    IP(src='192.168.2.1', dst='8.8.8.8') /
    UDP(sport=1237, dport=53) /
    DNS(id=4, rd=1, qd=DNSQR(qname='example.com')))

# 1 packet from 10.0.0.1: masked to 10.0.0.0/24, not in dataset, no fire
pkts.append(Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05') /
    IP(src='10.0.0.1', dst='8.8.8.8') /
    UDP(sport=1238, dport=53) /
    DNS(id=5, rd=1, qd=DNSQR(qname='example.com')))

wrpcap('input.pcap', pkts)
print("Wrote input.pcap with %d packets" % len(pkts))
