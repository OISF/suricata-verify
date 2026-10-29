#!/usr/bin/env python3
from scapy.all import Ether, IP, UDP, DNS, DNSQR, wrpcap

pkts = []

# 192.168.0.0 - first address of 192.168.0.0/16 - should match
pkts.append(Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05') /
    IP(src='192.168.0.0', dst='8.8.8.8') /
    UDP(sport=1234, dport=53) /
    DNS(id=1, rd=1, qd=DNSQR(qname='example.com')))

# 192.168.255.255 - last address of 192.168.0.0/16 - should match
pkts.append(Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05') /
    IP(src='192.168.255.255', dst='8.8.8.8') /
    UDP(sport=1235, dport=53) /
    DNS(id=2, rd=1, qd=DNSQR(qname='example.com')))

# 192.169.0.1 - one above 192.168.0.0/16 - should NOT match
pkts.append(Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05') /
    IP(src='192.169.0.1', dst='8.8.8.8') /
    UDP(sport=1236, dport=53) /
    DNS(id=3, rd=1, qd=DNSQR(qname='example.com')))

# 192.167.255.255 - one below 192.168.0.0/16 - should NOT match
pkts.append(Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05') /
    IP(src='192.167.255.255', dst='8.8.8.8') /
    UDP(sport=1237, dport=53) /
    DNS(id=4, rd=1, qd=DNSQR(qname='example.com')))

wrpcap('input-boundary.pcap', pkts)
print("Wrote input-boundary.pcap with %d packets" % len(pkts))
