#!/usr/bin/env python3
from scapy.all import Ether, IP, IPv6, UDP, DNS, DNSQR, wrpcap

pkts = []

# IPv4: 192.168.1.5 - in 192.168.0.0/16 - should match
pkts.append(Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05') /
    IP(src='192.168.1.5', dst='8.8.8.8') /
    UDP(sport=1234, dport=53) /
    DNS(id=1, rd=1, qd=DNSQR(qname='example.com')))

# IPv6: fc00::1 - in fc00::/7 - should match
pkts.append(Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05') /
    IPv6(src='fc00::1', dst='2001:db8::1') /
    UDP(sport=1235, dport=53) /
    DNS(id=2, rd=1, qd=DNSQR(qname='example.com')))

# IPv4: 1.2.3.4 - public IP, not in any CIDR - should NOT match
pkts.append(Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05') /
    IP(src='1.2.3.4', dst='8.8.8.8') /
    UDP(sport=1236, dport=53) /
    DNS(id=3, rd=1, qd=DNSQR(qname='example.com')))

wrpcap('input-mixed.pcap', pkts)
print("Wrote input-mixed.pcap with %d packets" % len(pkts))
