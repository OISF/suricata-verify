#!/usr/bin/env python3
from scapy.all import Ether, IP, UDP, DNS, DNSQR, wrpcap

pkts = []

# 192.168.1.5 - in RFC1918 (192.168.0.0/16) - should match
pkts.append(Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05') /
    IP(src='192.168.1.5', dst='8.8.8.8') /
    UDP(sport=1234, dport=53) /
    DNS(id=1, rd=1, qd=DNSQR(qname='example.com')))

# 10.0.0.50 - in RFC1918 (10.0.0.0/8) - should match
pkts.append(Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05') /
    IP(src='10.0.0.50', dst='8.8.8.8') /
    UDP(sport=1235, dport=53) /
    DNS(id=2, rd=1, qd=DNSQR(qname='example.com')))

# 172.17.0.1 - in RFC1918 (172.16.0.0/12) - should match
pkts.append(Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05') /
    IP(src='172.17.0.1', dst='8.8.8.8') /
    UDP(sport=1236, dport=53) /
    DNS(id=3, rd=1, qd=DNSQR(qname='example.com')))

# 1.2.3.4 - public IP - should NOT match
pkts.append(Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05') /
    IP(src='1.2.3.4', dst='8.8.8.8') /
    UDP(sport=1237, dport=53) /
    DNS(id=4, rd=1, qd=DNSQR(qname='example.com')))

# 203.0.113.1 - public IP (TEST-NET-3) - should NOT match
pkts.append(Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05') /
    IP(src='203.0.113.1', dst='8.8.8.8') /
    UDP(sport=1238, dport=53) /
    DNS(id=5, rd=1, qd=DNSQR(qname='example.com')))

wrpcap('input-ipv4.pcap', pkts)
print("Wrote input-ipv4.pcap with %d packets" % len(pkts))
