#!/usr/bin/env python3
from scapy.all import Ether, IP, UDP, DNS, DNSQR, wrpcap

pkts = []

# 192.168.1.5 - first IP in 192.168.1.0/24; set+mask 24 adds the /24 (new -> fires)
pkts.append(Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05') /
    IP(src='192.168.1.5', dst='8.8.8.8') /
    UDP(sport=1234, dport=53) /
    DNS(id=1, rd=1, qd=DNSQR(qname='example.com')))

# 192.168.1.99 - same /24 already in set; set does not fire (not new)
pkts.append(Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05') /
    IP(src='192.168.1.99', dst='8.8.8.8') /
    UDP(sport=1235, dport=53) /
    DNS(id=2, rd=1, qd=DNSQR(qname='example.com')))

# 192.168.2.1 - different /24; adds 192.168.2.0/24 (new -> fires)
pkts.append(Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05') /
    IP(src='192.168.2.1', dst='8.8.8.8') /
    UDP(sport=1236, dport=53) /
    DNS(id=3, rd=1, qd=DNSQR(qname='example.com')))

# 192.168.1.200 - back to first /24 which is already in set; does not fire
pkts.append(Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05') /
    IP(src='192.168.1.200', dst='8.8.8.8') /
    UDP(sport=1237, dport=53) /
    DNS(id=4, rd=1, qd=DNSQR(qname='example.com')))

wrpcap('input.pcap', pkts)
print("Wrote input.pcap with %d packets" % len(pkts))
