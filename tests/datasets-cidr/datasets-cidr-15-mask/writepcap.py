#!/usr/bin/env python3
from scapy.all import Ether, IP, UDP, DNS, DNSQR, wrpcap

pkts = []

# 2 packets from 192.168.1.5 using the same 5-tuple (same flow, same worker).
# First masks to 192.168.1.0/24 and adds it (new -> fires); second finds it
# already present (no fire).
pkts.append(Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05') /
    IP(src='192.168.1.5', dst='8.8.8.8') /
    UDP(sport=1234, dport=53) /
    DNS(id=1, rd=1, qd=DNSQR(qname='example.com')))

pkts.append(Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05') /
    IP(src='192.168.1.5', dst='8.8.8.8') /
    UDP(sport=1234, dport=53) /
    DNS(id=2, rd=1, qd=DNSQR(qname='example.com')))

# 2 packets from 192.168.2.1 using the same 5-tuple (same flow, same worker).
# First adds 192.168.2.0/24 (new -> fires); second finds it already present.
pkts.append(Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05') /
    IP(src='192.168.2.1', dst='8.8.8.8') /
    UDP(sport=1234, dport=53) /
    DNS(id=3, rd=1, qd=DNSQR(qname='example.com')))

pkts.append(Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05') /
    IP(src='192.168.2.1', dst='8.8.8.8') /
    UDP(sport=1234, dport=53) /
    DNS(id=4, rd=1, qd=DNSQR(qname='example.com')))

wrpcap('input.pcap', pkts)
print("Wrote input.pcap with %d packets" % len(pkts))
