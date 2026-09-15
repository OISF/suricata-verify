#!/usr/bin/env python3
from scapy.all import Ether, IP, UDP, DNS, DNSQR, wrpcap

pkts = []

# 2 packets from 1.2.3.4 - first fires 'set' (new), second does not
pkts.append(Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05') /
    IP(src='1.2.3.4', dst='8.8.8.8') /
    UDP(sport=1234, dport=53) /
    DNS(id=1, rd=1, qd=DNSQR(qname='example.com')))

pkts.append(Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05') /
    IP(src='1.2.3.4', dst='8.8.8.8') /
    UDP(sport=1235, dport=53) /
    DNS(id=2, rd=1, qd=DNSQR(qname='example.com')))

# 2 packets from 5.6.7.8 - first fires 'set' (new), second does not
pkts.append(Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05') /
    IP(src='5.6.7.8', dst='8.8.8.8') /
    UDP(sport=1236, dport=53) /
    DNS(id=3, rd=1, qd=DNSQR(qname='example.com')))

pkts.append(Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05') /
    IP(src='5.6.7.8', dst='8.8.8.8') /
    UDP(sport=1237, dport=53) /
    DNS(id=4, rd=1, qd=DNSQR(qname='example.com')))

wrpcap('input.pcap', pkts)
print("Wrote input.pcap with %d packets" % len(pkts))
