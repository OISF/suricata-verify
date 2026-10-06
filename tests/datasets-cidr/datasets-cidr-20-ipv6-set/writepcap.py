#!/usr/bin/env python3
from scapy.all import Ether, IPv6, UDP, DNS, DNSQR, wrpcap

pkts = []

# 2 packets from fc00::1 - first fires 'set' (new), second does not
pkts.append(Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05') /
    IPv6(src='fc00::1', dst='2001:db8::53') /
    UDP(sport=1234, dport=53) /
    DNS(id=1, rd=1, qd=DNSQR(qname='example.com')))

pkts.append(Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05') /
    IPv6(src='fc00::1', dst='2001:db8::53') /
    UDP(sport=1234, dport=53) /
    DNS(id=2, rd=1, qd=DNSQR(qname='example.com')))

# 2 packets from 2001:db8::1 - first fires 'set' (new), second does not
pkts.append(Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05') /
    IPv6(src='2001:db8::1', dst='2001:db8::53') /
    UDP(sport=1234, dport=53) /
    DNS(id=3, rd=1, qd=DNSQR(qname='example.com')))

pkts.append(Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05') /
    IPv6(src='2001:db8::1', dst='2001:db8::53') /
    UDP(sport=1234, dport=53) /
    DNS(id=4, rd=1, qd=DNSQR(qname='example.com')))

wrpcap('input-ipv6.pcap', pkts)
print("Wrote input-ipv6.pcap with %d packets" % len(pkts))
