#!/usr/bin/env python3
from scapy.all import Ether, IPv6, UDP, DNS, DNSQR, wrpcap

pkts = []

# fc00::1 - in ULA range (fc00::/7) - should match
pkts.append(Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05') /
    IPv6(src='fc00::1', dst='2001:db8::53') /
    UDP(sport=1234, dport=53) /
    DNS(id=1, rd=1, qd=DNSQR(qname='example.com')))

# fd12:3456::1 - in ULA range (fc00::/7 covers fd::/8 too) - should match
pkts.append(Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05') /
    IPv6(src='fd12:3456::1', dst='2001:db8::53') /
    UDP(sport=1235, dport=53) /
    DNS(id=2, rd=1, qd=DNSQR(qname='example.com')))

# 2001:db8::1 - documentation prefix, not ULA - should NOT match
pkts.append(Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05') /
    IPv6(src='2001:db8::1', dst='2001:db8::53') /
    UDP(sport=1236, dport=53) /
    DNS(id=3, rd=1, qd=DNSQR(qname='example.com')))

# fe80::1 - link-local, not ULA - should NOT match
pkts.append(Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05') /
    IPv6(src='fe80::1', dst='2001:db8::53') /
    UDP(sport=1237, dport=53) /
    DNS(id=4, rd=1, qd=DNSQR(qname='example.com')))

wrpcap('input-ipv6.pcap', pkts)
print("Wrote input-ipv6.pcap with %d packets" % len(pkts))
