#!/usr/bin/env python3
# A DNS request/response for example.com so a plain dns rule is
# inspected on a flow whose app-layer protocol is identified as dns.
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, wrpcap, Ether

q = (Ether() / IP(src="10.0.0.1", dst="10.0.0.2") /
     UDP(sport=53535, dport=53) /
     DNS(id=0x1111, qr=0, qd=DNSQR(qname="example.com", qtype="A")))
r = (Ether() / IP(src="10.0.0.2", dst="10.0.0.1") /
     UDP(sport=53, dport=53535) /
     DNS(id=0x1111, qr=1, qd=DNSQR(qname="example.com", qtype="A"),
         an=DNSRR(rrname="example.com", type=1, rdata="9.9.9.9")))
wrpcap("input.pcap", [q, r])
print("wrote input.pcap (1 DNS request/response)")
