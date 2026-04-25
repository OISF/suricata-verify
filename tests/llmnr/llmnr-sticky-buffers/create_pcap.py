#!/usr/bin/env python3

from scapy.all import *

packets = []

llmnr_query = Ether(dst="01:00:5e:00:00:fc", src="00:0c:29:12:34:56") / \
              IP(src="192.168.1.100", dst="224.0.0.252") / \
              UDP(sport=54321, dport=5355) / \
              DNS(id=1234, 
                  qr=0,  # Query
                  opcode=0,
                  qd=DNSQR(qname="testhost.local", qtype="A"))

packets.append(llmnr_query)

llmnr_response = Ether(dst="00:0c:29:12:34:56", src="00:0c:29:87:65:43") / \
                 IP(src="192.168.1.200", dst="192.168.1.100") / \
                 UDP(sport=5355, dport=54321) / \
                 DNS(id=1234,
                     qr=1,  # Response
                     opcode=0,
                     aa=1,
                     qd=DNSQR(qname="testhost.local", qtype="A"),
                     an=DNSRR(rrname="testhost.local", type="A", ttl=120, rdata="192.168.1.200"),
                     ns=DNSRR(rrname="local", type="NS", ttl=3600, rdata="auth.local"),
                     ar=DNSRR(rrname="auth.local", type="A", ttl=120, rdata="192.168.1.1"))

packets.append(llmnr_response)

wrpcap("input.pcap", packets)
print("Created input.pcap with LLMNR packets")
