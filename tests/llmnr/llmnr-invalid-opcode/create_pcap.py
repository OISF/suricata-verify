#!/usr/bin/env python3

from scapy.all import *

llmnr_pkt = (
    Ether(dst="01:00:5e:00:00:fc", src="00:0c:29:12:34:56")
    / IP(src="192.168.1.100", dst="224.0.0.252")
    / UDP(sport=54321, dport=5355)
    / DNS(id=12345, opcode=15, qd=DNSQR(qname="test-host.local", qtype="A"))
)

wrpcap("input.pcap", [llmnr_pkt])
print("Created input.pcap with LLMNR packet")
