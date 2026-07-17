#!/usr/bin/env python3
"""
Generate input.pcap for the detect-pcrexform-13 (error passthrough)  test.

Three DNS queries:
  1. "example.com"     -- not a subdomain, pcrexform fails, original buffer preserved
  2. "www.example.com" -- subdomain, pcrexform succeeds, buffer = extracted "example.com"
  3. "example.org"     -- not a subdomain, pcrexform fails, original buffer preserved
"""

from scapy.all import IP, UDP, DNS, DNSQR, wrpcap

SRC = "192.168.1.100"
DST = "8.8.8.8"

cases = [
    (1, "example.com"),      # pcrexform fails -> "example.com" preserved
    (2, "www.example.com"),  # pcrexform succeeds -> extracts "example.com"
    (3, "example.org"),      # pcrexform fails -> "example.org" preserved
]

packets = [
    IP(src=SRC, dst=DST) / UDP(sport=12300 + txid, dport=53) / DNS(id=txid, rd=1, qd=DNSQR(qname=name))
    for txid, name in cases
]

wrpcap("input.pcap", packets)
print("Wrote input.pcap")
for txid, name in cases:
    print(f"  query {txid}: {name}")
