#!/usr/bin/env python3
# A short TCP flow 10.0.0.1:1234 -> 10.0.0.2:80 (handshake + one GET) so
# a plain tcp rule is inspected on an established IPv4 flow and
# flow:tuple() returns the 6 documented values.
from scapy.all import IP, TCP, Raw, wrpcap, Ether

def ip(s, d):
    return Ether() / IP(src=s, dst=d)

pkts = [
    ip("10.0.0.1", "10.0.0.2") / TCP(sport=1234, dport=80, flags="S", seq=100),
    ip("10.0.0.2", "10.0.0.1") / TCP(sport=80, dport=1234, flags="SA", seq=200, ack=101),
    ip("10.0.0.1", "10.0.0.2") / TCP(sport=1234, dport=80, flags="A", seq=101, ack=201),
    ip("10.0.0.1", "10.0.0.2") / TCP(sport=1234, dport=80, flags="PA", seq=101, ack=201) /
        Raw(load=b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"),
    ip("10.0.0.2", "10.0.0.1") / TCP(sport=80, dport=1234, flags="A", seq=201, ack=149),
    ip("10.0.0.1", "10.0.0.2") / TCP(sport=1234, dport=80, flags="F", seq=149, ack=201),
    ip("10.0.0.2", "10.0.0.1") / TCP(sport=80, dport=1234, flags="FA", seq=201, ack=150),
]
wrpcap("input.pcap", pkts)
print("wrote input.pcap (%d packets)" % len(pkts))
