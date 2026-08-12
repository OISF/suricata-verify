#!/usr/bin/env python3
from scapy.all import Ether, IP, TCP, Raw, wrpcap

C, S, CP, SP = "10.0.0.1", "10.0.0.2", 40000, 443
CM, SM = "02:00:00:00:00:01", "02:00:00:00:00:02"

def packet(to_server, flags, seq, ack=0, payload=b""):
    if to_server:
        base = Ether(src=CM, dst=SM) / IP(src=C, dst=S) / TCP(sport=CP, dport=SP, flags=flags, seq=seq, ack=ack)
    else:
        base = Ether(src=SM, dst=CM) / IP(src=S, dst=C) / TCP(sport=SP, dport=CP, flags=flags, seq=seq, ack=ack)
    return base / Raw(payload) if payload else base

trigger = bytes.fromhex("80 01 01 00 02 00 00 00 00")
packets = [
    packet(True, "S", 1000),
    packet(False, "SA", 2000, 1001),
    packet(True, "A", 1001, 2001),
    packet(True, "PA", 1001, 2001, trigger),
    packet(False, "A", 2001, 1010),
]
for i, p in enumerate(packets):
    p.time = 1.0 + i / 1000000.0
wrpcap("input.pcap", packets)
