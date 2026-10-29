#!/usr/bin/env python3
from scapy.all import Ether, IP, TCP, Raw, wrpcap

client_hello = bytes.fromhex(
    "16 03 01 00 47"
    " 01 00 00 43"
    " 03 03"
    " 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
    " 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
    " 00"
    " 00 02 c0 2c"
    " 01 00"
    " 00 18"
    " 00 0a 00 14"
    " 00 12"
    " 00 17 00 18 00 19 00 1d 00 1e 00 1f 00 20 00 21 00 22"
)

C, S, CP, SP = "10.0.0.1", "10.0.0.2", 40000, 443
CM, SM = "02:00:00:00:00:01", "02:00:00:00:00:02"

def packet(to_server, flags, seq, ack=0, payload=b""):
    if to_server:
        base = Ether(src=CM, dst=SM) / IP(src=C, dst=S) / TCP(sport=CP, dport=SP, flags=flags, seq=seq, ack=ack)
    else:
        base = Ether(src=SM, dst=CM) / IP(src=S, dst=C) / TCP(sport=SP, dport=CP, flags=flags, seq=seq, ack=ack)
    return base / Raw(payload) if payload else base

packets = [
    packet(True, "S", 1000),
    packet(False, "SA", 2000, 1001),
    packet(True, "A", 1001, 2001),
    packet(True, "PA", 1001, 2001, client_hello),
    packet(False, "A", 2001, 1001 + len(client_hello)),
]
for i, p in enumerate(packets):
    p.time = 1.0 + i / 1000000.0
wrpcap("input.pcap", packets)
