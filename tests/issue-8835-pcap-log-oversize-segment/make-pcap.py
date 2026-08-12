#!/usr/bin/env python3
from scapy.all import Ether, IP, TCP, Raw, PcapWriter

C, S, CP, SP = "10.0.0.1", "10.0.0.2", 40000, 80
CM, SM = "02:00:00:00:00:01", "02:00:00:00:00:02"

def packet(to_server, flags, seq, ack=0, payload=b""):
    if to_server:
        base = Ether(src=CM, dst=SM) / IP(src=C, dst=S) / TCP(sport=CP, dport=SP, flags=flags, seq=seq, ack=ack, window=65535)
    else:
        base = Ether(src=SM, dst=CM) / IP(src=S, dst=C) / TCP(sport=SP, dport=CP, flags=flags, seq=seq, ack=ack, window=65535)
    return base / Raw(payload) if payload else base

payload = b"A" * 65495
packets = [
    packet(True, "S", 1000),
    packet(False, "SA", 5000, 1001),
    packet(True, "A", 1001, 5001),
    packet(True, "PA", 1001, 5001, payload),
    packet(False, "A", 5001, 1001 + len(payload)),
]

writer = PcapWriter("input.pcap", sync=True, snaplen=262144)
for i, p in enumerate(packets):
    p.time = 1.0 + i / 1000000.0
    writer.write(p)
writer.close()
