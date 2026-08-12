#!/usr/bin/env python3
from scapy.all import Ether, IP, TCP, wrpcap

packets = []
for i in range(4):
    packets.append(
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="10.1.1.1", dst="10.2.2.2")
        / TCP(
            sport=40000,
            dport=80,
            flags="S",
            seq=0x1000 + i,
            window=8192,
            options=[("Timestamp", (100 + i, 0)), ("NOP", None), ("NOP", None)],
        )
    )
for i, packet in enumerate(packets):
    packet.time = 1.0 + i / 1000000.0
wrpcap("input.pcap", packets)
