#!/usr/bin/env python3
"""Generate FTP traffic whose request allocation exceeds the FTP memcap."""

from pathlib import Path

from scapy.all import Ether, IP, TCP, Raw, wrpcap


CLIENT = "192.0.2.1"
SERVER = "192.0.2.2"
CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"
SPORT = 49152
DPORT = 21


def packet(src, dst, sport, dport, seq, ack, flags, payload=b""):
    if src == CLIENT:
        ether = Ether(src=CLIENT_MAC, dst=SERVER_MAC)
    else:
        ether = Ether(src=SERVER_MAC, dst=CLIENT_MAC)
    pkt = ether / IP(src=src, dst=dst) / TCP(
        sport=sport, dport=dport, seq=seq, ack=ack, flags=flags
    )
    if payload:
        pkt /= Raw(payload)
    return pkt


def main():
    cseq = 1000
    sseq = 9000
    request = b"USER " + (b"A" * 4000) + b"\r\n"

    packets = [
        packet(CLIENT, SERVER, SPORT, DPORT, cseq, 0, "S"),
        packet(SERVER, CLIENT, DPORT, SPORT, sseq, cseq + 1, "SA"),
        packet(CLIENT, SERVER, SPORT, DPORT, cseq + 1, sseq + 1, "A"),
        packet(CLIENT, SERVER, SPORT, DPORT, cseq + 1, sseq + 1, "PA", request),
        packet(SERVER, CLIENT, DPORT, SPORT, sseq + 1, cseq + 1 + len(request), "A"),
    ]

    for idx, pkt in enumerate(packets):
        pkt.time = idx / 1_000_000

    wrpcap(str(Path(__file__).with_name("input.pcap")), packets)


if __name__ == "__main__":
    main()
