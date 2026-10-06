#!/usr/bin/env python3
"""Generate the TCP trigger for Redmine issue 8805."""

from scapy.all import Ether, IP, Raw, TCP, wrpcap

CLIENT = "192.0.2.1"
SERVER = "192.0.2.2"
CLIENT_PORT = 55005
SERVER_PORT = 80


def packet(src, dst, sport, dport, seq, ack, flags, payload=b""):
    pkt = (
        Ether(src=src[0], dst=dst[0])
        / IP(src=src[1], dst=dst[1])
        / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
    )
    if payload:
        pkt /= Raw(payload)
    return pkt


def main():
    client = ("02:00:00:00:88:05", CLIENT)
    server = ("02:00:00:00:88:06", SERVER)
    client_seq = 1000
    server_seq = 2000

    packets = [
        packet(client, server, CLIENT_PORT, SERVER_PORT, client_seq, 0, "S"),
        packet(
            server, client, SERVER_PORT, CLIENT_PORT, server_seq, client_seq + 1, "SA"
        ),
        packet(
            client,
            server,
            CLIENT_PORT,
            SERVER_PORT,
            client_seq + 1,
            server_seq + 1,
            "A",
        ),
        packet(
            client,
            server,
            CLIENT_PORT,
            SERVER_PORT,
            client_seq + 1,
            server_seq + 1,
            "PA",
            b"X",
        ),
        packet(
            server,
            client,
            SERVER_PORT,
            CLIENT_PORT,
            server_seq + 1,
            client_seq + 2,
            "A",
        ),
    ]

    for index, pkt in enumerate(packets):
        pkt.time = 1_700_880_500 + index / 1000

    wrpcap("input.pcap", packets)


if __name__ == "__main__":
    main()
