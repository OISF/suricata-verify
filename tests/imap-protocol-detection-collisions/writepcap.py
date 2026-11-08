#!/usr/bin/env python3

from scapy.all import Ether, IP, Raw, TCP, wrpcap


CLIENT_IP = "192.0.2.10"
SERVER_IP = "192.0.2.20"
CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"


def tcp_session(client_port, server_port, payload, client_seq, server_seq):
    to_server = Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(
        src=CLIENT_IP, dst=SERVER_IP
    )
    to_client = Ether(src=SERVER_MAC, dst=CLIENT_MAC) / IP(
        src=SERVER_IP, dst=CLIENT_IP
    )
    return [
        to_server
        / TCP(
            sport=client_port,
            dport=server_port,
            flags="S",
            seq=client_seq,
        ),
        to_client
        / TCP(
            sport=server_port,
            dport=client_port,
            flags="SA",
            seq=server_seq,
            ack=client_seq + 1,
        ),
        to_server
        / TCP(
            sport=client_port,
            dport=server_port,
            flags="A",
            seq=client_seq + 1,
            ack=server_seq + 1,
        ),
        to_server
        / TCP(
            sport=client_port,
            dport=server_port,
            flags="PA",
            seq=client_seq + 1,
            ack=server_seq + 1,
        )
        / Raw(load=payload),
    ]


packets = []
packets += tcp_session(40000, 143, b"GET / HTTP/1.1\r\n", 1000, 9000)
packets += tcp_session(40001, 21, b"USER CAPABILITY\r\n", 2000, 10000)
packets += tcp_session(40002, 143, b"A1 CAPABILITY\r\n", 3000, 11000)

for timestamp, packet in enumerate(packets, start=1):
    packet.time = timestamp

wrpcap("input.pcap", packets)
