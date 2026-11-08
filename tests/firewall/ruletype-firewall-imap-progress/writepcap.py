#!/usr/bin/env python3

from scapy.all import Ether, IP, Raw, TCP, wrpcap


CLIENT_IP = "192.0.2.10"
SERVER_IP = "192.0.2.20"
CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"
CLIENT_PORT = 40000
SERVER_PORT = 143
CLIENT_ISN = 1000
SERVER_ISN = 9000

GREETING = b"* OK IMAP4rev1 server ready\r\n"
REQUEST = b"A1 NOOP\r\n"
UNTAGGED_RESPONSE = b"* 1 EXISTS\r\n"
TAGGED_RESPONSE = b"A1 OK NOOP completed\r\n"

to_server = Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(
    src=CLIENT_IP, dst=SERVER_IP
)
to_client = Ether(src=SERVER_MAC, dst=CLIENT_MAC) / IP(
    src=SERVER_IP, dst=CLIENT_IP
)

client_seq = CLIENT_ISN + 1
server_seq = SERVER_ISN + 1

packets = [
    to_server
    / TCP(
        sport=CLIENT_PORT,
        dport=SERVER_PORT,
        flags="S",
        seq=CLIENT_ISN,
    ),
    to_client
    / TCP(
        sport=SERVER_PORT,
        dport=CLIENT_PORT,
        flags="SA",
        seq=SERVER_ISN,
        ack=client_seq,
    ),
    to_server
    / TCP(
        sport=CLIENT_PORT,
        dport=SERVER_PORT,
        flags="A",
        seq=client_seq,
        ack=server_seq,
    ),
    to_client
    / TCP(
        sport=SERVER_PORT,
        dport=CLIENT_PORT,
        flags="PA",
        seq=server_seq,
        ack=client_seq,
    )
    / Raw(load=GREETING),
]

server_seq += len(GREETING)
packets.append(
    to_server
    / TCP(
        sport=CLIENT_PORT,
        dport=SERVER_PORT,
        flags="PA",
        seq=client_seq,
        ack=server_seq,
    )
    / Raw(load=REQUEST)
)

client_seq += len(REQUEST)
packets.append(
    to_client
    / TCP(
        sport=SERVER_PORT,
        dport=CLIENT_PORT,
        flags="PA",
        seq=server_seq,
        ack=client_seq,
    )
    / Raw(load=UNTAGGED_RESPONSE)
)

server_seq += len(UNTAGGED_RESPONSE)
packets.append(
    to_client
    / TCP(
        sport=SERVER_PORT,
        dport=CLIENT_PORT,
        flags="PA",
        seq=server_seq,
        ack=client_seq,
    )
    / Raw(load=TAGGED_RESPONSE)
)

server_seq += len(TAGGED_RESPONSE)
packets.append(
    to_server
    / TCP(
        sport=CLIENT_PORT,
        dport=SERVER_PORT,
        flags="RA",
        seq=client_seq,
        ack=server_seq,
    )
)

for timestamp, packet in enumerate(packets, start=1):
    packet.time = timestamp

wrpcap("input.pcap", packets)
