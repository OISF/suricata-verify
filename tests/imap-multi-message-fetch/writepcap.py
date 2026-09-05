#!/usr/bin/env python3

from scapy.all import Ether, IP, Raw, TCP, wrpcap


CLIENT_IP = "192.0.2.1"
SERVER_IP = "192.0.2.2"
CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"
CLIENT_PORT = 40000
SERVER_PORT = 143


def client_packet(seq, ack, flags, payload=b""):
    packet = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT_IP, dst=SERVER_IP)
        / TCP(
            sport=CLIENT_PORT,
            dport=SERVER_PORT,
            seq=seq,
            ack=ack,
            flags=flags,
        )
    )
    return packet / Raw(load=payload) if payload else packet


def server_packet(seq, ack, flags, payload=b""):
    packet = (
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / IP(src=SERVER_IP, dst=CLIENT_IP)
        / TCP(
            sport=SERVER_PORT,
            dport=CLIENT_PORT,
            seq=seq,
            ack=ack,
            flags=flags,
        )
    )
    return packet / Raw(load=payload) if payload else packet


def fetch_response(sequence, message):
    marker = f"* {sequence} FETCH (BODY[] {{{len(message)}}}\r\n".encode()
    return marker + message + b")\r\n"


first_message = (
    b"From: first@example.test\r\n"
    b"To: analyst@example.test\r\n"
    b"Subject: First fetch control\r\n"
    b"Message-ID: <first@example.test>\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n"
    b"Content-Transfer-Encoding: 7bit\r\n"
    b"\r\n"
    b"FIRST-BODY-CONTROL-71A2\r\n"
)

second_message = (
    b"From: second@example.test\r\n"
    b"To: analyst@example.test\r\n"
    b"Subject: SECOND-SUBJECT-ONLY-9F52\r\n"
    b"Message-ID: <second@example.test>\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n"
    b"Content-Transfer-Encoding: 7bit\r\n"
    b"\r\n"
    b"SECOND-BODY-ONLY-8E41\r\n"
)

greeting = b"* OK IMAP server ready\r\n"
request = b"A1 FETCH 1:* BODY[]\r\n"
response = (
    fetch_response(1, first_message)
    + fetch_response(2, second_message)
    + b"A1 OK FETCH completed\r\n"
)

client_seq = 1000
server_seq = 9000
packets = [
    client_packet(client_seq, 0, "S"),
    server_packet(server_seq, client_seq + 1, "SA"),
    client_packet(client_seq + 1, server_seq + 1, "A"),
    server_packet(server_seq + 1, client_seq + 1, "PA", greeting),
    client_packet(client_seq + 1, server_seq + 1 + len(greeting), "PA", request),
    server_packet(
        server_seq + 1 + len(greeting),
        client_seq + 1 + len(request),
        "PA",
        response,
    ),
]

for timestamp, packet in enumerate(packets, start=1):
    packet.time = timestamp

wrpcap("input.pcap", packets)
