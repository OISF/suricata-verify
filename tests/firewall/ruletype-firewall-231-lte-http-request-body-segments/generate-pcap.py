#!/usr/bin/env python3

from scapy.all import Ether, IP, Raw, TCP, wrpcap

CLIENT_IP = "192.0.2.10"
SERVER_IP = "198.51.100.20"
CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"
CLIENT_PORT = 42424
SERVER_PORT = 80

packets = []
client_seq = 1000
server_seq = 9000


def add(packet):
    packet.time = 1.0 + len(packets) * 0.001
    packets.append(packet)


def client_packet(flags, payload=b""):
    global client_seq
    packet = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT_IP, dst=SERVER_IP)
        / TCP(
            sport=CLIENT_PORT,
            dport=SERVER_PORT,
            flags=flags,
            seq=client_seq,
            ack=server_seq,
            window=64240,
        )
    )
    if payload:
        packet /= Raw(payload)
    add(packet)
    client_seq += len(payload)
    if "S" in flags or "F" in flags:
        client_seq += 1


def server_packet(flags, payload=b""):
    global server_seq
    packet = (
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / IP(src=SERVER_IP, dst=CLIENT_IP)
        / TCP(
            sport=SERVER_PORT,
            dport=CLIENT_PORT,
            flags=flags,
            seq=server_seq,
            ack=client_seq,
            window=64240,
        )
    )
    if payload:
        packet /= Raw(payload)
    add(packet)
    server_seq += len(payload)
    if "S" in flags or "F" in flags:
        server_seq += 1


# TCP handshake. The SYN packets are written explicitly because ACK is not valid yet.
add(
    Ether(src=CLIENT_MAC, dst=SERVER_MAC)
    / IP(src=CLIENT_IP, dst=SERVER_IP)
    / TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="S", seq=client_seq, window=64240)
)
client_seq += 1
add(
    Ether(src=SERVER_MAC, dst=CLIENT_MAC)
    / IP(src=SERVER_IP, dst=CLIENT_IP)
    / TCP(
        sport=SERVER_PORT,
        dport=CLIENT_PORT,
        flags="SA",
        seq=server_seq,
        ack=client_seq,
        window=64240,
    )
)
server_seq += 1
client_packet("A")

body_first = b"first-body-"
body_second = b"second-body"
body_final = b"x" * (100 - len(body_first) - len(body_second))
headers = (
    b"POST /upload HTTP/1.1\r\n"
    b"Host: example.test\r\n"
    b"Content-Type: text/plain\r\n"
    b"Content-Length: 100\r\n"
    b"\r\n"
)

# Keep the matching contents in separate request-body updates. The body is not
# complete when body_second arrives, so both inspections occur at request_body.
client_packet("PA", headers + body_first)
server_packet("A")
client_packet("PA", body_second)
server_packet("A")
client_packet("PA", body_final)
server_packet("A")

response = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"
server_packet("PA", response)
client_packet("A")

# Clean four-way close.
client_packet("FA")
server_packet("A")
server_packet("FA")
client_packet("A")

wrpcap("input.pcap", packets)
