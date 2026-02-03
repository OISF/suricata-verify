#!/usr/bin/env python3

from scapy.all import Ether, IP, Raw, TCP, wrpcap

CLIENT_IP = "192.0.2.31"
SERVER_IP = "192.0.2.32"
CLIENT_MAC = "02:00:00:00:00:31"
SERVER_MAC = "02:00:00:00:00:32"
CLIENT_PORT = 40343
SERVER_PORT = 143


def packet(server, seq, ack, flags, payload=b""):
    if server:
        src_mac, dst_mac = SERVER_MAC, CLIENT_MAC
        src_ip, dst_ip = SERVER_IP, CLIENT_IP
        src_port, dst_port = SERVER_PORT, CLIENT_PORT
    else:
        src_mac, dst_mac = CLIENT_MAC, SERVER_MAC
        src_ip, dst_ip = CLIENT_IP, SERVER_IP
        src_port, dst_port = CLIENT_PORT, SERVER_PORT
    p = (
        Ether(src=src_mac, dst=dst_mac)
        / IP(src=src_ip, dst=dst_ip)
        / TCP(
            sport=src_port,
            dport=dst_port,
            seq=seq,
            ack=ack,
            flags=flags,
            window=65535,
        )
    )
    return p / Raw(load=payload) if payload else p


greeting = b"* OK IMAP ready\r\n"
small_email = (
    b"From: early@example.test\r\n"
    b"Subject: retained\r\n"
    b"\r\n"
    b"APPEND-EARLY-MARKER\r\n"
)
large_size = 10 * 1024 * 1024
large_prefix = b"\r\nAPPEND-LATE-MARKER\r\n"
large_email = large_prefix + b"X" * (large_size - len(large_prefix))

command1 = b"A1 APPEND INBOX {%d+}\r\n" % len(small_email)
completion1 = b"A1 OK APPEND completed\r\n"
command2 = b"A2 APPEND INBOX {%d+}\r\n" % len(large_email)
completion2 = b"A2 OK APPEND completed\r\n"

client_seq, server_seq = 1000, 9000
packets = [
    packet(False, client_seq, 0, "S"),
    packet(True, server_seq, client_seq + 1, "SA"),
    packet(False, client_seq + 1, server_seq + 1, "A"),
]
client_seq += 1
server_seq += 1

packets.append(packet(True, server_seq, client_seq, "PA", greeting))
server_seq += len(greeting)

packets.append(packet(False, client_seq, server_seq, "PA", command1))
client_seq += len(command1)
packets.append(packet(False, client_seq, server_seq, "PA", small_email + b"\r\n"))
client_seq += len(small_email) + 2
packets.append(packet(True, server_seq, client_seq, "PA", completion1))
server_seq += len(completion1)

packets.append(packet(False, client_seq, server_seq, "PA", command2))
client_seq += len(command2)
for offset in range(0, len(large_email), 32768):
    chunk = large_email[offset : offset + 32768]
    packets.append(packet(False, client_seq, server_seq, "PA", chunk))
    client_seq += len(chunk)
    packets.append(packet(True, server_seq, client_seq, "A"))
packets.append(packet(False, client_seq, server_seq, "PA", b"\r\n"))
client_seq += 2
packets.append(packet(True, server_seq, client_seq, "PA", completion2))

for timestamp, p in enumerate(packets, 1):
    p.time = timestamp
wrpcap("input.pcap", packets)
