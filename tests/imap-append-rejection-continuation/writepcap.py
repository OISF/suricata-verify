#!/usr/bin/env python3

from scapy.all import Ether, IP, Raw, TCP, wrpcap


CLIENT_IP = "192.0.2.71"
SERVER_IP = "192.0.2.72"
CLIENT_MAC = "02:00:00:00:00:71"
SERVER_MAC = "02:00:00:00:00:72"
CLIENT_PORT = 40743
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

    pkt = (
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
    return pkt / Raw(load=payload) if payload else pkt


client_seq, server_seq = 1000, 9000
packets = [
    packet(False, client_seq, 0, "S"),
    packet(True, server_seq, client_seq + 1, "SA"),
    packet(False, client_seq + 1, server_seq + 1, "A"),
]
client_seq += 1
server_seq += 1


def send_client(payload):
    global client_seq
    packets.append(packet(False, client_seq, server_seq, "PA", payload))
    client_seq += len(payload)


def send_server(payload):
    global server_seq
    packets.append(packet(True, server_seq, client_seq, "PA", payload))
    server_seq += len(payload)


sync_email = (
    b"From: owner@example.test\r\n"
    b"Subject: Synchronizing APPEND\r\n"
    b"\r\n"
    b"SYNC-APPEND-BODY\r\n"
)

send_server(b"* OK IMAP ready\r\n")

send_client(b"A1 APPEND INBOX {4}\r\n")
send_server(b"A1 NO APPEND rejected\r\n")
send_client(b"A2 IDLE\r\n")
send_server(b"+ idling\r\n")
send_client(b"DONE\r\n")
send_server(b"A2 OK IDLE completed\r\n")

send_client(b"A3 APPEND INBOX {4}\r\n")
send_server(b"A3 BAD APPEND rejected\r\n")
send_client(b"A4 IDLE\r\n")
send_server(b"+ idling\r\n")
send_client(b"DONE\r\n")
send_server(b"A4 OK IDLE completed\r\n")

send_client(b"A5 APPEND INBOX {%d}\r\n" % len(sync_email))
send_server(b"+ Ready for literal\r\n")
send_client(sync_email + b"\r\n")
send_server(b"A5 OK APPEND completed\r\n")

send_client(b"A6 NOOP\r\n")
send_server(b"A6 OK NOOP completed\r\n")

for timestamp, pkt in enumerate(packets, 1):
    pkt.time = timestamp

wrpcap("input.pcap", packets)
