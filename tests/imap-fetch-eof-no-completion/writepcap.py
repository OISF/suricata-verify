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


packets = []


def send_client(payload):
    global client_seq
    packets.append(packet(False, client_seq, server_seq, "PA", payload))
    client_seq += len(payload)
    packets.append(packet(True, server_seq, client_seq, "A"))


def send_server(payload):
    global server_seq
    packets.append(packet(True, server_seq, client_seq, "PA", payload))
    server_seq += len(payload)
    packets.append(packet(False, client_seq, server_seq, "A"))


email = (
    b"Subject: SECRETSUBJECT\r\n"
    b"From: alice@example.com\r\n"
    b"\r\n"
    b"BODYMARKER hello\r\n"
)

for CLIENT_PORT, scenario in enumerate(
    ["fetch-fin", "fetch-partial", "fetch-unacked", "append-partial", "append-unacked"],
    40743,
):
    client_seq, server_seq = 1000, 9000
    packets.extend([
        packet(False, client_seq, 0, "S"),
        packet(True, server_seq, client_seq + 1, "SA"),
        packet(False, client_seq + 1, server_seq + 1, "A"),
    ])
    client_seq += 1
    server_seq += 1
    send_server(b"* OK IMAP ready\r\n")

    if scenario.startswith("fetch"):
        send_client(b"A1 FETCH 1 BODY[]\r\n")
        response = b"* 1 FETCH (BODY[] {%d}\r\n" % len(email) + email + b")\r\n"
        if scenario == "fetch-partial":
            response += b"A1 O"
        if scenario == "fetch-unacked":
            packets.append(packet(True, server_seq, client_seq, "PA", response))
            continue
        send_server(response)
    else:
        send_client(b"A1 APPEND INBOX {%d+}\r\n" % len(email))
        if scenario == "append-unacked":
            packets.append(packet(False, client_seq, server_seq, "PA", email + b"\r\n"))
            continue
        send_client(email + b" ")

    packets.append(packet(True, server_seq, client_seq, "FA"))
    server_seq += 1
    packets.append(packet(False, client_seq, server_seq, "FA"))
    client_seq += 1
    packets.append(packet(True, server_seq, client_seq, "A"))

for timestamp, pkt in enumerate(packets, 1):
    pkt.time = timestamp

wrpcap("input.pcap", packets)
