#!/usr/bin/env python3

from scapy.all import Ether, IP, Raw, TCP, wrpcap


CLIENT_IP = "192.0.2.81"
SERVER_IP = "192.0.2.82"
CLIENT_MAC = "02:00:00:00:00:81"
SERVER_MAC = "02:00:00:00:00:82"
CLIENT_PORT = 40843
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


send_server(b"* OK IMAP ready\r\n")

send_client(b'A1 ID ("name" "value ) ( \\"quoted\\" \\\\folder")\r\n')
send_server(b"A1 OK ID completed\r\n")

send_client(b"A2 FETCH 1 BODYSTRUCTURE\r\n")
send_server(
    b'* 1 FETCH (BODYSTRUCTURE ("TEXT" "PLAIN" ("NAME" "a)b") '
    b'NIL NIL "7BIT" 12 1))\r\n'
)
send_server(b"A2 OK FETCH completed\r\n")

send_client(b"A3 NOOP\r\n")
send_server(b"A3 OK NOOP completed\r\n")

for timestamp, pkt in enumerate(packets, 1):
    pkt.time = timestamp

wrpcap("input.pcap", packets)
