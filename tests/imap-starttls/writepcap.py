#!/usr/bin/env python3
from scapy.all import Ether, IP, Raw, TCP, rdpcap, wrpcap


CLIENT_IP = "192.0.2.91"
SERVER_IP = "192.0.2.92"
CLIENT_MAC = "02:00:00:00:00:91"
SERVER_MAC = "02:00:00:00:00:92"
SERVER_PORT = 143

tls_records = []
for pkt in rdpcap("../ldap-starttls/input.pcap"):
    if TCP in pkt and Raw in pkt:
        data = bytes(pkt[Raw].load)
        if data[0] in (0x14, 0x16) and data[1] == 3:
            tls_records.append((pkt[TCP].sport == 389, data))
            if len(tls_records) == 9:
                break


def build_flow(client_port, untagged_before_reply):
    packets = []
    client_seq, server_seq = 1000, 9000

    def packet(server, seq, ack, flags, payload=b""):
        if server:
            src_mac, dst_mac = SERVER_MAC, CLIENT_MAC
            src_ip, dst_ip = SERVER_IP, CLIENT_IP
            src_port, dst_port = SERVER_PORT, client_port
        else:
            src_mac, dst_mac = CLIENT_MAC, SERVER_MAC
            src_ip, dst_ip = CLIENT_IP, SERVER_IP
            src_port, dst_port = client_port, SERVER_PORT
        pkt = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dst_ip)
            / TCP(sport=src_port, dport=dst_port, seq=seq, ack=ack, flags=flags, window=65535)
        )
        return pkt / Raw(load=payload) if payload else pkt

    packets += [
        packet(False, client_seq, 0, "S"),
        packet(True, server_seq, client_seq + 1, "SA"),
        packet(False, client_seq + 1, server_seq + 1, "A"),
    ]
    client_seq += 1
    server_seq += 1

    def send(server, payload):
        nonlocal client_seq, server_seq
        if server:
            packets.append(packet(True, server_seq, client_seq, "PA", payload))
            server_seq += len(payload)
        else:
            packets.append(packet(False, client_seq, server_seq, "PA", payload))
            client_seq += len(payload)

    send(True, b"* OK IMAP ready\r\n")
    send(False, b"A1 STARTTLS\r\n")
    if untagged_before_reply:
        send(True, b"* OK preparing TLS\r\n")
    send(True, b"A1 OK Begin TLS negotiation now\r\n")
    for server, data in tls_records:
        send(server, data)
    return packets


packets = build_flow(40101, True) + build_flow(40102, False)
for timestamp, pkt in enumerate(packets, 1):
    pkt.time = timestamp
wrpcap("input.pcap", packets)
