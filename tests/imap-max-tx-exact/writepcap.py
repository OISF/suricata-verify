#!/usr/bin/env python3
from scapy.all import Ether, IP, Raw, TCP, wrpcap

CLIENT_IP, SERVER_IP = "192.0.2.41", "192.0.2.42"
CLIENT_MAC, SERVER_MAC = "02:00:00:00:00:41", "02:00:00:00:00:42"
CPORT, SPORT = 40443, 143


def packet(server, seq, ack, flags, payload=b""):
    if server:
        src_mac, dst_mac = SERVER_MAC, CLIENT_MAC
        src_ip, dst_ip = SERVER_IP, CLIENT_IP
        src_port, dst_port = SPORT, CPORT
    else:
        src_mac, dst_mac = CLIENT_MAC, SERVER_MAC
        src_ip, dst_ip = CLIENT_IP, SERVER_IP
        src_port, dst_port = CPORT, SPORT
    pkt = (
        Ether(src=src_mac, dst=dst_mac)
        / IP(src=src_ip, dst=dst_ip)
        / TCP(sport=src_port, dport=dst_port, seq=seq, ack=ack, flags=flags)
    )
    return pkt / Raw(load=payload) if payload else pkt


requests = [b"A1 NOOP\r\n", b"A2 NOOP\r\n", b"A3 NOOP\r\n"]
client_seq, server_seq = 1000, 9000
client_data_seq = client_seq + 1
server_data_seq = server_seq + 1
packets = [
    packet(False, client_seq, 0, "S"),
    packet(True, server_seq, client_data_seq, "SA"),
    packet(False, client_data_seq, server_data_seq, "A"),
]

for request in requests:
    packets.append(
        packet(
            False,
            client_data_seq,
            server_data_seq,
            "PA",
            request,
        )
    )
    client_data_seq += len(request)

for timestamp, pkt in enumerate(packets, 1):
    pkt.time = timestamp

wrpcap("input.pcap", packets)
