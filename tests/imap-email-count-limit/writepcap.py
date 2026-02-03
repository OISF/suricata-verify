#!/usr/bin/env python3
from scapy.all import Ether, IP, Raw, TCP, wrpcap

CLIENT_IP, SERVER_IP = "192.0.2.31", "192.0.2.32"
CLIENT_MAC, SERVER_MAC = "02:00:00:00:00:31", "02:00:00:00:00:32"
CPORT, SPORT = 40343, 143


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


def fetch_response(sequence, email):
    return b"* %d FETCH (BODY[] {%d}\r\n%s)\r\n" % (sequence, len(email), email)


greeting = b"* OK IMAP ready\r\n"
request = b"A1 FETCH 1:* BODY[]\r\n"
email = b"Subject: count limit\r\n\r\nx"
fetches = [fetch_response(i, email) for i in range(1, 514)]
completion = b"A1 OK FETCH completed\r\n"
request2 = b"A2 NOOP\r\n"
completion2 = b"A2 OK NOOP completed\r\n"

client_seq, server_seq = 1000, 9000
client_data_seq = client_seq + 1
server_data_seq = server_seq + 1
packets = [
    packet(False, client_seq, 0, "S"),
    packet(True, server_seq, client_data_seq, "SA"),
    packet(False, client_data_seq, server_data_seq, "A"),
    packet(True, server_data_seq, client_data_seq, "PA", greeting),
    packet(False, client_data_seq, server_data_seq + len(greeting), "PA", request),
]
client_data_seq += len(request)
server_data_seq += len(greeting)

for offset in range(0, 500, 100):
    chunk = b"".join(fetches[offset : offset + 100])
    packets.append(packet(True, server_data_seq, client_data_seq, "PA", chunk))
    server_data_seq += len(chunk)
    packets.append(packet(False, client_data_seq, server_data_seq, "A"))

final_response = b"".join(fetches[500:]) + completion
packets.append(packet(True, server_data_seq, client_data_seq, "PA", final_response))
server_data_seq += len(final_response)
packets.append(packet(False, client_data_seq, server_data_seq, "PA", request2))
client_data_seq += len(request2)
packets.append(packet(True, server_data_seq, client_data_seq, "PA", completion2))

for timestamp, pkt in enumerate(packets, 1):
    pkt.time = timestamp

wrpcap("input.pcap", packets)
