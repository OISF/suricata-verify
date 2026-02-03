#!/usr/bin/env python3

from scapy.all import Ether, IP, Raw, TCP, wrpcap


CLIENT_IP = "192.0.2.51"
SERVER_IP = "192.0.2.52"
CLIENT_MAC = "02:00:00:00:00:51"
SERVER_MAC = "02:00:00:00:00:52"
CLIENT_PORT = 40543
SERVER_PORT = 143

PLAIN_INITIAL_RESPONSE = (
    b"AHBsYWluLXVzZXItc2VjcmV0AHBsYWluLXBhc3N3b3JkLXNlY3JldA=="
)
XOAUTH2_INITIAL_RESPONSE = (
    b"dXNlcj1vYXV0aC11c2VyLXNlY3JldAFhdXRoPUJlYXJlciBvYXV0aC10b2tlbi1zZWNyZXQBAQ=="
)
CONTINUATION_RESPONSE = (
    b"Y29udGludWF0aW9uLXVzZXItc2VjcmV0AGNvbnRpbnVhdGlvbi1wYXNzd29yZC1zZWNyZXQ="
)
LITERAL_LOGIN_USER = b"literal-login-user-secret"
LITERAL_LOGIN_PASSWORD = b"literal-login-password-secret"


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

send_client(b'A1 LOGIN "login-user-secret" "login-password-secret"\r\n')
send_server(b"A1 NO LOGIN failed\r\n")

send_client(b"A2 AUTHENTICATE PLAIN " + PLAIN_INITIAL_RESPONSE + b"\r\n")
send_server(b"A2 NO AUTHENTICATE failed\r\n")

send_client(b"A3 AUTHENTICATE XOAUTH2 " + XOAUTH2_INITIAL_RESPONSE + b"\r\n")
send_server(b"A3 NO AUTHENTICATE failed\r\n")

send_client(b"A4 AUTHENTICATE PLAIN\r\n")
send_server(b"+ \r\n")
send_client(CONTINUATION_RESPONSE + b"\r\n")
send_server(b"A4 NO AUTHENTICATE failed\r\n")

send_client(b"A5 LOGIN {%d}\r\n" % len(LITERAL_LOGIN_USER))
send_server(b"+ continue\r\n")
send_client(LITERAL_LOGIN_USER + b" {%d}\r\n" % len(LITERAL_LOGIN_PASSWORD))
send_server(b"+ continue\r\n")
send_client(LITERAL_LOGIN_PASSWORD + b"\r\n")
send_server(b"A5 NO LOGIN failed\r\n")

for timestamp, pkt in enumerate(packets, 1):
    pkt.time = timestamp

wrpcap("input.pcap", packets)
