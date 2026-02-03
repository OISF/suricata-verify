#!/usr/bin/env python3

from scapy.all import Ether, IP, Raw, TCP, wrpcap


SERVER_PORT = 143
PACKETS = []
LABELS = {}


class TcpFlow:
    def __init__(self, client_ip, server_ip, client_port, client_isn, server_isn):
        self.client_ip = client_ip
        self.server_ip = server_ip
        self.client_port = client_port
        self.client_mac = "02:00:00:00:00:01"
        self.server_mac = "02:00:00:00:00:02"
        self.client_seq = client_isn + 1
        self.server_seq = server_isn + 1

        self._client_packet(client_isn, 0, "S")
        self._server_packet(server_isn, self.client_seq, "SA")
        self._client_packet(self.client_seq, self.server_seq, "A")

    def _client_packet(self, seq, ack, flags, payload=b""):
        packet = (
            Ether(src=self.client_mac, dst=self.server_mac)
            / IP(src=self.client_ip, dst=self.server_ip)
            / TCP(
                sport=self.client_port,
                dport=SERVER_PORT,
                seq=seq,
                ack=ack,
                flags=flags,
                window=65535,
            )
        )
        PACKETS.append(packet / Raw(load=payload) if payload else packet)

    def _server_packet(self, seq, ack, flags, payload=b""):
        packet = (
            Ether(src=self.server_mac, dst=self.client_mac)
            / IP(src=self.server_ip, dst=self.client_ip)
            / TCP(
                sport=SERVER_PORT,
                dport=self.client_port,
                seq=seq,
                ack=ack,
                flags=flags,
                window=65535,
            )
        )
        PACKETS.append(packet / Raw(load=payload) if payload else packet)

    def client(self, payload, label=None):
        if label:
            LABELS[label] = len(PACKETS) + 1
        self._client_packet(self.client_seq, self.server_seq, "PA", payload)
        self.client_seq += len(payload)

    def server(self, payload, label=None):
        if label:
            LABELS[label] = len(PACKETS) + 1
        self._server_packet(self.server_seq, self.client_seq, "PA", payload)
        self.server_seq += len(payload)

    def ack(self):
        self._client_packet(self.client_seq, self.server_seq, "A")

    def reset(self):
        self._client_packet(self.client_seq, self.server_seq, "RA")


def large_fragmented_fetch():
    flow = TcpFlow("192.0.2.1", "192.0.2.2", 40001, 1000, 9000)
    greeting = b"* OK IMAP server ready\r\n"
    request = b"A1 FETCH 1 BODY[]\r\n"
    flow.server(greeting)
    flow.client(request)

    literal_size = 6 * 1024 * 1024
    headers = (
        b"From: sender@example.test\r\n"
        b"To: analyst@example.test\r\n"
        b"Subject: Large fragmented FETCH\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
    )
    tail = b"\r\nLARGE-FETCH-BODY-END-7D31\r\n"
    message = headers + b"x" * (literal_size - len(headers) - len(tail)) + tail

    marker = f"* 1 FETCH (BODY[] {{{len(message)}}}\r\n".encode()
    flow.server(marker, "large_fetch_prefix")
    for offset in range(0, len(message), 60 * 1024):
        flow.server(message[offset : offset + 60 * 1024])
        flow.ack()
    flow.server(b")\r\n", "large_fetch_close")
    flow.server(b"A1 OK FETCH completed\r\n", "large_fetch_tagged")
    flow.client(b"A2 NOOP\r\n")
    flow.server(b"A2 OK NOOP completed\r\n", "large_noop_tagged")
    flow.reset()


def multiple_fragmented_literals():
    flow = TcpFlow("192.0.2.11", "192.0.2.12", 40002, 2000, 10000)
    flow.server(b"* OK IMAP server ready\r\n")
    flow.client(b"B1 FETCH 2 (BODY[HEADER] BODY[TEXT])\r\n")

    header = (
        b"From: pieces@example.test\r\n"
        b"To: analyst@example.test\r\n"
        b"Subject: MULTI-LITERAL-SUBJECT-4A92\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
    )
    body = b"MULTI-LITERAL-BODY-8C15\r\n"

    flow.server(f"* 2 FETCH (BODY[HEADER] {{{len(header)}}}\r\n".encode())
    flow.server(header[:37])
    flow.server(header[37:91])
    flow.server(header[91:])
    body_marker = f" BODY[TEXT] {{{len(body)}}}\r\n".encode()
    flow.server(body_marker[:9])
    flow.server(body_marker[9:-1])
    flow.server(body_marker[-1:])
    flow.server(body[:8])
    flow.server(body[8:19])
    flow.server(body[19:])
    flow.server(b")\r\n", "multi_fetch_close")
    flow.server(b"B1 OK FETCH completed\r\n")
    flow.reset()


def response_first_fragmented_fetch():
    flow = TcpFlow("192.0.2.21", "192.0.2.22", 40003, 3000, 11000)
    message = (
        b"From: response-first@example.test\r\n"
        b"To: analyst@example.test\r\n"
        b"Subject: RESPONSE-FIRST-SUBJECT-2F63\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"RESPONSE-FIRST-BODY-6B04\r\n"
    )
    marker = f"* 7 FETCH (BODY[] {{{len(message)}}}\r\n".encode()
    flow.server(marker, "response_first_prefix")
    flow.server(message[:23])
    flow.server(message[23:79])
    flow.server(message[79:])
    flow.server(b")\r\n", "response_first_close")
    flow.reset()


large_fragmented_fetch()
multiple_fragmented_literals()
response_first_fragmented_fetch()

for timestamp, packet in enumerate(PACKETS, start=1):
    packet.time = timestamp

wrpcap("input.pcap", PACKETS)
for name, packet_number in LABELS.items():
    print(f"{name}: {packet_number}")
