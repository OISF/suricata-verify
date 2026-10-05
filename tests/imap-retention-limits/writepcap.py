#!/usr/bin/env python3

from decimal import Decimal

from scapy.all import Ether, IP, Raw, TCP, wrpcap


class Flow:
    def __init__(self, port, server_port=143, window=65535, seq=(1000, 9000)):
        self.port = port
        self.server_port = server_port
        self.window = window
        self.seq = list(seq)
        self.packets = []
        self.send(False, flags="S")
        self.send(True, flags="SA")
        self.send(False, flags="A")

    def send(self, server, payload=b"", flags="PA"):
        client = ("02:00:00:00:00:01", "192.0.2.1", self.port)
        peer = ("02:00:00:00:00:02", "192.0.2.2", self.server_port)
        src, dst = (peer, client) if server else (client, peer)
        pkt = (
            Ether(src=src[0], dst=dst[0])
            / IP(src=src[1], dst=dst[1])
            / TCP(sport=src[2], dport=dst[2], seq=self.seq[server],
                  ack=0 if flags == "S" else self.seq[not server],
                  flags=flags, window=self.window)
        )
        self.packets.append(pkt / Raw(load=payload) if payload else pkt)
        self.seq[server] += len(payload) + ("S" in flags) + ("F" in flags)


def body_too_large():
    flow = Flow(42010, seq=(1000, 2000))
    flow.send(True, b'* OK IMAP4rev1 Service Ready\r\n', flags='PA')
    flow.send(False, b'', flags='A')
    flow.send(False, b'A001 APPEND INBOX {10485813+}\r\n', flags='PA')
    flow.send(True, b'', flags='A')
    flow.send(False, b'From: test@example.com\r\nSubject: Large body test\r\n\r\n'
              + b'X' * 59948)
    for _ in range(173):
        flow.send(True, b'', flags='A')
        flow.send(False, b'X' * 60000, flags='PA')
    flow.send(True, b'', flags='A')
    flow.send(False, b'X' * 45813 + b'\r\n', flags='PA')
    flow.send(True, b'', flags='A')
    flow.send(True, b'A001 OK APPEND completed\r\n', flags='PA')
    flow.send(False, b'', flags='A')
    flow.send(False, b'A002 LOGOUT\r\n', flags='PA')
    flow.send(True, b'', flags='A')
    flow.send(True, b'* BYE Server logging out\r\nA002 OK LOGOUT completed\r\n', flags='PA')
    flow.send(False, b'', flags='A')
    flow.send(False, b'', flags='FA')
    flow.send(True, b'', flags='FA')
    flow.send(False, b'', flags='A')
    return flow.packets


def fetch_metadata_limit():
    flow = Flow(42020)
    def server(payload):
        for offset in range(0, len(payload), 1093):
            flow.send(True, payload[offset:offset + 1093])
            flow.send(False, flags="A")

    server(b"* OK IMAP ready\r\n")
    flow.send(False, b"A1 FETCH 1 BODY[TEXT]\r\n")
    early, late = b"EARLY-METADATA-BODY", b"LATE-METADATA-BODY"
    response = b"* 1 FETCH (BODY[TEXT] {%d}\r\n%s" % (len(early), early)
    response += b" BODY[TEXT] {0}\r\n" * 2000
    response += b" BODY[TEXT] {%d}\r\n%s)\r\nA1 OK FETCH completed\r\n" % (len(late), late)
    server(response)
    flow.send(False, b"A2 NOOP\r\n")
    server(b"A2 OK NOOP completed\r\n")
    return flow.packets


def retention_completion():
    flow = Flow(42030)
    flow.send(True, b"* OK IMAP ready\r\n")
    flow.send(False, b"A1 FETCH 1:* BODY[]\r\n")
    early = b"From: a@example.test\r\nSubject: early\r\n\r\nEARLY-IMAP-MARKER\r\n"
    late = b"From: z@example.test\r\nSubject: late\r\n\r\nLATE-IMAP-MARKER\r\n"
    body = early + b"X" * (30000 - len(early))
    for sequence in range(1, 401):
        flow.send(True, b"* %d FETCH (BODY[] {%d}\r\n%s)\r\n" % (sequence, len(body), body))
        flow.send(False, flags="A")
    flow.send(True, b"* 99 FETCH (BODY[] {%d}\r\n%s)\r\n" % (len(late), late))
    flow.send(False, flags="A")
    flow.send(True, b"A1 OK FETCH completed\r\n")
    flow.send(False, flags="A")
    flow.send(False, b"A2 NOOP\r\n")
    flow.send(True, b"A2 OK NOOP completed\r\n")
    return flow.packets

packets = []
timestamp = 1_000_000
for scenario, interval in [
    (body_too_large, 1000),
    (fetch_metadata_limit, 1000000),
    (retention_completion, 1000000),
]:
    for pkt in scenario():
        pkt.time = Decimal(timestamp) / 1_000_000
        packets.append(pkt)
        timestamp += interval

wrpcap("input.pcap", packets)
