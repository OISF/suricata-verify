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


def response_line_count():
    flow = Flow(42010, window=8192)
    flow.send(True, b"* OK IMAP ready\r\n")
    flow.send(False, b"A1 NOOP\r\n")
    flow.send(True, b"".join(b"* %d EXISTS\r\n" % i for i in range(1, 513)))
    flow.send(True, b"A1 OK NOOP completed\r\n")
    flow.send(False, b"A2 NOOP\r\n")
    flow.send(True, b"A2 OK NOOP completed\r\n")
    return flow.packets


def email_count_limit():
    flow = Flow(42020, window=8192)
    flow.send(True, b"* OK IMAP ready\r\n")
    flow.send(False, b"A1 FETCH 1:* BODY[]\r\n")
    email = b"Subject: count limit\r\n\r\nx"
    fetches = [b"* %d FETCH (BODY[] {%d}\r\n%s)\r\n" % (i, len(email), email)
               for i in range(1, 514)]
    for offset in range(0, 500, 100):
        flow.send(True, b"".join(fetches[offset:offset + 100]))
        flow.send(False, flags="A")
    flow.send(True, b"".join(fetches[500:]) + b"A1 OK FETCH completed\r\n")
    flow.send(False, b"A2 NOOP\r\n")
    flow.send(True, b"A2 OK NOOP completed\r\n")
    return flow.packets

packets = []
timestamp = 1_000_000
for scenario, interval in [
    (response_line_count, 1000000),
    (email_count_limit, 1000000),
]:
    for pkt in scenario():
        pkt.time = Decimal(timestamp) / 1_000_000
        packets.append(pkt)
        timestamp += interval

wrpcap("input.pcap", packets)
