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


def send(flow, server, payload):
    for offset in range(0, len(payload), 8192):
        flow.send(server, payload[offset:offset + 8192])
        flow.send(not server, flags="A")


flow = Flow(42010)
send(flow, True, b"* OK IMAP ready\r\n")
send(flow, False, b"A1 FETCH 1:140 (ENVELOPE)\r\n")
# More than the 1 MiB of lines retained per flow.
for i in range(1, 141):
    send(flow, True, b"* %d FETCH (ENVELOPE (" % i + b"x" * 8000 + b"))\r\n")
# Short lines use up what is left of it.
send(flow, True, b"* 9 EXPUNGE\r\n" * 400)
# Sent while the transaction holding the whole budget is still open.
send(flow, False, b"A2 SEARCH TEXT hello\r\n")
send(flow, True, b"A1 OK [HIGHESTMODSEQ 715194045007] FETCH completed\r\n")
send(flow, True, b"* SEARCH 4 7\r\nA2 OK SEARCH completed\r\n")

timestamp = 1_000_000
for pkt in flow.packets:
    pkt.time = Decimal(timestamp) / 1_000_000
    timestamp += 1000

wrpcap("input.pcap", flow.packets)
