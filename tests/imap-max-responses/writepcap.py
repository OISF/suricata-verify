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

    def send_segmented(self, server, payload):
        # Each acknowledged segment hands the incomplete line to the parser
        # again.
        for offset in range(0, len(payload), 1460):
            self.send(server, payload[offset:offset + 1460])
            self.send(not server, flags="A")


flow = Flow(42060)
flow.send_segmented(True, b"* OK IMAP ready\r\n")
# Two lines past the limit of 3.
flow.send_segmented(False, b"A1 UID FETCH 1:* (FLAGS)\r\n")
flow.send_segmented(True, b"".join(b"* %d FETCH (UID %d FLAGS ())\r\n" % (n, n) for n in range(1, 6))
                    + b"A1 OK UID FETCH completed\r\n")
# Exactly the limit.
flow.send_segmented(False, b"A2 NOOP\r\n")
flow.send_segmented(True, b"".join(b"* %d EXISTS\r\n" % n for n in range(1, 4))
                    + b"A2 OK NOOP completed\r\n")
flow.send_segmented(False, b"A3 NOOP\r\n")
flow.send_segmented(True, b"A3 OK NOOP completed\r\n")

timestamp = 1_000_000
for pkt in flow.packets:
    pkt.time = Decimal(timestamp) / 1_000_000
    timestamp += 1000

wrpcap("input.pcap", flow.packets)
