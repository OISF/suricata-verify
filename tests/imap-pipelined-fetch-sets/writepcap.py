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


flow = Flow(42040)
flow.send_segmented(True, b"* OK IMAP ready\r\n")

# Pending FETCHes whose 8 KiB sets never match the responses below.
requests = b"".join(
    b"B%d FETCH %s (FLAGS)\r\n" % (i, b",".join([b"1"] * 4080)) for i in range(1, 33))
# One target per sequence number, and a set with as many ranges as kept.
requests += b"".join(b"T%d FETCH %d (FLAGS)\r\n" % (n, n) for n in range(2, 12))
requests += b"R1 FETCH %s (FLAGS)\r\n" % b",".join(b"%d" % n for n in range(1001, 1129, 2))
flow.send_segmented(False, requests)

responses = b""
for n in range(2, 12):
    responses += b"* %d FETCH (FLAGS ())\r\n" % n * 500
    responses += b"T%d OK FETCH completed\r\n" % n
responses += b"* 1003 FETCH (FLAGS ())\r\nR1 OK FETCH completed\r\n"
responses += b"".join(b"B%d OK FETCH completed\r\n" % i for i in range(1, 33))
flow.send_segmented(True, responses)

flow.send_segmented(False, b"A1 NOOP\r\n")
flow.send_segmented(True, b"A1 OK NOOP completed\r\n")

packets = flow.packets

# A set longer than a line is truncated mid-number, so it cannot rule out the
# number of a response that follows.
flow = Flow(42041)
flow.send_segmented(True, b"* OK IMAP ready\r\n")
flow.send_segmented(False, b"L1 FETCH %s (FLAGS)\r\n"
                    % b",".join(b"%d" % n for n in range(1, 3001)))
flow.send_segmented(True, b"* 2900 FETCH (FLAGS ())\r\nL1 OK FETCH completed\r\n")
# A number past u32 is unknown, so the set cannot rule it out either.
flow.send_segmented(False, b"O1 FETCH 1:5 (FLAGS)\r\n")
flow.send_segmented(True, b"* 99999999999 FETCH (FLAGS ())\r\nO1 OK FETCH completed\r\n")
packets += flow.packets

timestamp = 1_000_000
for pkt in packets:
    pkt.time = Decimal(timestamp) / 1_000_000
    timestamp += 1000

wrpcap("input.pcap", packets)
