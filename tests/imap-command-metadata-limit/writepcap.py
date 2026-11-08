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


def command_metadata_limit():
    def send(flow, server, payload):
        for offset in range(0, len(payload), 4096):
            flow.send(server, payload[offset:offset + 4096])
            flow.send(not server, flags="A")

    flow = Flow(42010)
    send(flow, True, b"* OK IMAP ready\r\n")
    send(flow, False, b'A1 SEARCH' + b' ""' * 100000 + b'\r\n')
    send(flow, True, b"A1 OK SEARCH completed\r\n")
    send(flow, False, b"A2 " + b"X" * 50000 + b"\r\n")
    send(flow, True, b"A2 BAD unknown command\r\n")
    send(flow, False, b'A3 SEARCH' + b' ""' * 5000 + b' {3+}\r\nfoo SUBJECT secret\r\n')
    send(flow, True, b"A3 OK SEARCH completed\r\n")
    send(flow, False, b'A4 LOGIN "' + b'u' * 50000 + b'" hidden-password\r\n')
    send(flow, True, b"A4 OK LOGIN completed\r\n")
    tag = b"T" * 8192
    send(flow, False, tag + b" NOOP\r\n")
    send(flow, True, tag + b" OK done\r\n")
    send(flow, False, b"A9 NOOP\r\n")
    send(flow, True, b"A9 OK NOOP completed\r\n")
    result = flow.packets
    for port, server in [(42010 + 1, False), (42010 + 2, True)]:
        flow = Flow(port)
        send(flow, True, b"* OK IMAP ready\r\n")
        send(flow, server, b"T" * 8193)
        send(flow, server, b" OK rejected\r\n" if server else b" NOOP\r\n")
        send(flow, False, b"A9 NOOP\r\n")
        send(flow, True, b"A9 OK NOOP completed\r\n")
        result.extend(flow.packets)
    return result


def oversized_command_argument():
    flow = Flow(42020)
    flow.send(True, b'* OK IMAP ready\r\n')
    oversized = b'x' * 50000
    flow.send(False, b'A1 CREATE "' + oversized + b'"\r\n')
    flow.send(True, b'A1 OK CREATE completed\r\n')
    flow.send(False, b'A2 NOOP\r\n')
    flow.send(True, b'A2 OK NOOP completed\r\n')
    return flow.packets

packets = []
timestamp = 1_000_000
for scenario, interval in [
    (command_metadata_limit, 1000),
    (oversized_command_argument, 1000000),
]:
    for pkt in scenario():
        pkt.time = Decimal(timestamp) / 1_000_000
        packets.append(pkt)
        timestamp += interval

wrpcap("input.pcap", packets)
