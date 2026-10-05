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


def list_wildcards():
    flow = Flow(42010)
    flow.send(True, b'* OK IMAP ready\r\n')
    flow.send(False, b'A1 LIST "" %\r\n')
    flow.send(True, b'* LIST (\\HasNoChildren) "/" INBOX\r\n'
                   b'* LIST (\\HasChildren) "/" Archive\r\nA1 OK LIST completed\r\n')
    flow.send(False, b'A2 LIST "" Archive/%\r\n')
    flow.send(True, b'* LIST (\\HasNoChildren) "/" Archive/2025\r\nA2 OK LIST completed\r\n')
    flow.send(False, b'A3 LSUB "" *\r\n')
    flow.send(True, b'* LSUB () "/" INBOX\r\nA3 OK LSUB completed\r\n')
    flow.send(False, b'A4 FETCH 1:* (FLAGS)\r\n')
    flow.send(True, b'* 1 FETCH (FLAGS (\\Seen))\r\nA4 OK FETCH completed\r\n')
    flow.send(False, b'A5 NOOP\r\n')
    flow.send(True, b'A5 OK NOOP completed\r\n')
    return flow.packets


def store_flags():
    flow = Flow(42020)
    flow.send(True, b'* OK IMAP ready\r\n')
    flow.send(False, b'A1 STORE 1 +FLAGS \\Seen\r\n')
    flow.send(True, b'* 1 FETCH (FLAGS (\\Seen))\r\nA1 OK STORE completed\r\n')
    flow.send(False, b'A2 STORE 1 FLAGS \\Seen \\Deleted\r\n')
    flow.send(True, b'* 1 FETCH (FLAGS (\\Seen \\Deleted))\r\nA2 OK STORE completed\r\n')
    flow.send(False, b'A3 STORE 2:4 -FLAGS.SILENT \\Answered\r\n')
    flow.send(True, b'A3 OK STORE completed\r\n')
    flow.send(False, b'A4 STORE 1 +FLAGS (\\Seen)\r\n')
    flow.send(True, b'* 1 FETCH (FLAGS (\\Seen))\r\nA4 OK STORE completed\r\n')
    flow.send(False, b'A5 NOOP\r\n')
    flow.send(True, b'A5 OK NOOP completed\r\n')
    return flow.packets


def quoted_grammar():
    flow = Flow(42030)
    flow.send(True, b'* OK IMAP ready\r\n')
    flow.send(False, b'A1 ID ("name" "value ) ( \\"quoted\\" \\\\folder")\r\n')
    flow.send(True, b'A1 OK ID completed\r\n')
    flow.send(False, b'A2 FETCH 1 BODYSTRUCTURE\r\n')
    flow.send(True, b'* 1 FETCH (BODYSTRUCTURE ("TEXT" "PLAIN" ("NAME" "a)b") '
                   b'NIL NIL "7BIT" 12 1))\r\n')
    flow.send(True, b'A2 OK FETCH completed\r\n')
    flow.send(False, b'A3 NOOP\r\n')
    flow.send(True, b'A3 OK NOOP completed\r\n')
    return flow.packets

packets = []
timestamp = 1_000_000
for scenario, interval in [
    (list_wildcards, 1000000),
    (store_flags, 1000000),
    (quoted_grammar, 1000000),
]:
    for pkt in scenario():
        pkt.time = Decimal(timestamp) / 1_000_000
        packets.append(pkt)
        timestamp += interval

wrpcap("input.pcap", packets)
