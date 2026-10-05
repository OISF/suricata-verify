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


def line_too_long():
    flow = Flow(42010, seq=(1000, 2000))
    flow.send(True, b'* OK IMAP4rev1 Service Ready\r\n', flags='PA')
    flow.send(False, b'', flags='A')
    flow.send(False, b'A001 NOOP ' + b'X' * 9000 + b'\r\n', flags='PA')
    flow.send(True, b'', flags='A')
    flow.send(True, b'A001 OK NOOP completed\r\n', flags='PA')
    flow.send(False, b'', flags='A')
    flow.send(False, b'A002 LOGOUT\r\n', flags='PA')
    flow.send(True, b'', flags='A')
    flow.send(True, b'* BYE Server logging out\r\nA002 OK LOGOUT completed\r\n', flags='PA')
    flow.send(False, b'', flags='A')
    flow.send(False, b'', flags='FA')
    flow.send(True, b'', flags='FA')
    flow.send(False, b'', flags='A')
    return flow.packets


def too_many_headers():
    flow = Flow(42020, seq=(1000, 2000))
    flow.send(True, b'* OK IMAP4rev1 Service Ready\r\n', flags='PA')
    flow.send(False, b'', flags='A')
    flow.send(False, b'A001 SELECT INBOX\r\n', flags='PA')
    flow.send(True, b'', flags='A')
    flow.send(True, b'* 1 EXISTS\r\n* 0 RECENT\r\n'
                   b'* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n'
                   b'A001 OK [READ-WRITE] SELECT completed\r\n')
    flow.send(False, b'', flags='A')
    flow.send(False, b'A002 FETCH 1 (BODY[])\r\n', flags='PA')
    flow.send(True, b'', flags='A')
    headers = b''.join(f'X-Header-{i}: value{i}\r\n'.encode() for i in range(514))
    flow.send(True, b'* 1 FETCH (BODY[] {12130}\r\n' + headers
              + b'\r\nHello World!)\r\nA002 OK FETCH completed\r\n')
    flow.send(False, b'', flags='A')
    flow.send(False, b'A003 LOGOUT\r\n', flags='PA')
    flow.send(True, b'', flags='A')
    flow.send(True, b'* BYE Server logging out\r\nA003 OK LOGOUT completed\r\n', flags='PA')
    flow.send(False, b'', flags='A')
    flow.send(False, b'', flags='FA')
    flow.send(True, b'', flags='FA')
    flow.send(False, b'', flags='A')
    return flow.packets

packets = []
timestamp = 1_000_000
for scenario, interval in [
    (line_too_long, 1000),
    (too_many_headers, 1000),
]:
    for pkt in scenario():
        pkt.time = Decimal(timestamp) / 1_000_000
        packets.append(pkt)
        timestamp += interval

wrpcap("input.pcap", packets)
