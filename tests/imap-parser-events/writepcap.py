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


def invalid_lines():
    flow = Flow(42020, seq=(1000, 2000))
    flow.send(True, b'* OK IMAP4rev1 Service Ready\r\n', flags='PA')
    flow.send(False, b'', flags='A')
    flow.send(False, b'A000 NOOP\r\n', flags='PA')
    flow.send(True, b'', flags='A')
    flow.send(True, b'A000 OK NOOP completed\r\n', flags='PA')
    flow.send(False, b'', flags='A')
    # A NUL in a quoted string, an unterminated list, a bare CR and 300 more invalid
    # lines: each is skipped, A004 is still parsed.
    flow.send(False, b'A001 NOOP "a\x00b"\r\nA002 NOOP (\r\nA003 NOOP\rx\r\n'
              + b'%%%\r\n' * 300 + b'A004 NOOP\r\n', flags='PA')
    flow.send(True, b'', flags='A')
    flow.send(True, b'A001 BAD invalid string\r\nA002 WHAT\r\n'
              b'A004 OK NOOP completed\r\n', flags='PA')
    flow.send(False, b'', flags='A')
    # A new run of invalid lines; the frame of A006 starts at A006.
    flow.send(False, b'A005 NOOP (\r\nA006 NOOP\r\n', flags='PA')
    flow.send(True, b'', flags='A')
    flow.send(True, b'A005 BAD unterminated list\r\nA006 OK NOOP completed\r\n', flags='PA')
    flow.send(False, b'', flags='A')
    flow.send(False, b'', flags='FA')
    flow.send(True, b'', flags='FA')
    flow.send(False, b'', flags='A')
    return flow.packets


def invalid_continuation():
    flow = Flow(42030, seq=(1000, 2000))
    flow.send(True, b'* OK IMAP4rev1 Service Ready\r\n', flags='PA')
    flow.send(False, b'', flags='A')
    flow.send(False, b'A001 IDLE\r\n', flags='PA')
    flow.send(True, b'', flags='A')
    flow.send(True, b'+ idling\r\n', flags='PA')
    flow.send(False, b'', flags='A')
    # A continuation line with a bare CR, whose LF comes in a later segment:
    # it is skipped once it ends, and DONE still ends the IDLE.
    flow.send(False, b'DO\rNE', flags='PA')
    flow.send(True, b'', flags='A')
    flow.send(False, b'\r\nDONE\r\nA002 NOOP\r\n', flags='PA')
    flow.send(True, b'', flags='A')
    flow.send(True, b'A001 OK IDLE terminated\r\nA002 OK NOOP completed\r\n', flags='PA')
    flow.send(False, b'', flags='A')
    flow.send(False, b'', flags='FA')
    flow.send(True, b'', flags='FA')
    flow.send(False, b'', flags='A')
    return flow.packets


def stale_authenticate():
    flow = Flow(42040, seq=(1000, 2000))
    flow.send(True, b'* OK IMAP4rev1 Service Ready\r\n', flags='PA')
    flow.send(False, b'', flags='A')
    flow.send(False, b'A001 AUTHENTICATE PLAIN\r\n', flags='PA')
    flow.send(True, b'', flags='A')
    flow.send(True, b'+ \r\n', flags='PA')
    flow.send(False, b'', flags='A')
    flow.send(False, b'AHVzZXIAcGFzcw==\r\n', flags='PA')
    flow.send(True, b'', flags='A')
    # The tagged reply of A001 is never seen. Once the client sends another
    # command, an invalid line is no longer taken as data of A001.
    flow.send(False, b'A002 NOOP\r\n', flags='PA')
    flow.send(True, b'', flags='A')
    flow.send(True, b'A002 OK NOOP completed\r\n', flags='PA')
    flow.send(False, b'', flags='A')
    flow.send(False, b'%%%\r\nA003 NOOP\r\n', flags='PA')
    flow.send(True, b'', flags='A')
    flow.send(True, b'A003 OK NOOP completed\r\n', flags='PA')
    flow.send(False, b'', flags='A')
    flow.send(False, b'', flags='FA')
    flow.send(True, b'', flags='FA')
    flow.send(False, b'', flags='A')
    return flow.packets


packets = []
timestamp = 1_000_000
for scenario, interval in [
    (line_too_long, 1000),
    (invalid_lines, 1000),
    (invalid_continuation, 1000),
    (stale_authenticate, 1000),
]:
    for pkt in scenario():
        pkt.time = Decimal(timestamp) / 1_000_000
        packets.append(pkt)
        timestamp += interval

wrpcap("input.pcap", packets)
