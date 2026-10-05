#!/usr/bin/env python3
"""Generate input.pcap without changing the original scenarios' packet boundaries."""

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


def append_frames():
    flow = Flow(42010)
    flow.send(True, b'* OK IMAP ready\r\n')
    # Whole literal in one segment.
    single = b'Subject: single\r\n\r\nSINGLE-BODY\r\n'
    flow.send(False, b'A1 APPEND INBOX {%d}\r\n' % len(single))
    flow.send(True, b'+ Ready for literal data\r\n')
    flow.send(False, single + b'\r\n')
    flow.send(True, b'A1 OK APPEND completed\r\n')
    # Literal split inside the body. The server ACK between the segments makes
    # the stream engine hand the first one to the parser on its own.
    split = b'Subject: split\r\n\r\nSPLIT-BODY line one\r\nSPLIT-BODY line two\r\n'
    cut = split.index(b'SPLIT-BODY line two')
    flow.send(False, b'A2 APPEND INBOX {%d}\r\n' % len(split))
    flow.send(True, b'+ Ready for literal data\r\n')
    flow.send(False, split[:cut])
    flow.send(True, flags='A')
    flow.send(False, split[cut:] + b'\r\n')
    flow.send(True, b'A2 OK APPEND completed\r\n')
    # FETCH literal split across two server segments, as control.
    fsplit = b'Subject: fsplit\r\n\r\nFSPLIT-BODY\r\n'
    cut = fsplit.index(b'FSPLIT-BODY') + 1
    flow.send(False, b'A3 FETCH 1 BODY[]\r\n')
    flow.send(True, b'* 1 FETCH (BODY[] {%d}\r\n' % len(fsplit) + fsplit[:cut])
    flow.send(False, flags='A')
    flow.send(True, fsplit[cut:] + b')\r\nA3 OK FETCH completed\r\n')
    # LITERAL+, split between the last header line and the blank line so the
    # CRLFCRLF boundary straddles the segments.
    hsplit = b'Subject: hsplit\r\n\r\nHSPLIT-BODY\r\n'
    cut = hsplit.index(b'\r\n\r\n') + 2
    flow.send(False, b'A4 APPEND INBOX {%d+}\r\n' % len(hsplit) + hsplit[:cut])
    flow.send(True, flags='A')
    flow.send(False, hsplit[cut:] + b'\r\n')
    flow.send(True, b'A4 OK APPEND completed\r\n')
    # Parsing must still be active after the literals.
    flow.send(False, b'A5 NOOP\r\n')
    flow.send(True, b'A5 OK NOOP completed\r\n')
    return flow.packets


def frame_tx_association():
    flow = Flow(42020)
    flow.send(True, b'* OK IMAP ready\r\n')
    # Transaction 1: FETCH producing a body frame with a distinctive marker.
    body = b'From: a@b.test\r\nSubject: s\r\n\r\nFETCHBODYMARKER\r\n'
    flow.send(False, b'A1 FETCH 1 BODY[]\r\n')
    flow.send(True, b'* 1 FETCH (BODY[] {%d}\r\n' % len(body)
              + body + b')\r\nA1 OK FETCH completed\r\n')
    # Transaction 2: a distinctive APPEND that must NOT be the body frame's tx.
    flow.send(False, b'A2 APPEND INBOX {5+}\r\nhello\r\n')
    flow.send(True, b'A2 OK APPEND completed\r\n')
    flow.send(False, b'A3 NOOP\r\n')
    flow.send(True, b'A3 OK NOOP completed\r\n')
    return flow.packets

packets = []
timestamp = 1_000_000
for scenario, interval in [
    (append_frames, 1000000),
    (frame_tx_association, 1000000),
]:
    for pkt in scenario():
        pkt.time = Decimal(timestamp) / 1_000_000
        packets.append(pkt)
        timestamp += interval

wrpcap("input.pcap", packets)
