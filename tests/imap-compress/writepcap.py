#!/usr/bin/env python3

import zlib
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


def accepted():
    flow = Flow(42010)
    deflate = [zlib.compressobj(wbits=-15), zlib.compressobj(wbits=-15)]

    def compressed(server, data):
        z = deflate[server]
        return z.compress(data) + z.flush(zlib.Z_SYNC_FLUSH)

    flow.send(True, b'* OK IMAP ready\r\n')
    flow.send(False, b'A1 COMPRESS DEFLATE\r\n')
    # The server compresses right after its reply, here in the same segment.
    flow.send(True, b'A1 OK DEFLATE active\r\n'
              + compressed(True, b'* 3 EXISTS\r\n'))
    flow.send(False, compressed(False, b'A2 LOGIN alice secret\r\n'))
    flow.send(True, compressed(True, b'A2 OK LOGIN completed\r\n'))
    for i in range(3, 40):
        flow.send(False, compressed(False, b'A%d FETCH %d (BODY[])\r\n' % (i, i)))
        flow.send(True, compressed(
            True, b'* %d FETCH (BODY[] {12}\r\nSECRET-%05d)\r\nA%d OK done\r\n' % (i, i, i)))
    return flow.packets


def rejected():
    flow = Flow(42020)
    flow.send(True, b'* OK IMAP ready\r\n')
    flow.send(False, b'A1 COMPRESS DEFLATE\r\n')
    flow.send(True, b'A1 NO DEFLATE not available\r\n')
    flow.send(False, b'A2 NOOP\r\n')
    flow.send(True, b'A2 OK NOOP completed\r\n')
    return flow.packets


def after_authenticate():
    # The server reads the second line as the SASL response, so the OK is
    # the reply to NOOP: COMPRESS was never accepted.
    flow = Flow(42030)
    flow.send(True, b'* OK IMAP ready\r\n')
    flow.send(False, b'a AUTHENTICATE PLAIN\r\nx COMPRESS DEFLATE\r\nx NOOP\r\n')
    flow.send(True, b'+ \r\n')
    flow.send(True, b'a BAD invalid base64\r\n')
    flow.send(True, b'x OK NOOP completed\r\n')
    flow.send(False, b'A9 LOGIN alice secret\r\n')
    flow.send(True, b'A9 OK LOGIN completed\r\n')
    return flow.packets


def after_literal():
    # The server reads the second line as the literal of LOGIN.
    flow = Flow(42040)
    flow.send(True, b'* OK IMAP ready\r\n')
    flow.send(False, b'a LOGIN {18}\r\nx COMPRESS DEFLATE\r\n')
    flow.send(True, b'+ Ready\r\n')
    flow.send(False, b' pw\r\nx NOOP\r\n')
    flow.send(True, b'a NO LOGIN failed\r\n')
    flow.send(True, b'x OK NOOP completed\r\n')
    flow.send(False, b'A9 LOGIN alice secret\r\n')
    flow.send(True, b'A9 OK LOGIN completed\r\n')
    return flow.packets


def uid_prefix():
    # UID COMPRESS is no COMPRESS command, whatever the server answers.
    flow = Flow(42050)
    flow.send(True, b'* OK IMAP ready\r\n')
    flow.send(False, b'A1 UID COMPRESS DEFLATE\r\n')
    flow.send(True, b'A1 OK done\r\n')
    flow.send(False, b'A9 LOGIN alice secret\r\n')
    flow.send(True, b'A9 OK LOGIN completed\r\n')
    return flow.packets


packets = []
timestamp = 1_000_000
for scenario in [accepted, rejected, after_authenticate, after_literal, uid_prefix]:
    for pkt in scenario():
        pkt.time = Decimal(timestamp) / 1_000_000
        packets.append(pkt)
        timestamp += 1000

wrpcap("input.pcap", packets)
