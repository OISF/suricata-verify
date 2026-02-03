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


def fetch_quoted_body():
    flow = Flow(42010)
    flow.send(True, b'* OK IMAP ready\r\n')
    flow.send(False, b'A1 FETCH 1 BODY[TEXT]\r\n')
    flow.send(True, b'* 1 FETCH (BODY[TEXT] "QUOTED-EVASION-BODY-7A1C")\r\n'
                   b'A1 OK FETCH completed\r\n')
    control = b'LITERAL-CONTROL-BODY-9E42'
    flow.send(False, b'A2 FETCH 2 BODY[TEXT]\r\n')
    flow.send(True, b'* 2 FETCH (BODY[TEXT] {%d}\r\n' % len(control)
              + control + b')\r\nA2 OK FETCH completed\r\n')
    flow.send(False, b'A3 NOOP\r\n')
    flow.send(True, b'A3 OK NOOP completed\r\n')
    return flow.packets


def fetch_partial_body():
    flow = Flow(42020)
    flow.send(True, b'* OK IMAP ready\r\n')
    frag = b'PARTIAL-BODY-CHUNK-5B2E'
    flow.send(False, b'A1 FETCH 1 BODY[]<1024>\r\n')
    flow.send(True, b'* 1 FETCH (BODY[]<1024> {%d}\r\n' % len(frag)
              + frag + b')\r\nA1 OK FETCH completed\r\n')
    first = b'Subject: chunked\r\n\r\nFIRST-CHUNK-BODY-1A7F\r\n'
    flow.send(False, b'A2 FETCH 1 BODY[]<0>\r\n')
    flow.send(True, b'* 1 FETCH (BODY[]<0> {%d}\r\n' % len(first)
              + first + b')\r\nA2 OK FETCH completed\r\n')
    full = b'Subject: full\r\n\r\nFULL-CONTROL-BODY-9C31\r\n'
    flow.send(False, b'A3 FETCH 2 BODY[]\r\n')
    flow.send(True, b'* 2 FETCH (BODY[] {%d}\r\n' % len(full)
              + full + b')\r\nA3 OK FETCH completed\r\n')
    flow.send(False, b'A4 NOOP\r\n')
    flow.send(True, b'A4 OK NOOP completed\r\n')
    return flow.packets


def multi_message_fetch():
    flow = Flow(42030, window=8192)
    def fetch(sequence, message):
        return b"* %d FETCH (BODY[] {%d}\r\n%s)\r\n" % (sequence, len(message), message)

    first = (
        b"From: first@example.test\r\nTo: analyst@example.test\r\n"
        b"Subject: First fetch control\r\nMessage-ID: <first@example.test>\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"Content-Transfer-Encoding: 7bit\r\n\r\nFIRST-BODY-CONTROL-71A2\r\n"
    )
    second = (
        b"From: second@example.test\r\nTo: analyst@example.test\r\n"
        b"Subject: SECOND-SUBJECT-ONLY-9F52\r\nMessage-ID: <second@example.test>\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"Content-Transfer-Encoding: 7bit\r\n\r\nSECOND-BODY-ONLY-8E41\r\n"
    )
    flow.send(True, b"* OK IMAP server ready\r\n")
    flow.send(False, b"A1 FETCH 1:* BODY[]\r\n")
    flow.send(True, fetch(1, first) + fetch(2, second) + b"A1 OK FETCH completed\r\n")
    return flow.packets

packets = []
timestamp = 1_000_000
for scenario, interval in [
    (fetch_quoted_body, 1000000),
    (fetch_partial_body, 1000000),
    (multi_message_fetch, 1000000),
]:
    for pkt in scenario():
        pkt.time = Decimal(timestamp) / 1_000_000
        packets.append(pkt)
        timestamp += interval

wrpcap("input.pcap", packets)
