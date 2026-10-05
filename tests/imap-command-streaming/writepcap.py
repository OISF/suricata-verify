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


def client_continuation_detection():
    flow = Flow(42010)
    append_email = (
        b'From: sender@example.test\r\nSubject: Continuation detection\r\n'
        b'Content-Type: text/plain\r\n\r\nSYNC-APPEND-DETECTION-BODY\r\n'
    )
    flow.send(True, b'* OK IMAP ready\r\n')
    flow.send(False, b'A1 APPEND INBOX {%d}\r\n' % len(append_email))
    flow.send(True, b'+ Ready for literal\r\n')
    flow.send(False, append_email + b'\r\n')
    flow.send(True, b'A1 OK APPEND completed\r\n')
    flow.send(False, b'A2 IDLE\r\n')
    flow.send(True, b'+ idling\r\n')
    flow.send(False, b'DONE\r\n')
    flow.send(True, b'A2 OK IDLE completed\r\n')
    flow.send(False, b'A3 AUTHENTICATE X-TEST\r\n')
    flow.send(True, b'+ first challenge\r\n')
    flow.send(False, b'FIRST-CONTINUATION-MARKER\r\n')
    flow.send(True, b'+ second challenge\r\n')
    flow.send(False, b'SECOND-CONTINUATION-MARKER\r\n')
    flow.send(True, b'A3 NO AUTHENTICATE failed\r\n')
    flow.send(False, b'A4 NOOP\r\n')
    flow.send(True, b'A4 OK NOOP completed\r\n')
    flow.send(False, b'A5 IDLE\r\n')
    flow.send(True, b'+ idling\r\n')
    flow.send(False, b'DO')
    flow.send(False, b'NE\r')
    flow.send(False, b'\n')
    flow.send(True, b'A5 OK IDLE completed\r\n')
    flow.send(False, b'A6 AUTHENTICATE X-TEST\r\n')
    flow.send(True, b'+ first challenge\r\n')
    flow.send(False, b'FIRST-CONTINUATION-')
    flow.send(False, b'MARKER\r\n')
    flow.send(True, b'+ second challenge\r\n')
    flow.send(False, b'SECOND-CONTINUATION-MARKER\r')
    flow.send(False, b'\n')
    flow.send(True, b'+ cancellation challenge\r\n')
    flow.send(False, b'*')
    flow.send(False, b'\r')
    flow.send(False, b'\n')
    flow.send(True, b'A6 BAD AUTHENTICATE cancelled\r\n')
    flow.send(False, b'A7 NOOP\r\n')
    flow.send(True, b'A7 OK NOOP completed\r\n')
    return flow.packets


def fetch_header_fields():
    flow = Flow(42020)
    flow.send(True, b'* OK IMAP ready\r\n')
    flow.send(False, b'A1 FETCH 1 BODY.PEEK[HEADER.FIELDS (SUBJECT FROM)]\r\n')
    headers = b'Subject: hello\r\nFrom: sender@example.test\r\n\r\n'
    flow.send(True,
              b'* 1 FETCH (BODY[HEADER.FIELDS (SUBJECT FROM)] {%d}\r\n' % len(headers)
              + headers + b')\r\nA1 OK FETCH completed\r\n')
    flow.send(False, b'A2 NOOP\r\n')
    flow.send(True, b'A2 OK NOOP completed\r\n')
    for chunk in [b'A3 FETCH 1 BODY[]<', b'0.', b'128>\r', b'\n']:
        flow.send(False, chunk)
        flow.send(True, flags='A')
    email = headers + b'STREAMED-PARTIAL-BODY'
    flow.send(True, b'* 1 FETCH (BODY[]<0> {%d}\r\n' % len(email)
              + email + b')\r\nA3 OK FETCH completed\r\n')
    flow.send(False, b'A4 SELECT BODY[Archive]suffix\r\n')
    flow.send(True, b'A4 OK SELECT completed\r\n')
    flow.send(False, b'A5 SELECT BODY[Archive\r\n')
    flow.send(True, b'A5 OK SELECT completed\r\n')
    for chunk in [b'A6 UID FETCH 1 body.peek[header.fields.not (TO)]<', b'0.128>\r\n']:
        flow.send(False, chunk)
        flow.send(True, flags='A')
    flow.send(True,
              b'* 1 FETCH (BODY[HEADER.FIELDS.NOT (TO)]<0> {%d}\r\n' % len(headers)
              + headers + b')\r\nA6 OK FETCH completed\r\n')
    flow.send(False, b'A7 FETCH 1 BODY[]\r\n')
    email = b'Subject: POST-ARGUMENT-SUBJECT\r\n\r\nAFTER-ARGUMENT-BODY'
    flow.send(True, b'* 1 FETCH (BODY[] {%d}\r\n' % len(email)
              + email + b')\r\nA7 OK FETCH completed\r\n')
    flow.send(False, b'A8 NOOP\r\n')
    flow.send(True, b'A8 OK NOOP completed\r\n')
    return flow.packets


def literal_arguments():
    flow = Flow(42030)
    flow.send(True, b'* OK IMAP ready\r\n')
    flow.send(False, b'A1 LOGIN {4+}\r\nuser {4+}\r\npass\r\n')
    flow.send(True, b'A1 OK LOGIN completed\r\n')
    flow.send(False, b'A2 SELECT {5}\r\n')
    flow.send(True, b'+ Ready for literal\r\n')
    flow.send(False, b'INBOX\r\n')
    flow.send(True, b'A2 OK [READ-WRITE] SELECT completed\r\n')
    flow.send(False, b'A3 CREATE {3+}\r\nfoo\r\n')
    flow.send(True, b'A3 OK CREATE completed\r\n')
    flow.send(False, b'A4 STATUS {5+}\r\nINBOX (MESSAGES UNSEEN)\r\n')
    flow.send(True, b'* STATUS INBOX (MESSAGES 1 UNSEEN 0)\r\nA4 OK STATUS completed\r\n')
    flow.send(False, b'A5 NOOP\r\n')
    flow.send(True, b'A5 OK NOOP completed\r\n')
    flow.send(False, b'A6 SEARCH (SUBJECT {3}\r\n')
    flow.send(True, b'+ Ready for literal\r\n')
    flow.send(False, b'foo)\r\n')
    flow.send(True, b'A6 OK SEARCH completed\r\n')
    for chunk in [
        b'A7 SEARCH ((SUBJECT {', b'4+}\r', b'\n)(',
        b'{} BODY {0+}\r\n)', b') UNSEEN\r', b'\n',
    ]:
        flow.send(False, chunk)
        flow.send(True, flags='A')
    flow.send(True, b'A7 OK SEARCH completed\r\n')
    flow.send(False, b'A8 CREATE "{5+}"\r\nA9 CREATE "{3}"\r\n')
    flow.send(True, b'A8 OK CREATE completed\r\nA9 OK CREATE completed\r\n')
    flow.send(False, b'A10 RENAME {3+}\r\nfoo "{5+}"\r\n')
    flow.send(True, b'A10 OK RENAME completed\r\n')
    flow.send(False, b'A11 NOOP\r\n')
    flow.send(True, b'A11 OK NOOP completed\r\n')
    flow.send(False, b'A12 SEARCH (SUBJECT {3}\r\n')
    flow.send(True, b'A12 NO SEARCH rejected\r\n')
    flow.send(False, b'A13 NOOP\r\n')
    flow.send(True, b'A13 OK NOOP completed\r\n')
    return flow.packets

packets = []
timestamp = 1_000_000
for scenario, interval in [
    (client_continuation_detection, 1000000),
    (fetch_header_fields, 1000000),
    (literal_arguments, 1000000),
]:
    for pkt in scenario():
        pkt.time = Decimal(timestamp) / 1_000_000
        packets.append(pkt)
        timestamp += interval

wrpcap("input.pcap", packets)
