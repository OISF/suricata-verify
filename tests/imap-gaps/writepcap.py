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


def lose(flow, server, payload):
    # The segment is never captured; the peer's next ACK covers it.
    flow.seq[server] += len(payload)


def send(flow, server, payload):
    flow.send(server, payload)
    flow.send(not server, flags="A")


def start(port):
    flow = Flow(port)
    send(flow, True, b"* OK IMAP ready\r\n")
    return flow


def finish(flow):
    send(flow, False, b"A2 NOOP\r\n")
    send(flow, True, b"A2 OK NOOP completed\r\n")
    return flow.packets


literal = [b"From: a@example.com\r\n", b"To: b@example.com\r\n",
           b"Subject: x\r\n\r\nHello world\r\n"]
append = b"A1 APPEND INBOX {%d}\r\n" % len(b"".join(literal))


def append_gap(port, lost, after):
    flow = start(port)
    send(flow, False, append)
    send(flow, True, b"+ Ready\r\n")
    send(flow, False, literal[0])
    lose(flow, False, lost)
    if after:
        send(flow, False, after)
    send(flow, True, b"A1 OK APPEND completed\r\n")
    return finish(flow)


packets = []
# Gap inside a client literal: the text after it is not taken as commands.
packets += append_gap(42070, literal[1], literal[2] + b"\r\n")
# Gap ending exactly at the end of the literal.
packets += append_gap(42071, literal[1] + literal[2], b"\r\n")
# Gap running past the end of the literal: resync on the next command.
packets += append_gap(42072, literal[1] + literal[2] + b"\r\n", None)

# Lost continuation request, reported before the literal through later data.
flow = start(42073)
send(flow, False, b"A1 LOGIN {5}\r\n")
lose(flow, True, b"+ Ready\r\n")
flow.send(True, b"* 3 EXISTS\r\n")
send(flow, False, b'alice "secret"\r\n')
send(flow, True, b"A1 OK LOGIN completed\r\n")
packets += finish(flow)

# Response gap while idling: DONE still ends the IDLE.
flow = start(42074)
send(flow, False, b"A1 IDLE\r\n")
send(flow, True, b"+ idling\r\n")
lose(flow, True, b"* 5 EXISTS\r\n")
flow.send(True, b"* 6 EXISTS\r\n")
send(flow, False, b"DONE\r\n")
send(flow, True, b"A1 OK IDLE terminated\r\n")
packets += finish(flow)

# Gap inside a server literal: the message text is not taken as responses.
flow = start(42075)
send(flow, False, b"A1 FETCH 1 BODY[]\r\n")
body = [b"Subject: notes\r\n\r\n", b"First part of the message.\r\n",
        b"* first point\r\nplain text\r\n"]
send(flow, True, b"* 1 FETCH (BODY[] {%d}\r\n" % len(b"".join(body)) + body[0])
lose(flow, True, body[1])
send(flow, True, body[2] + b")\r\nA1 OK FETCH completed\r\n")
packets += finish(flow)

# Lost continuation request for IDLE with nothing after it: the gap is reported
# only after DONE, which still ends the IDLE.
flow = start(42076)
send(flow, False, b"A1 IDLE\r\n")
lose(flow, True, b"+ idling\r\n")
send(flow, False, b"DONE\r\n")
send(flow, True, b"A1 OK IDLE terminated\r\n")
packets += finish(flow)

# Request gap ending inside a line: the rest of that line is skipped, and the
# complete commands after it in the same segment are still parsed.
flow = start(42077)
flow.send(False, b"B1 SEARCH TEXT hel")
lose(flow, False, b"lo world\r\nB2 NO")
send(flow, False, b"OP\r\nB3 LOGIN user pass\r\nB4 NOOP\r\n")
send(flow, True, b"B1 OK SEARCH completed\r\nB2 OK NOOP completed\r\n"
     b"B3 OK LOGIN completed\r\nB4 OK NOOP completed\r\n")
packets += finish(flow)

# Response gap ending inside a line: the tagged reply after it still
# completes the command.
flow = start(42078)
send(flow, False, b"A1 SEARCH TEXT x\r\n")
send(flow, True, b"* SEARCH 1 2 3")
lose(flow, True, b" 4 5 6\r\n* SEARCH 7")
send(flow, True, b" 8 9\r\nA1 OK SEARCH completed\r\n")
packets += finish(flow)

# Synchronizing literal whose continuation request never comes: once the
# client sends another command the literal is given up, so a later request gap
# is not taken for its octets and the commands after it are still parsed.
flow = start(42079)
send(flow, False, b"A1 APPEND INBOX {40}\r\n")
send(flow, False, b"B1 NOOP\r\n")
send(flow, True, b"B1 OK NOOP completed\r\n")
lose(flow, False, b"B2 NO")
send(flow, False, b"OP\r\nB3 NOOP\r\nB4 NOOP\r\n")
send(flow, True, b"B3 OK NOOP completed\r\nB4 OK NOOP completed\r\n")
packets += finish(flow)

# Request gap losing the line that announces a literal: the text of the
# literal reads as commands this parser does not know, which are skipped until
# a known command.
flow = start(42080)
lose(flow, False, b"A1 APPEND INBOX {50}\r\n")
send(flow, True, b"+ Ready\r\n")
send(flow, False, b"Dear Bob,\r\nSee you tomorrow\r\nBest regards, Alice\r\n\r\n")
send(flow, True, b"A1 OK APPEND completed\r\n")
packets += finish(flow)

# Response gap losing the line that announces a literal: the text of the
# literal is skipped until a response this parser knows, although some of its
# lines read as untagged, continuation or tagged responses.
flow = start(42081)
send(flow, False, b"A1 FETCH 1:2 (BODY[])\r\n")
send(flow, True, b"* 1 FETCH (BODY[] {7}\r\nHello\r\n)\r\n")
lose(flow, True, b"* 2 FETCH (BODY[] {66}\r\n")
send(flow, True, b"Dear Bob,\r\n* first item\r\n+ added line\r\nthat is OK with me\r\n"
     b"Regards\r\n)\r\nA1 OK FETCH completed\r\n")
packets += finish(flow)

# Client data taken as the SASL response of an AUTHENTICATE gives up the
# literal its command line announced: the response gap is not taken for the
# continuation request of that literal, and the commands after it are parsed.
flow = start(42082)
send(flow, False, b"F1 AUTHENTICATE PLAIN {20}\r\n")
send(flow, False, b"dGVzdAB0ZXN0AHRlc3Q=\r\n")
lose(flow, True, b"F1 NO AUTHENTICATE failed\r\n")
send(flow, True, b"* OK still here\r\n")
send(flow, False, b"F2 LOGIN alice secret\r\nF3 NOOP\r\n")
send(flow, True, b"F2 OK LOGIN completed\r\nF3 OK NOOP completed\r\n")
packets += finish(flow)

timestamp = 1_000_000
for pkt in packets:
    pkt.time = Decimal(timestamp) / 1_000_000
    timestamp += 1000

wrpcap("input.pcap", packets)
