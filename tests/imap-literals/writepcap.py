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


def append_rejection_continuation():
    flow = Flow(42010)
    sync_email = (b'From: owner@example.test\r\nSubject: Synchronizing APPEND\r\n'
                  b'\r\nSYNC-APPEND-BODY\r\n')
    flow.send(True, b'* OK IMAP ready\r\n')
    flow.send(False, b'A1 APPEND INBOX {4}\r\n')
    flow.send(True, b'A1 NO APPEND rejected\r\n')
    flow.send(False, b'A2 IDLE\r\n')
    flow.send(True, b'+ idling\r\n')
    flow.send(False, b'DONE\r\n')
    flow.send(True, b'A2 OK IDLE completed\r\n')
    flow.send(False, b'A3 APPEND INBOX {4}\r\n')
    flow.send(True, b'A3 BAD APPEND rejected\r\n')
    flow.send(False, b'A4 IDLE\r\n')
    flow.send(True, b'+ idling\r\n')
    flow.send(False, b'DONE\r\n')
    flow.send(True, b'A4 OK IDLE completed\r\n')
    flow.send(False, b'A5 APPEND INBOX {%d}\r\n' % len(sync_email))
    flow.send(True, b'+ Ready for literal\r\n')
    flow.send(False, sync_email + b'\r\n')
    flow.send(True, b'A5 OK APPEND completed\r\n')
    flow.send(False, b'A6 NOOP\r\n')
    flow.send(True, b'A6 OK NOOP completed\r\n')
    return flow.packets


def literal_command_suffix():
    flow = Flow(42020)
    flow.send(True, b'* OK IMAP ready\r\n')
    flow.send(False, b'A1 SEARCH TEXT {3+}\r\nfoo SUBJECT secret\r\n')
    flow.send(True, b'* SEARCH 1\r\nA1 OK SEARCH completed\r\n')
    flow.send(False, b'A2 LOGIN {5+}\r\nadmin secretpass\r\n')
    flow.send(True, b'A2 OK LOGIN completed\r\n')
    return flow.packets


def response_literals():
    flow = Flow(42030)
    flow.send(True, b'* OK IMAP ready\r\n')
    flow.send(False, b'A1 LIST "" *\r\n')
    flow.send(True, b'* LIST () "/" {5}\r\nINBOX\r\nA1 OK LIST completed\r\n')
    flow.send(False, b'A2 STATUS INBOX (MESSAGES)\r\n')
    flow.send(True, b'* STATUS {5}\r\nINBOX (MESSAGES 1)\r\nA2 OK STATUS completed\r\n')
    flow.send(False, b'A3 ID NIL\r\n')
    flow.send(True, b'* ID ({4}\r\nname {6}\r\nserver)\r\nA3 OK ID completed\r\n')
    flow.send(False, b'A4 LIST "" "Arch*"\r\n')
    flow.send(True, b'* LIST () "/" {7}\r\nArch')
    flow.send(True, b'ive\r\nA4 OK LIST completed\r\n')
    flow.send(False, b'A5 NOOP\r\n')
    flow.send(True, b'* OK still here {3}\r\nA5 OK NOOP completed\r\n')
    flow.send(False, b'A6 NOOP\r\n')
    flow.send(True, b'A6 OK NOOP completed\r\n')
    flow.send(False, b'A7 FETCH 1 BODY[]\r\n')
    message = b'Subject: hi\r\n\r\nbody\r\n'
    flow.send(True, b'* 1 FETCH (BODY[] {%d}\r\n' % len(message)
              + message + b')\r\nA7 OK FETCH completed\r\n')
    return flow.packets


def eve_credential_redaction():
    flow = Flow(42040)
    PLAIN_INITIAL_RESPONSE = b'AHBsYWluLXVzZXItc2VjcmV0AHBsYWluLXBhc3N3b3JkLXNlY3JldA=='
    XOAUTH2_INITIAL_RESPONSE = (
        b'dXNlcj1vYXV0aC11c2VyLXNlY3JldAFhdXRoPUJlYXJlciBvYXV0aC10b2tlbi1zZWNyZXQBAQ=='
    )
    CONTINUATION_RESPONSE = (
        b'Y29udGludWF0aW9uLXVzZXItc2VjcmV0AGNvbnRpbnVhdGlvbi1wYXNzd29yZC1zZWNyZXQ='
    )
    LITERAL_LOGIN_USER = b'literal-login-user-secret'
    LITERAL_LOGIN_PASSWORD = b'literal-login-password-secret'
    flow.send(True, b'* OK IMAP ready\r\n')
    flow.send(False, b'A1 LOGIN "login-user-secret" "login-password-secret"\r\n')
    flow.send(True, b'A1 NO LOGIN failed\r\n')
    flow.send(False, b'A2 AUTHENTICATE PLAIN ' + PLAIN_INITIAL_RESPONSE + b'\r\n')
    flow.send(True, b'A2 NO AUTHENTICATE failed\r\n')
    flow.send(False, b'A3 AUTHENTICATE XOAUTH2 ' + XOAUTH2_INITIAL_RESPONSE + b'\r\n')
    flow.send(True, b'A3 NO AUTHENTICATE failed\r\n')
    flow.send(False, b'A4 AUTHENTICATE PLAIN\r\n')
    flow.send(True, b'+ \r\n')
    flow.send(False, CONTINUATION_RESPONSE + b'\r\n')
    flow.send(True, b'A4 NO AUTHENTICATE failed\r\n')
    flow.send(False, b'A5 LOGIN {%d}\r\n' % len(LITERAL_LOGIN_USER))
    flow.send(True, b'+ continue\r\n')
    flow.send(False, LITERAL_LOGIN_USER + b' {%d}\r\n' % len(LITERAL_LOGIN_PASSWORD))
    flow.send(True, b'+ continue\r\n')
    flow.send(False, LITERAL_LOGIN_PASSWORD + b'\r\n')
    flow.send(True, b'A5 NO LOGIN failed\r\n')
    return flow.packets

packets = []
timestamp = 1_000_000
for scenario, interval in [
    (append_rejection_continuation, 1000000),
    (literal_command_suffix, 1000000),
    (response_literals, 1000000),
    (eve_credential_redaction, 1000000),
]:
    for pkt in scenario():
        pkt.time = Decimal(timestamp) / 1_000_000
        packets.append(pkt)
        timestamp += interval

wrpcap("input.pcap", packets)
