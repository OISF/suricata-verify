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

def literal8():
    flow = Flow(42050)
    flow.send(True, b'* OK IMAP ready\r\n')
    # Literal8 (RFC 3516) alone and closing a list; the octets hold a CRLF.
    flow.send(False, b'A1 APPEND INBOX ~{5+}\r\nx\r\ny!\r\n')
    flow.send(True, b'A1 OK APPEND completed\r\n')
    flow.send(False, b'A2 APPEND INBOX UTF8 (~{5+}\r\nx\r\ny!)\r\n')
    flow.send(True, b'A2 OK APPEND completed\r\n')
    flow.send(False, b'A3 NOOP\r\n')
    flow.send(True, b'A3 OK NOOP completed\r\n')
    return flow.packets


def stray_continuation():
    flow = Flow(42060)
    flow.send(True, b'* OK IMAP ready\r\n')
    # A continuation request nothing asked for: the next client line is
    # still a command of its own.
    flow.send(False, b'A1 LOGIN alice secret\r\n')
    flow.send(True, b'+ stray\r\n')
    flow.send(False, b'A2 SELECT private-folder\r\n')
    flow.send(True, b'A1 OK LOGIN completed\r\nA2 OK SELECT completed\r\n')
    # A command this parser does not know may take continuation lines.
    flow.send(False, b'A3 XAUTH\r\n')
    flow.send(True, b'+ go\r\n')
    flow.send(False, b'dGVzdA==\r\n')
    flow.send(True, b'A3 OK XAUTH done\r\n')
    # So may one whose literal is done.
    flow.send(False, b'A4 XFOO {3}\r\n')
    flow.send(True, b'+ literal\r\n')
    flow.send(False, b'abc\r\n')
    flow.send(True, b'+ more\r\n')
    flow.send(False, b'eGZvbw==\r\n')
    flow.send(True, b'A4 OK XFOO done\r\n')
    return flow.packets


def eve_8bit():
    flow = Flow(42070)
    flow.send(True, b'* OK IMAP ready\r\n')
    # A byte that is not valid UTF-8 is kept, escaped, in EVE.
    flow.send(False, b'A1 SELECT "caf\xe9"\r\n')
    flow.send(True, b'* OK [caf\xe9] opened\r\nA1 OK SELECT completed\r\n')
    return flow.packets


def early_reply():
    flow = Flow(42080)
    flow.send(True, b'* OK IMAP ready\r\n')
    body = b'Dear Bob,\r\nSee you tomorrow\r\nBest regards, Alice\r\n'
    # The server answers before the literal ends but still reads it.
    flow.send(False, b'A1 APPEND INBOX {%d+}\r\n' % len(body) + body[:11])
    flow.send(True, b'A1 NO [OVERQUOTA] quota exceeded\r\n')
    flow.send(False, body[11:] + b'\r\n')
    flow.send(False, b'A2 NOOP\r\n')
    flow.send(True, b'A2 OK NOOP completed\r\n')
    return flow.packets


def no_literal_plus():
    flow = Flow(42090)
    flow.send(True, b'* OK [CAPABILITY IMAP4rev1 IDLE] IMAP ready\r\n')
    # The server offers no LITERAL+: it rejects the first line and runs the
    # others, which are no literal octets.
    flow.send(False, b'A1 SEARCH TEXT {17+}\r\nB1 LOGIN admin pw\r\nB2 NOOP\r\n')
    flow.send(True, b'A1 BAD invalid literal\r\nB1 OK LOGIN completed\r\n'
              b'B2 OK NOOP completed\r\n')
    # Once the server offers it, the literal is consumed again.
    flow.send(False, b'B3 CAPABILITY\r\n')
    flow.send(True, b'* CAPABILITY IMAP4rev1 LITERAL+ IDLE\r\nB3 OK CAPABILITY completed\r\n')
    flow.send(False, b'B4 SEARCH TEXT {17+}\r\nB5 LOGIN admin pw\r\nB6 NOOP\r\n')
    flow.send(True, b'B4 OK SEARCH completed\r\nB6 OK NOOP completed\r\n')
    return flow.packets


def literal_plus_rejected():
    # No capability list: BAD tells that the server did not take the literal.
    flow = Flow(42100)
    flow.send(True, b'* OK IMAP ready\r\n')
    flow.send(False, b'C1 NOOP {1000+}\r\n')
    flow.send(True, b'C1 BAD invalid arguments\r\n')
    flow.send(False, b'C2 LOGIN alice secret\r\n')
    flow.send(True, b'C2 OK LOGIN completed\r\n')
    flow.send(False, b'C3 NOOP\r\n')
    flow.send(True, b'C3 OK NOOP completed\r\n')
    return flow.packets


def literal_plus_bad_reply():
    # The server offers LITERAL+, so it reads the literal even with BAD.
    flow = Flow(42110)
    flow.send(True, b'* OK [CAPABILITY IMAP4rev1 LITERAL+] IMAP ready\r\n')
    body = b'Dear Bob,\r\nC7 NOOP\r\nBest regards, Alice\r\n'
    flow.send(False, b'C1 APPEND INBOX {%d+}\r\n' % len(body) + body[:11])
    flow.send(True, b'C1 BAD invalid mailbox\r\n')
    flow.send(False, body[11:] + b'\r\n')
    flow.send(False, b'C2 NOOP\r\n')
    flow.send(True, b'C2 OK NOOP completed\r\n')
    return flow.packets


def unseen_login_continuation():
    # The continuation request is not seen: the password read as a command
    # line is not logged.
    flow = Flow(42120)
    flow.send(True, b'* OK IMAP ready\r\n')
    flow.send(False, b'D1 LOGIN alice {10}\r\n')
    flow.send(False, b'my secret1\r\n')
    flow.send(False, b'D2 NOOP\r\n')
    flow.send(True, b'D2 OK NOOP completed\r\n')
    return flow.packets


def unseen_login_continuations():
    # Both literals of LOGIN without their continuation requests: the lines
    # stay unlogged until a known command.
    flow = Flow(42140)
    flow.send(True, b'* OK IMAP ready\r\n')
    flow.send(False, b'G1 LOGIN {5}\r\n')
    flow.send(False, b'admin {9}\r\n')
    flow.send(False, b'pass word\r\n')
    flow.send(False, b'G2 NOOP\r\n')
    flow.send(True, b'G2 OK NOOP completed\r\n')
    return flow.packets


def continuation_after_early_reply():
    # A continuation request while the literal of an answered command is still
    # counted belongs to no command.
    flow = Flow(42130)
    flow.send(True, b'* OK IMAP ready\r\n')
    body = b'Dear Bob,\r\nSee you tomorrow\r\nBest regards, Alice\r\n'
    flow.send(False, b'E1 APPEND INBOX {%d+}\r\n' % len(body) + body[:11])
    flow.send(True, b'E1 NO [OVERQUOTA] quota exceeded\r\n')
    flow.send(False, body[11:20])
    flow.send(True, b'+ unexpected\r\n')
    flow.send(False, body[20:] + b'\r\n')
    flow.send(False, b'E2 NOOP\r\n')
    flow.send(True, b'E2 OK NOOP completed\r\n')
    return flow.packets


packets = []
timestamp = 1_000_000
for scenario, interval in [
    (append_rejection_continuation, 1000000),
    (literal_command_suffix, 1000000),
    (response_literals, 1000000),
    (eve_credential_redaction, 1000000),
    (literal8, 1000000),
    (stray_continuation, 1000000),
    (eve_8bit, 1000000),
    (early_reply, 1000000),
    (no_literal_plus, 1000000),
    (literal_plus_rejected, 1000000),
    (literal_plus_bad_reply, 1000000),
    (unseen_login_continuation, 1000000),
    (unseen_login_continuations, 1000000),
    (continuation_after_early_reply, 1000000),
]:
    for pkt in scenario():
        pkt.time = Decimal(timestamp) / 1_000_000
        packets.append(pkt)
        timestamp += interval

wrpcap("input.pcap", packets)
