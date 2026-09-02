#!/usr/bin/env python3
# Generates input.pcap: two SMTP sessions validating the email.url and
# email.received app_stream (streaming multi-buffer) registrations.
#
# The Received header and the body URL arrive in the second MIME packet
# (during SMTP DATA, progress request_data): on the first DATA pass the
# buffers are empty - their no-matches there are PROVISIONAL (the multi-
# buffers are streaming: the MIME keeps streaming at their registered
# progress) and must not be converted to CANT_MATCH.
#
# * flow A (49290): a Received header and a body URL "urlA.example.com";
#   both keywords match on the second pass and the flow is accepted.
# * flow B (49291): no Received header and no URL; no keyword matches; the
#   flow is dropped once when the mail completes (eof CANT_MATCH).
#
# Expected: exactly 1 `firewall default app policy` drop (flow B).
from scapy.all import Ether, IP, TCP, Raw, wrpcap

SIP, DIP = "10.20.0.14", "142.251.111.105"  # $HOME_NET -> $EXTERNAL_NET
DP = 25

SIP, DIP = "10.20.0.14", "142.251.111.105"  # $HOME_NET -> $EXTERNAL_NET
DP = 25

class Flow:
    def __init__(self, sport, cs, ss):
        self.sp = sport
        self.cseq, self.sseq = cs + 1, ss + 1
        self.sack, self.cake = cs + 1, ss + 1
    def mk(self, src, dst, sp, dp, seq, ack, flags, payload=b""):
        p = Ether(src="00:11:22:33:44:55" if src == SIP else "66:77:88:99:aa:bb",
                  dst="66:77:88:99:aa:bb" if src == SIP else "00:11:22:33:44:55")/IP(src=src, dst=dst)/TCP(sport=sp, dport=dp, seq=seq, ack=ack, flags=flags)
        if payload: p = p/Raw(payload)
        return p
    def hs(self, pkts):
        Cs, Ss = self.cseq - 1, self.sseq - 1
        pkts.append(self.mk(SIP, DIP, self.sp, DP, Cs, 0, "S"))
        pkts.append(self.mk(DIP, SIP, DP, self.sp, Ss, Cs + 1, "SA"))
        self.c(b"", "A", pkts)
    def c(self, payload, flags, pkts):
        pkts.append(self.mk(SIP, DIP, self.sp, DP, self.cseq, self.cake, flags, payload))
        self.cseq += len(payload) + (1 if "F" in flags else 0)
        self.sack = self.cseq
    def s(self, payload, flags, pkts):
        pkts.append(self.mk(DIP, SIP, DP, self.sp, self.sseq, self.sack, flags, payload))
        self.sseq += len(payload) + (1 if "F" in flags else 0)
        self.cake = self.sseq
    def fin(self, pkts):
        self.s(b"", "F", pkts); self.c(b"", "A", pkts)
        self.c(b"", "F", pkts); self.s(b"", "A", pkts)


def smtp_session(f, mail_from, mime1, mime2):
    f.hs(pkts)
    f.s(b"220 mx.example.com ESMTP\r\n", "PA", pkts); f.c(b"", "A", pkts)
    f.c(b"EHLO client.example.com\r\n", "PA", pkts); f.s(b"", "A", pkts)
    f.s(b"250-mx.example.com\r\n250 OK\r\n", "PA", pkts); f.c(b"", "A", pkts)
    f.c(b"MAIL FROM:<" + mail_from + b">\r\n", "PA", pkts); f.s(b"", "A", pkts)
    f.s(b"250 2.1.0 Ok\r\n", "PA", pkts); f.c(b"", "A", pkts)
    f.c(b"RCPT TO:<bob@example.com>\r\n", "PA", pkts); f.s(b"", "A", pkts)
    f.s(b"250 2.1.5 Ok\r\n", "PA", pkts); f.c(b"", "A", pkts)
    f.c(b"DATA\r\n", "PA", pkts); f.s(b"", "A", pkts)
    f.s(b"354 End data with .\r\n", "PA", pkts); f.c(b"", "A", pkts)
    f.c(mime1, "PA", pkts); f.s(b"", "A", pkts)
    f.c(mime2, "PA", pkts); f.s(b"", "A", pkts)
    f.s(b"250 2.0.0 Ok: queued\r\n", "PA", pkts); f.c(b"", "A", pkts)
    f.c(b"QUIT\r\n", "PA", pkts); f.s(b"", "A", pkts)
    f.s(b"221 Bye\r\n", "PA", pkts); f.c(b"", "A", pkts)
    f.fin(pkts)

pkts = []
MIME2_A = (b"Received: from a.example.com (a.example.com [10.0.0.1]) by b.example.com\r\n"
           b"Subject: link\r\n\r\nsee http://urlA.example.com/x for details\r\n.\r\n")
MIME2_B = (b"Subject: none\r\n\r\nplain text, no links here\r\n.\r\n")

f = Flow(49290, 49290 + 1000, 49290 + 5000)
smtp_session(f, b"alice@example.com", b"From: alice@example.com\r\n", MIME2_A)
f = Flow(49291, 49291 + 1000, 49291 + 5000)
smtp_session(f, b"carol@example.com", b"From: carol@example.com\r\n", MIME2_B)

wrpcap("input.pcap", pkts)
print("wrote input.pcap:", len(pkts), "packets")
