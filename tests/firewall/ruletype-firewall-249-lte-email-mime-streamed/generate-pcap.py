#!/usr/bin/env python3
# Generates input.pcap: 16 SMTP sessions validating the eight email.*
# app_stream registrations (email.from, email.subject, email.to, email.cc,
# email.date, email.message_id, email.x_mailer, email.body_md5).
#
# The MIME headers stream in during SMTP DATA (progress request_data): the
# first MIME packet carries only the From line, the remaining headers and the
# body arrive in the second packet. On the first DATA pass the other email
# buffers are empty - their no-matches there are PROVISIONAL (the buffers are
# streaming: the MIME keeps streaming at their registered progress) and must
# not be converted to CANT_MATCH.
#
# * flows A1-A8 (49270-49277): the full MIME with all marker values; the
#   keywords match (from on the first pass, the rest on the second) and the
#   flows are accepted.
# * flows B1-B8 (49278-49285): a different sender/recipient/subject/date/
#   message-id/x-mailer and a different body; no keyword matches; each flow
#   is dropped once when the mail completes (eof CANT_MATCH).
#
# Expected: exactly 8 `firewall default app policy` drops (B1-B8).
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
MIME2_A = b'To: bob@example.com\r\nCc: cc@example.com\r\nDate: Mon, 01 Jan 2024 00:00:00 +0000\r\nSubject: marker subject A\r\nMessage-Id: <midA@ex.com>\r\nX-Mailer: MailerA/1.0\r\n\r\nbodyA\r\n.\r\n'
MIME2_B = b'To: dave@example.com\r\nCc: cc2@example.com\r\nDate: Tue, 02 Feb 2024 00:00:00 +0000\r\nSubject: other subject B\r\nMessage-Id: <midB@ex.com>\r\nX-Mailer: MailerB/2.0\r\n\r\nbodyB\r\n.\r\n'
f = Flow(49270, 50270, 54270)
smtp_session(f, b"alice@example.com", b"From: alice@example.com\r\n", MIME2_A)
f = Flow(49271, 50271, 54271)
smtp_session(f, b"alice@example.com", b"From: alice@example.com\r\n", MIME2_A)
f = Flow(49272, 50272, 54272)
smtp_session(f, b"alice@example.com", b"From: alice@example.com\r\n", MIME2_A)
f = Flow(49273, 50273, 54273)
smtp_session(f, b"alice@example.com", b"From: alice@example.com\r\n", MIME2_A)
f = Flow(49274, 50274, 54274)
smtp_session(f, b"alice@example.com", b"From: alice@example.com\r\n", MIME2_A)
f = Flow(49275, 50275, 54275)
smtp_session(f, b"alice@example.com", b"From: alice@example.com\r\n", MIME2_A)
f = Flow(49276, 50276, 54276)
smtp_session(f, b"alice@example.com", b"From: alice@example.com\r\n", MIME2_A)
f = Flow(49277, 50277, 54277)
smtp_session(f, b"alice@example.com", b"From: alice@example.com\r\n", MIME2_A)
f = Flow(49278, 50278, 54278)
smtp_session(f, b"carol@example.com", b"From: carol@example.com\r\n", MIME2_B)
f = Flow(49279, 50279, 54279)
smtp_session(f, b"carol@example.com", b"From: carol@example.com\r\n", MIME2_B)
f = Flow(49280, 50280, 54280)
smtp_session(f, b"carol@example.com", b"From: carol@example.com\r\n", MIME2_B)
f = Flow(49281, 50281, 54281)
smtp_session(f, b"carol@example.com", b"From: carol@example.com\r\n", MIME2_B)
f = Flow(49282, 50282, 54282)
smtp_session(f, b"carol@example.com", b"From: carol@example.com\r\n", MIME2_B)
f = Flow(49283, 50283, 54283)
smtp_session(f, b"carol@example.com", b"From: carol@example.com\r\n", MIME2_B)
f = Flow(49284, 50284, 54284)
smtp_session(f, b"carol@example.com", b"From: carol@example.com\r\n", MIME2_B)
f = Flow(49285, 50285, 54285)
smtp_session(f, b"carol@example.com", b"From: carol@example.com\r\n", MIME2_B)

wrpcap("input.pcap", pkts)
print("wrote input.pcap:", len(pkts), "packets")
