#!/usr/bin/env python3
# Generates the shared SMTP pcap for the LTE state matrix tests
# (tests/firewall/ruletype-firewall-4xx-lte-smtp-*).
#
# One SMTP session whose mail is a multipart/mixed message with three
# attachments (base64 PNG, quoted-printable text, 7bit raw), so the MIME
# parser streams a realistic multi-attachment body through the
# email.* buffers registered at request_data.
#
# The DATA payload is split over two segments: the first carries the message
# headers, the second the parts and the terminating ".", so the request_data
# state is entered on its own packet and the body can still stream afterwards
# (the provisional no-match behaviour the matrix pins).
#
#   request_started    EHLO / MAIL / RCPT
#   request_data       MIME headers then the parts (attachments)
#   request_complete   after the final "."
from scapy.all import Ether, IP, TCP, Raw, wrpcap

SIP, DIP = "10.20.0.14", "93.184.216.34"  # $HOME_NET -> $EXTERNAL_NET
DP = 25


class Flow:
    def __init__(self, sport, cs, ss):
        self.sp = sport
        self.cseq, self.sseq = cs + 1, ss + 1
        self.sack, self.cake = cs + 1, ss + 1

    def mk(self, src, dst, sp, dp, seq, ack, flags, payload=b""):
        p = Ether(src="00:11:22:33:44:55" if src == SIP else "66:77:88:99:aa:bb",
                  dst="66:77:88:99:aa:bb" if src == SIP else "00:11:22:33:44:55") / \
            IP(src=src, dst=dst) / \
            TCP(sport=sp, dport=dp, seq=seq, ack=ack, flags=flags)
        if payload:
            p = p / Raw(payload)
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
        self.s(b"", "F", pkts)
        self.c(b"", "A", pkts)
        self.c(b"", "F", pkts)
        self.s(b"", "A", pkts)


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

# 1x1 RGB PNG, base64 encoded (the first attachment)
PNG_B64 = (b"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQ"
           b"AAAABJRU5ErkJggg==")

MIME1_A = (b"From: Alice <alice@example.com>\r\n"
           b"To: bob@example.com\r\n"
           b"Cc: carol@example.com\r\n"
           b"Subject: marker subject A\r\n"
           b"Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n"
           b"Message-Id: <midA@example.com>\r\n"
           b"X-Mailer: MailerA/1.0\r\n"
           b"MIME-Version: 1.0\r\n"
           b"Content-Type: multipart/mixed; boundary=\"BOUND-A\"\r\n"
           b"\r\n")

MIME2_A = (b"--BOUND-A\r\n"
           b"Content-Type: text/plain\r\n"
           b"Content-Transfer-Encoding: 7bit\r\n"
           b"\r\n"
           b"see http://urlA.example.com/x for details\r\n"
           b"--BOUND-A\r\n"
           b"Content-Type: image/png; name=\"logo.png\"\r\n"
           b"Content-Disposition: attachment; filename=\"logo.png\"\r\n"
           b"Content-Transfer-Encoding: base64\r\n"
           b"\r\n"
           + PNG_B64 + b"\r\n"
           b"--BOUND-A\r\n"
           b"Content-Type: text/plain; name=\"notes.txt\"\r\n"
           b"Content-Disposition: attachment; filename=\"notes.txt\"\r\n"
           b"Content-Transfer-Encoding: quoted-printable\r\n"
           b"\r\n"
           b"attachment=20two=20marker\r\n"
           b"--BOUND-A\r\n"
           b"Content-Type: application/octet-stream; name=\"raw.bin\"\r\n"
           b"Content-Disposition: attachment; filename=\"raw.bin\"\r\n"
           b"Content-Transfer-Encoding: 7bit\r\n"
           b"\r\n"
           b"raw attachment three\r\n"
           b"--BOUND-A--\r\n"
           b".\r\n")

f = Flow(49360, 49360 + 1000, 49360 + 5000)
smtp_session(f, b"alice@example.com", MIME1_A, MIME2_A)

wrpcap("smtp.pcap", pkts)
print(f"wrote smtp.pcap: {len(pkts)} packets")
