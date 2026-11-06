#!/usr/bin/env python3
# One SMTP flow, client 192.0.2.1 -> server 192.0.2.2:25, see README.md.
import base64
from scapy.all import Ether, IP, TCP, Raw, wrpcap


class Flow:
    def __init__(self, sport):
        self.cseq, self.sseq, self.sport, self.pkts = 1000, 5000, sport, []

    def c(self, payload=None, flags="PA"):
        p = (Ether(src="00:01:02:03:04:05", dst="05:04:03:02:01:00")
             / IP(src="192.0.2.1", dst="192.0.2.2")
             / TCP(sport=self.sport, dport=25, flags=flags, seq=self.cseq, ack=self.sseq, window=65535))
        if payload is not None:
            p = p / Raw(load=payload)
            self.cseq += len(payload)
        if "S" in flags or "F" in flags:
            self.cseq += 1
        self.pkts.append(p)

    def s(self, payload=None, flags="PA"):
        p = (Ether(src="05:04:03:02:01:00", dst="00:01:02:03:04:05")
             / IP(src="192.0.2.2", dst="192.0.2.1")
             / TCP(sport=25, dport=self.sport, flags=flags, seq=self.sseq, ack=self.cseq, window=65535))
        if payload is not None:
            p = p / Raw(load=payload)
            self.sseq += len(payload)
        if "S" in flags or "F" in flags:
            self.sseq += 1
        self.pkts.append(p)

    def greeting(self):
        self.c(flags="S"); self.s(flags="SA"); self.c(flags="A")
        self.s(b"220 mail.example.com ESMTP\r\n"); self.c(flags="A")
        self.c(b"EHLO client.example.com\r\n")
        self.s(b"250-mail.example.com\r\n250-8BITMIME\r\n250 CHUNKING\r\n"); self.c(flags="A")
        self.c(b"MAIL FROM:<alice@example.com>\r\n"); self.s(b"250 2.1.0 Ok\r\n"); self.c(flags="A")
        self.c(b"RCPT TO:<bob@example.com>\r\n"); self.s(b"250 2.1.5 Ok\r\n"); self.c(flags="A")

    def close(self):
        self.c(flags="FA"); self.s(flags="FA"); self.c(flags="A")


PAYLOAD = b"file data delivered behind a rejected DATA command\n"
B64 = base64.encodebytes(PAYLOAD).replace(b"\n", b"\r\n")
MSG = (b"From: alice@example.com\r\nTo: bob@example.com\r\nSubject: att\r\n"
       b'MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="ZZ"\r\n\r\n'
       b'--ZZ\r\nContent-Type: text/plain; name="note.txt"\r\n'
       b"Content-Transfer-Encoding: base64\r\n\r\n" + B64 + b"--ZZ--\r\n")

# C: DATA refused for bad syntax, then the same message pushed through a BDAT
# chunk on the same transaction, the way a client that ignores the 501 can.
f = Flow(40021); f.greeting()
f.c(b"DATA syntax error\r\n"); f.s(b"501 5.5.2 Syntax error in parameters\r\n"); f.c(flags="A")
f.c(b"BDAT %d LAST\r\n" % len(MSG)); f.c(MSG); f.s(flags="A")
f.s(b"250 2.0.0 Ok: queued\r\n"); f.c(flags="A")
f.c(b"QUIT\r\n"); f.s(b"221 2.0.0 Bye\r\n"); f.close()
wrpcap("input.pcap", f.pkts)
