#!/usr/bin/env python3
# One SMTP flow, client 192.0.2.1 -> server 192.0.2.2:25, see README.md.
import base64, os
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

    def segs(self, data, size):
        # client data in fixed-size segments, each acked by the server
        for i in range(0, len(data), size):
            self.c(data[i:i + size])
            self.s(flags="A")

ATT = bytes(range(256)) * 16  # 4096 byte attachment
B64 = base64.encodebytes(ATT).replace(b"\n", b"\r\n")  # 76-char lines
MSG = (b"From: alice@example.com\r\nTo: bob@example.com\r\nSubject: att\r\n"
       b'MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="ZZ"\r\n\r\n'
       b'--ZZ\r\nContent-Type: application/octet-stream; name="att.bin"\r\n'
       b"Content-Transfer-Encoding: base64\r\n\r\n" + B64 + b"--ZZ--\r\n")

body = (b"From: alice@example.com\r\nSubject: long\r\n\r\n" + b"A" * 65536 + b"\r\n")

# A2: a text body that is one 64 KiB run without LF
f = Flow(40002); f.greeting()
f.c(b"BDAT %d LAST\r\n" % len(body)); f.segs(body, 1400)
f.s(b"250 2.0.0 Ok: queued\r\n"); f.c(flags="A")
f.c(b"QUIT\r\n"); f.s(b"221 2.0.0 Bye\r\n"); f.close()
wrpcap("input.pcap", f.pkts)
