#!/usr/bin/env python3
# One SMTP flow pair, client 192.0.2.1 -> server 192.0.2.2:25, see README.md.
# Body lines must not be capped: the same message goes out over BDAT LAST (port
# 40014) and over DATA (port 40015), and one 5000-byte header line makes sure the
# header cap still applies on both framings.
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
             / IP(src="192.0.2.2", dst="192.0.2.1") / TCP(sport=25, dport=self.sport, flags=flags,
                                                          seq=self.sseq, ack=self.cseq, window=65535))
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


# base64 on a single 8192-char line, and an 8bit attachment that is one 12288-byte line
ATT = bytes(range(256)) * 24            # 6144 bytes
B64_1LINE = base64.b64encode(ATT)       # no line breaks
TXT = b"x" * 12288
MSG = (b"From: alice@example.com\r\nTo: bob@example.com\r\nSubject: long lines\r\n"
       b'MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="ZZ"\r\n\r\n'
       b'--ZZ\r\nContent-Type: application/octet-stream; name="b64line.bin"\r\n'
       b"Content-Transfer-Encoding: base64\r\n\r\n" + B64_1LINE + b"\r\n"
       b'--ZZ\r\nContent-Type: text/plain; name="longline.txt"\r\n'
       b"Content-Transfer-Encoding: 8bit\r\n\r\n" + TXT + b"\r\n--ZZ--\r\n")
# plus one header line over the line buffer limit
MSG = MSG.replace(b"Subject: long lines\r\n", b"Subject: long lines\r\nX-Long: " + b"h" * 5000 + b"\r\n")

f = Flow(40014); f.greeting()
f.c(b"BDAT %d LAST\r\n" % len(MSG)); f.segs(MSG, 1400)
f.s(b"250 2.0.0 Ok: queued\r\n"); f.c(flags="A")
f.c(b"QUIT\r\n"); f.s(b"221 2.0.0 Bye\r\n"); f.close()

g = Flow(40015); g.greeting()
g.c(b"DATA\r\n"); g.s(b"354 go ahead\r\n"); g.c(flags="A")
g.segs(MSG + b".\r\n", 1400)
g.s(b"250 2.0.0 Ok: queued\r\n"); g.c(flags="A")
g.c(b"QUIT\r\n"); g.s(b"221 2.0.0 Bye\r\n"); g.close()

wrpcap("input.pcap", f.pkts + g.pkts)
