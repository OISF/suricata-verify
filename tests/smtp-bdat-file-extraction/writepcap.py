#!/usr/bin/env python
# The same MIME message over two framing paths: BDAT chunks (flow on port 41414)
# and DATA (flow on port 41415). The base64 payload is split across the chunk
# boundary, so a MIME line straddles two chunks.
from scapy.all import Ether, IP, TCP, Raw, wrpcap

pkts = []

B64 = b"SGVsbG8gZnJvbSBCREFUIHN0cmVhbQ0KaGVsbG8gd29ybGQ="  # "Hello from BDAT stream\r\nhello world"
prefix = (b"From: alice@example.com\r\nTo: bob@example.com\r\nSubject: chunked attachment\r\n"
          b'MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="ZZ"\r\n\r\n'
          b'--ZZ\r\nContent-Type: application/octet-stream; name="note.bin"\r\n'
          b"Content-Transfer-Encoding: base64\r\n\r\n")
chunk1 = prefix + B64[:20]
chunk2 = B64[20:] + b"\r\n--ZZ--\r\n"
data_msg = prefix + B64 + b"\r\n.\r\n"


class Flow:
    def __init__(self, sport):
        self.cseq, self.sseq, self.sport = 1000, 5000, sport

    def c(self, payload=None, flags="PA"):
        p = (Ether(src="00:01:02:03:04:05", dst="05:04:03:02:01:00")
             / IP(src="192.0.2.1", dst="192.0.2.2")
             / TCP(sport=self.sport, dport=25, flags=flags, seq=self.cseq,
                   ack=self.sseq, window=65535))
        if payload is not None:
            p = p / Raw(load=payload)
            self.cseq += len(payload)
        if "S" in flags or "F" in flags:
            self.cseq += 1
        pkts.append(p)

    def s(self, payload=None, flags="PA"):
        p = (Ether(src="05:04:03:02:01:00", dst="00:01:02:03:04:05")
             / IP(src="192.0.2.2", dst="192.0.2.1")
             / TCP(sport=25, dport=self.sport, flags=flags, seq=self.sseq,
                   ack=self.cseq, window=65535))
        if payload is not None:
            p = p / Raw(load=payload)
            self.sseq += len(payload)
        if "S" in flags or "F" in flags:
            self.sseq += 1
        pkts.append(p)


def greeting(f):
    f.c(flags="S")
    f.s(flags="SA")
    f.c(flags="A")
    f.s(b"220 mail.example.com ESMTP\r\n")
    f.c(flags="A")
    f.c(b"EHLO client.example.com\r\n")
    f.s(b"250-mail.example.com\r\n250-8BITMIME\r\n250 CHUNKING\r\n")
    f.c(flags="A")
    f.c(b"MAIL FROM:<alice@example.com>\r\n")
    f.s(b"250 2.1.0 Ok\r\n")
    f.c(flags="A")
    f.c(b"RCPT TO:<bob@example.com>\r\n")
    f.s(b"250 2.1.5 Ok\r\n")
    f.c(flags="A")


f1 = Flow(41414)
greeting(f1)
f1.c(b"BDAT %d\r\n" % len(chunk1) + chunk1)
f1.c(b"BDAT %d LAST\r\n" % len(chunk2) + chunk2)
f1.s(b"250 2.0.0 Ok: queued\r\n")
f1.c(flags="A")
f1.c(b"QUIT\r\n")
f1.s(b"221 2.0.0 Bye\r\n")
f1.c(flags="A")
f1.c(flags="FA")
f1.s(flags="A")

f2 = Flow(41415)
greeting(f2)
f2.c(b"DATA\r\n")
f2.s(b"354 End data with <CR><LF>.<CR><LF>\r\n")
f2.c(data_msg)
f2.s(b"250 2.0.0 Ok: queued\r\n")
f2.c(flags="A")
f2.c(b"QUIT\r\n")
f2.s(b"221 2.0.0 Bye\r\n")
f2.c(flags="A")
f2.c(flags="FA")
f2.s(flags="A")

wrpcap("input.pcap", pkts)
