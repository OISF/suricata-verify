#!/usr/bin/env python3
# One SMTP session whose DATA message is a multipart MIME message with
# two attachments; with mime decoding enabled the smtp parser extracts
# both attachments as files of the transaction, so the file log
# callback (and the File::file_store_id assignment in the filedata
# path) runs once per file.
from scapy.all import IP, TCP, Raw, wrpcap, Ether

CIP, SIP = "10.0.0.1", "10.0.0.2"
CP, SP = 49152, 25

att1 = b"A1a2B3b4C5c6D7d8"
att2 = b"feedfacecafebabe"
msg = (b"From: a@example.com\r\n"
       b"To: b@example.com\r\n"
       b"Subject: two attachments\r\n"
       b"MIME-Version: 1.0\r\n"
       b"Content-Type: multipart/mixed; boundary=\"MIX2\"\r\n"
       b"\r\n"
       b"--MIX2\r\n"
       b"Content-Type: text/plain\r\n"
       b"\r\n"
       b"body text\r\n"
       b"--MIX2\r\n"
       b"Content-Type: application/octet-stream\r\n"
       b"Content-Disposition: attachment; filename=\"attach1.bin\"\r\n"
       b"Content-Transfer-Encoding: binary\r\n"
       b"\r\n" + att1 + b"\r\n"
       b"--MIX2\r\n"
       b"Content-Type: application/octet-stream\r\n"
       b"Content-Disposition: attachment; filename=\"attach2.bin\"\r\n"
       b"Content-Transfer-Encoding: binary\r\n"
       b"\r\n" + att2 + b"\r\n"
       b"--MIX2--\r\n"
       b".\r\n")

# explicit tcp stream bookkeeping: (cseq, sseq) are next-to-send
class Stream:
    def __init__(self):
        self.cseq, self.sseq = 1000, 5000

    def pkt(self, s, d, sp, dp, flags, seq, ack, load=b""):
        p = Ether() / IP(src=s, dst=d) / TCP(sport=sp, dport=dp, flags=flags,
            seq=seq, ack=ack)
        return p / Raw(load=load) if load else p

    def syn(self):
        pkts = [self.pkt(CIP, SIP, CP, SP, "S", self.cseq, 0),
                self.pkt(SIP, CIP, SP, CP, "SA", self.sseq, self.cseq + 1),
                self.pkt(CIP, SIP, CP, SP, "A", self.cseq + 1, self.sseq + 1)]
        self.cseq += 1
        self.sseq += 1
        return pkts

    def c(self, load):
        pkt = self.pkt(CIP, SIP, CP, SP, "PA", self.cseq, self.sseq, load)
        self.cseq += len(load)
        return [pkt]

    def s(self, load):
        pkt = self.pkt(SIP, CIP, SP, CP, "PA", self.sseq, self.cseq, load)
        self.sseq += len(load)
        return [pkt]

    def fin(self):
        return [self.pkt(CIP, SIP, CP, SP, "F", self.cseq, self.sseq),
                self.pkt(SIP, CIP, SP, CP, "FA", self.sseq, self.cseq + 1)]

st = Stream()
pkts = st.syn()
pkts += st.s(b"220 mx.example.com ESMTP ready\r\n")
pkts += st.c(b"EHLO client.example.com\r\n")
pkts += st.s(b"250-mx.example.com\r\n250 SIZE 100000000\r\n")
pkts += st.c(b"MAIL FROM:<a@example.com>\r\n")
pkts += st.s(b"250 2.1.0 OK\r\n")
pkts += st.c(b"RCPT TO:<b@example.com>\r\n")
pkts += st.s(b"250 2.1.5 OK\r\n")
pkts += st.c(b"DATA\r\n")
pkts += st.s(b"354 End data with <CR><LF>.<CR><LF>\r\n")
pkts += st.c(msg)
pkts += st.s(b"250 2.0.0 OK: queued\r\n")
pkts += st.c(b"QUIT\r\n")
pkts += st.s(b"221 2.0.0 Bye\r\n")
pkts += st.fin()
wrpcap("input.pcap", pkts)
print("wrote input.pcap (%d bytes data)" % len(msg))
