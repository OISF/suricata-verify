#!/usr/bin/env python3
"""Craft an http2 pcap whose request stream carries a trailer HEADERS frame.

TCP seq/ack bookkeeping matters: the SYN and the SYN/ACK each consume one
sequence number, so payload must not overlap the handshake. Getting this wrong
is silent - the stream engine never delivers the 24-byte preface to proto
detection, which reports app_proto "failed" and produces no events at all, and
the frames still look fine in tshark.
"""
from scapy.all import Ether, IP, TCP, wrpcap
import struct

SPORT, DPORT = 49152, 80
C, S = "10.0.0.5", "203.0.113.7"


def frame(ftype, flags, sid, payload=b""):
    return struct.pack("!I", len(payload))[1:] + bytes([ftype, flags]) + struct.pack("!I", sid) + payload


def lit(name, value):
    """HPACK literal header field without indexing (RFC 7541 6.2.2)."""
    n, v = name.encode(), value.encode()
    return b"\x00" + bytes([len(n)]) + n + bytes([len(v)]) + v


HEADERS, DATA, SETTINGS, END_STREAM, END_HEADERS = 0x1, 0x0, 0x6, 0x1, 0x4

req = (
    lit(":method", "POST") + lit(":path", "/upload") + lit(":authority", "www.example.com") + lit("content-type", "text/plain")
)
trailer = lit("x-note", "LATE-MARKER")
preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
c2s_head = preface + frame(SETTINGS, 0x00, 0) + frame(HEADERS, END_HEADERS, 1, req)
c2s_body = frame(DATA, 0x00, 1, b"hello")
c2s_trail = frame(HEADERS, END_HEADERS | END_STREAM, 1, trailer)
s2c = frame(HEADERS, 0x00, 1, lit(":status", "200")) + frame(DATA, END_HEADERS | END_STREAM, 1, b"ok") + frame(SETTINGS, 0x00, 0)


def main():
    pkts = []
    cseq, sseq = 1000, 2000

    def c2s(pay=b"", flags="PA"):
        nonlocal cseq
        pkts.append(Ether() / IP(src=C, dst=S) / TCP(sport=SPORT, dport=DPORT, flags=flags, seq=cseq, ack=sseq) / (pay or b""))
        cseq += len(pay) + (1 if "S" in flags else 0)

    def s2c(pay=b"", flags="PA"):
        nonlocal sseq
        pkts.append(Ether() / IP(src=S, dst=C) / TCP(sport=DPORT, dport=SPORT, flags=flags, seq=sseq, ack=cseq) / (pay or b""))
        sseq += len(pay) + (1 if "S" in flags else 0)

    c2s(flags="S")
    s2c(flags="SA")
    c2s(flags="A")
    c2s(c2s_head)
    s2c(frame(SETTINGS, 0x00, 0) + frame(HEADERS, END_HEADERS, 1, lit(":status", "200")))
    c2s(c2s_body)
    s2c(frame(DATA, END_HEADERS, 1, b"ok"))
    c2s(c2s_trail)
    c2s(flags="FA")
    wrpcap("input.pcap", pkts)
    print("packets:", len(pkts))


if __name__ == "__main__":
    main()
