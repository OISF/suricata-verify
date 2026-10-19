#!/usr/bin/env python3
"""h2c request against a host allowlist, scenario s4_trailer_host: headers, body, END_STREAM trailer carrying host.

Crafted from the reviewer fixture in MR 106; re-run with `python3 gen_input_pcap.py`
and check with tshark that the frames and flags still match README.md."""
import struct, sys
from scapy.all import Ether, IP, TCP, wrpcap

SPORT, DPORT = 49152, 80
C, S = "10.0.0.5", "203.0.113.7"
HEADERS, DATA, SETTINGS = 0x1, 0x0, 0x4
END_STREAM, END_HEADERS = 0x1, 0x4


def frame(ftype, flags, sid, payload=b""):
    return struct.pack("!I", len(payload))[1:] + bytes([ftype, flags]) + struct.pack("!I", sid) + payload


def lit(name, value):
    n, v = name.encode(), value.encode()
    return b"\x00" + bytes([len(n)]) + n + bytes([len(v)]) + v


def req_block(authority=None, host=None, method="POST"):
    b = lit(":method", method) + lit(":scheme", "http") + lit(":path", "/x")
    if authority:
        b += lit(":authority", authority)
    if host:
        b += lit("host", host)
    return b


PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
scen = "s4_trailer_host"  # this test pins this one scenario
client = []  # list of client payloads, each its own TCP segment
if scen == "s0_allowed_hdr_eos":
    client = [PREFACE + frame(SETTINGS, 0, 0) + frame(HEADERS, END_HEADERS | END_STREAM, 1, req_block("allowed.example", method="GET"))]
elif scen == "s1_denied_hdr_eos":
    client = [PREFACE + frame(SETTINGS, 0, 0) + frame(HEADERS, END_HEADERS | END_STREAM, 1, req_block("evil.example", method="GET"))]
elif scen == "s2_denied_body":
    client = [PREFACE + frame(SETTINGS, 0, 0) + frame(HEADERS, END_HEADERS, 1, req_block("evil.example")),
              frame(DATA, 0, 1, b"secret-body-1"),
              frame(DATA, END_STREAM, 1, b"secret-body-2")]
elif scen == "s3_trailer_authority":
    client = [PREFACE + frame(SETTINGS, 0, 0) + frame(HEADERS, END_HEADERS, 1, req_block("evil.example")),
              frame(DATA, 0, 1, b"secret-body-1"),
              frame(HEADERS, END_HEADERS | END_STREAM, 1, lit(":authority", "allowed.example"))]
elif scen == "s4_trailer_host":
    client = [PREFACE + frame(SETTINGS, 0, 0) + frame(HEADERS, END_HEADERS, 1, req_block(None, host="evil.example")),
              frame(DATA, 0, 1, b"secret-body-1"),
              frame(HEADERS, END_HEADERS | END_STREAM, 1, lit("host", "allowed.example"))]
else:
    sys.exit("unknown scenario")

pkts = []
cseq, sseq = 1000, 2000
def c2s(pay=b"", flags="PA"):
    global cseq
    pkts.append(Ether() / IP(src=C, dst=S) / TCP(sport=SPORT, dport=DPORT, flags=flags, seq=cseq, ack=sseq) / (pay or b""))
    cseq += len(pay) + (1 if ("S" in flags or "F" in flags) else 0)
def s2c(pay=b"", flags="PA"):
    global sseq
    pkts.append(Ether() / IP(src=S, dst=C) / TCP(sport=DPORT, dport=SPORT, flags=flags, seq=sseq, ack=cseq) / (pay or b""))
    sseq += len(pay) + (1 if ("S" in flags or "F" in flags) else 0)

c2s(flags="S"); s2c(flags="SA"); c2s(flags="A")
for i, pay in enumerate(client):
    c2s(pay)
    s2c(flags="A") if i == 0 else s2c(flags="A")
# server responds only after the whole request (worst case for the window)
s2c(frame(SETTINGS, 0, 0) + frame(HEADERS, END_HEADERS, 1, lit(":status", "200")))
c2s(flags="A")
s2c(frame(DATA, END_STREAM, 1, b"ok"))
c2s(flags="A")
c2s(flags="FA"); s2c(flags="FA"); c2s(flags="A")
for i, p in enumerate(pkts):
    p.time = 1700000000 + i * 0.01
wrpcap("input.pcap", pkts)
print(scen, "packets:", len(pkts), "client data segments:", len(client))
