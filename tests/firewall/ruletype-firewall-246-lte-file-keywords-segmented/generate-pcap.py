#!/usr/bin/env python3
# Generates input.pcap: two HTTP file downloads validating the remaining
# filehandler app_stream registrations toclient: file.magic, the files
# multi-buffer (filename keyword) and file.name.
#
# The response body (the file data) arrives in two segments. Flow A (port
# 49240) downloads "match.png" whose content is a PNG file; flow B (port
# 49241) downloads "other.txt", a text file. None of the file values is
# available on the first response pass (response_headers, before the body):
# the file starts only with the first body byte (a 4-byte first segment)
# and the magic is computed when the file completes - so the no-match of the
# first body pass is PROVISIONAL (all three
# buffers are streaming) and must not be converted to CANT_MATCH.
#
# * flow A: the file name matches "match.png" and the magic matches "PNG";
#   the flow is accepted.
# * flow B: the file name is "other.txt" and the content is text; none of
#   the three keywords matches and the engines' own eof CANT_MATCH drops the
#   flow once.
#
# A toserver accept:hook shield (sids 701-706) keeps the toserver direction
# from adjudicating the flow before the toclient direction does.
#
# Expected: exactly 1 `firewall default app policy` drop (flow B).
from scapy.all import Ether, IP, TCP, Raw, wrpcap

SIP, DIP = "10.20.0.14", "142.251.111.105"  # $HOME_NET -> $EXTERNAL_NET
DP = 80

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


BODY_A = bytes.fromhex(
    "89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 00 00 00 01 00 00 00 01 08 02 00 00 00 90 77 53 de 00 00 00 0c 49 44 41 54 78 9c 63 f8 cf c0 00 00 03 01 01 00 c9 fe 92 ef 00 00 00 00 49 45 4e 44 ae 42 60 82")  # 69 bytes, valid 1x1 RGB PNG
BODY_B = b"this is a text file, not a png"
BODY_B = BODY_B + b" " * (len(BODY_A) - len(BODY_B))
REQ = b"GET /download HTTP/1.1\r\nHost: a\r\n\r\n"

def resp(filename, ctype):
    return (b"HTTP/1.1 200 OK\r\nContent-Type: " + ctype +
            b"\r\nContent-Disposition: attachment; filename=\"" + filename +
            b"\"\r\nContent-Length: " + str(len(BODY_A)).encode() + b"\r\n\r\n")

pkts = []
f = Flow(49240, 49240 + 1000, 49240 + 5000); f.hs(pkts)
f.c(REQ, "PA", pkts); f.s(b"", "A", pkts)
f.s(resp(b"match.png", b"image/png"), "PA", pkts); f.c(b"", "A", pkts)
f.s(BODY_A[:4], "PA", pkts); f.c(b"", "A", pkts)
f.s(BODY_A[4:], "PA", pkts); f.c(b"", "A", pkts)
f.fin(pkts)

f = Flow(49241, 49241 + 1000, 49241 + 5000); f.hs(pkts)
f.c(REQ, "PA", pkts); f.s(b"", "A", pkts)
f.s(resp(b"other.txt", b"text/plain"), "PA", pkts); f.c(b"", "A", pkts)
f.s(BODY_B[:4], "PA", pkts); f.c(b"", "A", pkts)
f.s(BODY_B[4:], "PA", pkts); f.c(b"", "A", pkts)
f.fin(pkts)

wrpcap("input.pcap", pkts)
print("wrote input.pcap:", len(pkts), "packets")
