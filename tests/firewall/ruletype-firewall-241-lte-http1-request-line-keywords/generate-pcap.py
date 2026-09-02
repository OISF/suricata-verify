#!/usr/bin/env python3
# Generates input.pcap: 8 HTTP flows whose request line is split over two TCP
# segments, covering the remaining request-line (LINE) keyword buffers:
# http.method, http.request_line, http_raw_uri and http.protocol (tosever).
#
# * flows A1-A4 (49170-49173) complete the line into
#   "GET /index HTTP/1.1" - every one of the four rule keywords matches;
# * flows B1-B4 (49174-49177) complete it into lines that match none of the
#   four keywords (method != GET, no "GET /" substring, uri != /index,
#   protocol != HTTP/1.1).
#
# The first segment leaves the line incomplete: HTP progress is at
# request_line and the line buffers are empty (no partial request-line
# inspection). Their no-match must stay provisional (all four buffers are
# streaming). A completes on the second segment and is accepted; each B flow
# is rejected by the engines' own eof CANT_MATCH and dropped once.
#
# Expected: exactly 4 `firewall default app policy` drops (B1-B4).
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

pkts = []
lines_a = [b"GET /ind" for _ in range(4)]
lines_b = [b"PATCH /p", b"PUT /upl", b"DELETE", b"POST /su"]
lines_b_end = [b" HTTP/1.0", b"oad HTTP/1.0", b" /x HTTP/1.0", b"bmit HTTP/1.0"]
sp = 49170
for i in range(4):
    f = Flow(sp, 1000 + sp, 5000 + sp); f.hs(pkts)
    f.c(lines_a[i], "PA", pkts); f.s(b"", "A", pkts)
    f.c(b"ex HTTP/1.1\r\nHost: a\r\n\r\n", "PA", pkts); f.s(b"", "A", pkts)
    f.s(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", "PA", pkts)
    f.fin(pkts)
    sp += 1
for i in range(4):
    f = Flow(sp, 1000 + sp, 5000 + sp); f.hs(pkts)
    f.c(lines_b[i], "PA", pkts); f.s(b"", "A", pkts)
    f.c(lines_b_end[i] + b"\r\nHost: b\r\n\r\n", "PA", pkts); f.s(b"", "A", pkts)
    f.s(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", "PA", pkts)
    f.fin(pkts)
    sp += 1
wrpcap("input.pcap", pkts)
print("wrote input.pcap:", len(pkts), "packets")
