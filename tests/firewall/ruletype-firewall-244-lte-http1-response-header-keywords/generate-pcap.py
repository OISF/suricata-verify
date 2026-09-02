#!/usr/bin/env python3
# Generates input.pcap: 6 HTTP flows validating the remaining response-header
# (HEADERS) keyword buffers toclient: http.cookie (Set-Cookie),
# http.header_names and http.start.
#
# The response line plus one header complete in the first segment (progress
# moves to response_headers before the remaining header lines are parsed);
# the discriminating headers arrive in the second segment. On the first
# segment the header buffers do not yet contain them, so the no-match there
# is provisional (all three buffers are streaming).
#
# * flows A1-A3 (49220-49222) carry the marker response headers in segment 2
#   and are accepted;
# * flows B1-B3 (49223-49225) carry different values that match no keyword
#   and are each dropped once (eof CANT_MATCH at the rule's own hook).
#
# A toserver accept:hook shield (sids 701-706) keeps the toserver direction
# from adjudicating the flow before the toclient direction does.
#
# Expected: exactly 3 `firewall default app policy` drops (B1-B3).
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

REQ = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"
RSEG1 = b"HTTP/1.1 200 OK\r\nServer: S\r\n"
RSEG2_A = (b"Set-Cookie: sct=cookieA\r\nX-RespA: r1\r\nX-StartR: s1\r\n"
           b"Content-Length: 0\r\n\r\n")
RSEG2_B = (b"Set-Cookie: sct=cookieB\r\nX-RespB: r2\r\nX-StartQ: s2\r\n"
           b"Content-Length: 0\r\n\r\n")

pkts = []
sp = 49220
for i in range(3):
    f = Flow(sp, 1000 + sp, 5000 + sp); f.hs(pkts)
    f.c(REQ, "PA", pkts); f.s(b"", "A", pkts)
    f.s(RSEG1, "PA", pkts); f.c(b"", "A", pkts)
    f.s(RSEG2_A, "PA", pkts); f.c(b"", "A", pkts)
    f.fin(pkts)
    sp += 1
for i in range(3):
    f = Flow(sp, 1000 + sp, 5000 + sp); f.hs(pkts)
    f.c(REQ, "PA", pkts); f.s(b"", "A", pkts)
    f.s(RSEG1, "PA", pkts); f.c(b"", "A", pkts)
    f.s(RSEG2_B, "PA", pkts); f.c(b"", "A", pkts)
    f.fin(pkts)
    sp += 1
wrpcap("input.pcap", pkts)
print("wrote input.pcap:", len(pkts), "packets")
