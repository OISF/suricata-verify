#!/usr/bin/env python3
# Generates input.pcap: 6 HTTP flows validating the remaining response-line
# (LINE) keyword buffers toclient: http.response_line, http.stat_msg and
# http.protocol.
#
# The status line is split over two TCP segments (like test 236 for
# http.stat_code): while the line is incomplete the HTP response progress is
# at response_line and the line buffers are empty (no partial line
# inspection). The no-match there is provisional (all three buffers are
# streaming).
#
# * flows A1-A3 (49210-49212) complete the line into
#   "HTTP/1.1 200 OK" - all three keywords match; accepted.
# * flows B1-B3 (49213-49215) complete it into "HTTP/1.0 503 Gone" - none of
#   the three keywords matches; each flow is dropped once (eof CANT_MATCH).
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

pkts = []
sp = 49210
for i in range(3):
    f = Flow(sp, 1000 + sp, 5000 + sp); f.hs(pkts)
    f.c(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n", "PA", pkts); f.s(b"", "A", pkts)
    f.s(b"HTTP/1.1 20", "PA", pkts); f.c(b"", "A", pkts)
    f.s(b"0 OK\r\nContent-Length: 0\r\n\r\n", "PA", pkts); f.c(b"", "A", pkts)
    f.fin(pkts)
    sp += 1
for i in range(3):
    f = Flow(sp, 1000 + sp, 5000 + sp); f.hs(pkts)
    f.c(b"GET / HTTP/1.1\r\nHost: b\r\n\r\n", "PA", pkts); f.s(b"", "A", pkts)
    f.s(b"HTTP/1.0 50", "PA", pkts); f.c(b"", "A", pkts)
    f.s(b"3 Gone\r\nContent-Length: 0\r\n\r\n", "PA", pkts); f.c(b"", "A", pkts)
    f.fin(pkts)
    sp += 1
wrpcap("input.pcap", pkts)
print("wrote input.pcap:", len(pkts), "packets")
