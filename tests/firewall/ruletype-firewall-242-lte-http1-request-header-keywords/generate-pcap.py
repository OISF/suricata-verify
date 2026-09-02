#!/usr/bin/env python3
# Generates input.pcap: 12 HTTP flows validating the remaining request-header
# (HEADERS) keyword buffers: http.header, http.cookie, http.host.raw,
# http.user_agent, http.header_names and http.start (tosever).
#
# The request line plus one header complete in the first segment (progress
# moves to request_headers before the remaining header lines are parsed); the
# discriminating headers arrive in the second segment. On the first segment
# the header buffers do not yet contain them, so the no-match there is
# provisional (all six buffers are streaming).
#
# * flows A1-A6 (49190-49195) carry all six marker headers in segment 2 and
#   are accepted;
# * flows B1-B6 (49196-49201) carry different values that match no keyword
#   and are each dropped once (eof CANT_MATCH at the rule's own hook).
#
# Expected: exactly 6 `firewall default app policy` drops (B1-B6).
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

SEG1 = b"GET / HTTP/1.1\r\nHost: hostA.example.com\r\nAccept: */*\r\n"
SEG2_A = (b"X-HdrA: a1\r\nCookie: sca=cookieA\r\nUser-Agent: AgentA/1.0\r\n"
          b"X-HdrB: b1\r\nX-StartA: s1\r\n\r\n")
SEG1_B = b"GET / HTTP/1.1\r\nHost: hostB.example.com\r\nAccept: */*\r\n"
SEG2_B = (b"X-HdrZ: z1\r\nCookie: sca=cookieB\r\nUser-Agent: AgentB/2.0\r\n"
          b"X-Other: o1\r\nX-StartB: s2\r\n\r\n")

pkts = []
sp = 49190
for i in range(6):
    f = Flow(sp, 1000 + sp, 5000 + sp); f.hs(pkts)
    f.c(SEG1, "PA", pkts); f.s(b"", "A", pkts)
    f.c(SEG2_A, "PA", pkts); f.s(b"", "A", pkts)
    f.s(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", "PA", pkts)
    f.fin(pkts)
    sp += 1
for i in range(6):
    f = Flow(sp, 1000 + sp, 5000 + sp); f.hs(pkts)
    f.c(SEG1_B, "PA", pkts); f.s(b"", "A", pkts)
    f.c(SEG2_B, "PA", pkts); f.s(b"", "A", pkts)
    f.s(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", "PA", pkts)
    f.fin(pkts)
    sp += 1
wrpcap("input.pcap", pkts)
print("wrote input.pcap:", len(pkts), "packets")
