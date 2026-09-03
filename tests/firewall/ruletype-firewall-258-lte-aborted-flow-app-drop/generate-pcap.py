#!/usr/bin/env python3
# Generates input.pcap: 2 HTTP flows validating the fail-closed drop at
# flow end when the parser completes the in-progress tx on stream close.
#
# The LTE rule (sid 100) waits for a marker header line at
# request_headers.
#
# * flow A (49380) completes the request with the marker header: the rule
#   matches (accept:flow), 0 drops;
# * flow B (49381) completes the request line plus two headers in the
#   first segment (progress moves to request_headers), sends a truncated
#   header line (`X-Pa`, no CRLF) in the second segment and then RSTs.
#   On stream close the htp parser completes the request transaction
#   (progress reaches request_complete, 5), so on the pass of the RST
#   packet the engine's eof applies (5 > 2): the no match is definitive
#   and the per-hook default app policy must drop the flow.
#
# Expected: exactly 1 `firewall default app policy` drop (flow B, at the
# RST packet).
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

SEG1 = b"GET / HTTP/1.1\r\nHost: hostX.example.com\r\nAccept: */*\r\n"

pkts = []

# flow A: marker header completes the request -> accepted
f = Flow(49380, 1000, 5000); f.hs(pkts)
f.c(SEG1, "PA", pkts); f.s(b"", "A", pkts)
f.c(b"X-Marker: MARKERHDR\r\n\r\n", "PA", pkts); f.s(b"", "A", pkts)
f.s(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", "PA", pkts)
f.fin(pkts)

# flow B: truncated header line, then RST -> htp completes the tx on close,
# the definitive no match drops the flow by the default app policy
f = Flow(49381, 2000, 6000); f.hs(pkts)
f.c(SEG1, "PA", pkts); f.s(b"", "A", pkts)
f.c(b"X-Pa", "PA", pkts); f.s(b"", "A", pkts)
pkts.append(f.mk(SIP, DIP, f.sp, DP, f.cseq, f.cake, "R"))

wrpcap("input.pcap", pkts)
print("wrote input.pcap:", len(pkts), "packets")
