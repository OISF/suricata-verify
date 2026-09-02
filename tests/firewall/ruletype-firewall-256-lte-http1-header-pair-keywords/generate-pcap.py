#!/usr/bin/env python3
# Generates input.pcap: three HTTP flows validating the http1
# app_stream registrations of the http.request_header and
# http.response_header multi-buffers (the header name+value pairs populate
# line by line during the HEADERS progress).
#
# * flows A1/A2 (49350-49351): the request header "X-Marker: valA" arrives
#   in the second request segment and the response header "X-RespMark: valA"
#   in the second response segment. On the first segment of each side the
#   multi-buffers do not yet contain the marker header - the no-match there
#   is PROVISIONAL (the multi-buffers are streaming) and must not be
#   converted to CANT_MATCH; the keywords match when the second segment is
#   parsed and both flows are accepted.
# * flow B (49352): "X-Marker: valB" / "X-RespMark: valB" - no keyword
#   matches; the toserver side is dropped once (the toclient side is masked
#   by the flow drop).
#
# Expected: exactly 1 `firewall default app policy` drop (flow B).
from scapy.all import Ether, IP, TCP, Raw, wrpcap

SIP, DIP = "10.20.0.14", "142.251.111.105"  # $HOME_NET -> $EXTERNAL_NET
DP = 80

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
REQ1 = b"GET / HTTP/1.1\r\nHost: a\r\n"
REQ2_A = b"X-Marker: valA\r\n\r\n"
REQ2_B = b"X-Marker: valB\r\n\r\n"
RSEG1 = b"HTTP/1.1 200 OK\r\nServer: S\r\n"
RSEG2_A = b"X-RespMark: valA\r\nContent-Length: 0\r\n\r\n"
RSEG2_B = b"X-RespMark: valB\r\nContent-Length: 0\r\n\r\n"

for sp in (49350, 49351):
    f = Flow(sp, sp + 1000, sp + 5000); f.hs(pkts)
    f.c(REQ1, "PA", pkts); f.s(b"", "A", pkts)
    f.c(REQ2_A, "PA", pkts); f.s(b"", "A", pkts)
    f.s(RSEG1, "PA", pkts); f.c(b"", "A", pkts)
    f.s(RSEG2_A, "PA", pkts); f.c(b"", "A", pkts)
    f.fin(pkts)

f = Flow(49352, 49352 + 1000, 49352 + 5000); f.hs(pkts)
f.c(REQ1, "PA", pkts); f.s(b"", "A", pkts)
f.c(REQ2_B, "PA", pkts); f.s(b"", "A", pkts)
f.s(RSEG1, "PA", pkts); f.c(b"", "A", pkts)
f.s(RSEG2_B, "PA", pkts); f.c(b"", "A", pkts)
f.fin(pkts)

wrpcap("input.pcap", pkts)
print("wrote input.pcap:", len(pkts), "packets")
