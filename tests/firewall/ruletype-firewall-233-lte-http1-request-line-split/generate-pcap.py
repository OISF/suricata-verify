#!/usr/bin/env python3
# Generates input.pcap: an HTTP GET per flow whose request line is split over two TCP segments: flow A completes into uri "/index", flow B into "/admin".
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
pkts = []
for sp, seg1, seg2 in ((49153, b"GET /ind", b"ex HTTP/1.1\r\nHost: a\r\n\r\n"),
                       (49154, b"GET /adm", b"in HTTP/1.1\r\nHost: b\r\n\r\n")):
    f = Flow(sp, 1000 + sp, 5000 + sp); f.hs(pkts)
    f.c(seg1, "PA", pkts); f.s(b"", "A", pkts)
    f.c(seg2, "PA", pkts); f.s(b"", "A", pkts)
    f.s(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", "PA", pkts)
    f.fin(pkts)
wrpcap("input.pcap", pkts)
print("wrote input.pcap:", len(pkts), "packets")
