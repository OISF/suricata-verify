#!/usr/bin/env python3
# Generates the shared HTTP/1 pcap for the LTE state matrix tests
# (tests/firewall/ruletype-firewall-3xx-lte-http1-*).
#
# One request/response flow that visits every HTTP1 progress state in both
# directions, with distinct markers per state so the matrix rules can match
# or not:
#
#   request_line    POST /index HTTP/1.1
#   request_headers Host: www.example.com
#   request_body    chunked body "BODY-MARKER"
#   request_trailer X-Trailer: yes
#   request_complete
#   response_line   HTTP/1.1 200 OK
#   response_headers X-Marker: yes
#   response_body   chunked body "RESP-BODY!!!"
#   response_trailer X-RTrailer: done
#   response_complete
#
# The payload is split over several segments so each state is entered on its
# own packet; the trailer chunked encoding is what makes HTP report the
# trailer states.
from scapy.all import Ether, IP, TCP, Raw, wrpcap

SIP, DIP = "10.20.0.14", "93.184.216.34"  # $HOME_NET -> $EXTERNAL_NET
DP = 80


class Flow:
    def __init__(self, sport, cs, ss):
        self.sp = sport
        self.cseq, self.sseq = cs + 1, ss + 1
        self.sack, self.cake = cs + 1, ss + 1

    def mk(self, src, dst, sp, dp, seq, ack, flags, payload=b""):
        p = Ether(src="00:11:22:33:44:55" if src == SIP else "66:77:88:99:aa:bb",
                  dst="66:77:88:99:aa:bb" if src == SIP else "00:11:22:33:44:55") / \
            IP(src=src, dst=dst) / \
            TCP(sport=sp, dport=dp, seq=seq, ack=ack, flags=flags)
        if payload:
            p = p / Raw(payload)
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
        self.s(b"", "F", pkts)
        self.c(b"", "A", pkts)
        self.c(b"", "F", pkts)
        self.s(b"", "A", pkts)


pkts = []
f = Flow(49200, 2000, 6000)
f.hs(pkts)

# request: split the line and the headers so each phase is observed
f.c(b"POST /ind", "PA", pkts)
f.s(b"", "A", pkts)
f.c(b"ex HTTP/1.1\r\nHost: www.example.com\r\n", "PA", pkts)
f.s(b"", "A", pkts)
f.c(b"Transfer-Encoding: chunked\r\n", "PA", pkts)
f.s(b"", "A", pkts)
f.c(b"\r\nb\r\nBODY-MARKER\r\n", "PA", pkts)
f.s(b"", "A", pkts)
f.c(b"0\r\nX-Trailer: yes\r\n\r\n", "PA", pkts)
f.s(b"", "A", pkts)

# response: split the line and the headers too
f.s(b"HTTP/1.1 200 ", "PA", pkts)
f.c(b"", "A", pkts)
f.s(b"OK\r\nServer: test\r\nX-Marker: yes\r\n", "PA", pkts)
f.c(b"", "A", pkts)
f.s(b"Transfer-Encoding: chunked\r\n", "PA", pkts)
f.c(b"", "A", pkts)
f.s(b"\r\nc\r\nRESP-BODY!!!\r\n", "PA", pkts)
f.c(b"", "A", pkts)
f.s(b"0\r\nX-RTrailer: done\r\n\r\n", "PA", pkts)
f.c(b"", "A", pkts)

f.fin(pkts)

wrpcap("http1.pcap", pkts)
print(f"wrote http1.pcap: {len(pkts)} packets")
