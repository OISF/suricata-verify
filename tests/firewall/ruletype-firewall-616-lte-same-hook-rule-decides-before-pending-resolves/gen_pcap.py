#!/usr/bin/env python3
"""Generate input.pcap: an LTE rule pending at a hook another rule shares.

Layout (pcap_cnt; tshark frame numbers are the same):
  1-3    TCP handshake
  4      C: "GET /decide HTTP/1.1\r\nHost: real.example.com\r\n"
                                     -> request_headers, the hook of sid 110 and
                                        of sid 120, first inspection of the tx
  5      S: ack
  6      C: "\r\n"                   -> header block closed, progress request_headers
                                        still, then request_body on completion
  7      S: ack
  8      S: 200 response
  9      C: ack
  10-12  client FIN, server FIN/ACK, client ACK

Frame 4 carries the request line and one header in a single segment and does not
terminate the block: with the final CRLF in the same segment the parser closes the
header state inside that update, so the tx would never be inspected at the bound.
Splitting it is what makes the first inspection land on `request_headers`, where
sid 110 (host "never.example.com") is a miss that is not final yet, and sid 120
(host "real.example.com", higher id, same hook) is a candidate in the same walk.
"""

from scapy.all import Ether, IP, TCP, Raw, wrpcap

ETH_SRC = "00:11:22:33:44:55"
ETH_DST = "66:77:88:99:aa:bb"
SRC = "10.20.0.14"
DST = "93.184.216.34"
SPORT = 49200
DPORT = 80
CSEQ, SSEQ = 2000, 6000

HDRS1 = b"GET /decide HTTP/1.1\r\nHost: real.example.com\r\n"
HDRS2 = b"\r\n"
RESP = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"


class Flow:
    """Track the four sequence edges so the data packets stay in order."""

    def __init__(self):
        self.cseq, self.sseq = CSEQ + 1, SSEQ + 1
        self.sack, self.cake = CSEQ + 1, CSEQ + 1

    def mk(self, src, dst, sp, dp, seq, ack, flags, payload=b""):
        pkt = (Ether(src=ETH_SRC if src == SRC else ETH_DST,
                     dst=ETH_DST if src == SRC else ETH_SRC) /
               IP(src=src, dst=dst) /
               TCP(sport=sp, dport=dp, seq=seq, ack=ack, flags=flags))
        if payload:
            pkt = pkt / Raw(load=payload)
        return pkt

    def handshake(self, pkts):
        pkts.append(self.mk(SRC, DST, SPORT, DPORT, CSEQ, 0, "S"))
        pkts.append(self.mk(DST, SRC, DPORT, SPORT, SSEQ, CSEQ + 1, "SA"))
        self.cake = SSEQ + 1
        self.client(b"", "A", pkts)

    def client(self, payload, flags, pkts):
        pkts.append(self.mk(SRC, DST, SPORT, DPORT, self.cseq, self.cake, flags, payload))
        self.cseq += len(payload) + (1 if "F" in flags else 0)
        self.sack = self.cseq

    def server(self, payload, flags, pkts):
        pkts.append(self.mk(DST, SRC, DPORT, SPORT, self.sseq, self.sack, flags, payload))
        self.sseq += len(payload) + (1 if "F" in flags else 0)
        self.cake = self.sseq

    def close(self, pkts):
        self.client(b"", "F", pkts)
        self.server(b"", "FA", pkts)
        self.client(b"", "A", pkts)


def main():
    pkts = []
    flow = Flow()
    flow.handshake(pkts)             # 1 S, 2 SA, 3 ACK
    flow.client(HDRS1, "PA", pkts)    # 4 first inspection, at the hook
    flow.server(b"", "A", pkts)       # 5
    flow.client(HDRS2, "PA", pkts)    # 6 closes the header block
    flow.server(b"", "A", pkts)       # 7
    flow.server(RESP, "PA", pkts)     # 8 response
    flow.client(b"", "A", pkts)       # 9
    flow.close(pkts)                  # 10-12
    wrpcap("input.pcap", pkts)


if __name__ == "__main__":
    main()
