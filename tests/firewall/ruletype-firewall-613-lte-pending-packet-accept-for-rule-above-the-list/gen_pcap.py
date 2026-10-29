#!/usr/bin/env python3
"""Generate input.pcap: a group whose stream pattern lands above the hook.

606 splits the request line across packets, so the tx is inspected at
`request_line` and rule state is stored there, before the hook. This pcap removes
that earlier update: the request line and the first header arrive in ONE segment,
so the tx is created and FIRST inspected at `request_headers`, i.e. at the hook
(`http1:<request_headers` is the bound of the transaction), and no prior
progress carries any rule state.

Note the header block is not terminated in that first segment: with the whole
block including the final CRLF in one segment the parser advances straight to
`request_body` (the header state is closed inside the same update), so the tx
would never be inspected at the bound at all. The request line + one header line
in a single segment is what makes the first inspection land on `request_headers`.

Then the transaction advances through updates that are strictly inside it:

  - the update closing the header block advances progress to request_body and
    holds no `STREAMONLY`,
  - a LATER update carries `STREAMONLY` while the body is still incomplete, so
    its ts_progress is still request_body and still within the tx,
  - a final body update completes Content-Length,
  - then the server response.

Layout (pcap_cnt; tshark frame numbers are the same):
  1-3    TCP handshake
  4      C: "POST /upload HTTP/1.1\\r\\nHost: other.example\\r\\n"
                                             -> request_headers (the hook), first
                                                inspection of the tx
  5      S: ack
  6      C: "Content-Length: 46\\r\\n\\r\\n"  -> request_body, no STREAMONLY
  7      S: ack
  8      C: body "A"*20 + "STREAMONLY" + "Z"*6
                                             -> request_body, carries STREAMONLY
  9      S: ack
  10     C: body "z"*10                     -> request_body, body complete
  11     S: ack
  12     S: 200 response
  13     C: ack
  14-16  client FIN, server FIN/ACK, client ACK

Server ACKs are interleaved so each client segment is its own app update.
"""

from scapy.all import Ether, IP, TCP, Raw, wrpcap

ETH_SRC = "00:11:22:33:44:55"
ETH_DST = "66:77:88:99:aa:bb"
SRC = "10.20.0.14"
DST = "93.184.216.34"
SPORT = 49200
DPORT = 80
CSEQ, SSEQ = 2000, 6000

# one segment: request line and headers start together, block not terminated
HDRS1 = b"POST /upload HTTP/1.1\r\nHost: other.example\r\n"
# closes the header block: progress becomes request_body, no STREAMONLY here
HDRS2 = b"Content-Length: %d\r\n\r\n"
BODY1 = b"A" * 20 + b"STREAMONLY" + b"Z" * 6
BODY2 = b"z" * 10
BODY_LEN = len(BODY1) + len(BODY2)
RESP = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"


class Flow:
    """Track the four sequence edges so the data packets stay in order."""

    def __init__(self):
        self.cseq, self.sseq = CSEQ + 1, SSEQ + 1
        self.sack, self.cake = CSEQ + 1, SSEQ + 1

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
        self.client(b"", "A", pkts)

    def client(self, payload, flags, pkts):
        pkts.append(self.mk(SRC, DST, SPORT, DPORT, self.cseq, self.cake,
                            flags, payload))
        self.cseq += len(payload) + (1 if "F" in flags else 0)
        self.sack = self.cseq

    def server(self, payload, flags, pkts):
        pkts.append(self.mk(DST, SRC, DPORT, SPORT, self.sseq, self.sack,
                            flags, payload))
        self.sseq += len(payload) + (1 if "F" in flags else 0)
        self.cake = self.sseq

    def close(self, pkts):
        self.client(b"", "F", pkts)
        self.server(b"", "FA", pkts)
        self.client(b"", "A", pkts)


def main():
    pkts = []
    flow = Flow()
    flow.handshake(pkts)  # 1 S, 2 SA, 3 ACK
    flow.client(HDRS1, "PA", pkts)
    flow.server(b"", "A", pkts)  # 4 first inspection, at the hook, 5
    flow.client(HDRS2 % BODY_LEN, "PA", pkts)
    flow.server(b"", "A", pkts)  # 6 request_body, no match, 7
    flow.client(BODY1, "PA", pkts)
    flow.server(b"", "A", pkts)  # 8 request_body with STREAMONLY, 9
    flow.client(BODY2, "PA", pkts)
    flow.server(b"", "A", pkts)  # 10 body complete, 11
    flow.server(RESP, "PA", pkts)  # 12
    flow.client(b"", "A", pkts)  # 13
    flow.close(pkts)  # 14-16

    for i, pkt in enumerate(pkts):
        pkt.time = i * 0.00025
    wrpcap("input.pcap", pkts)
    print("wrote input.pcap with %d packets" % len(pkts))


if __name__ == "__main__":
    main()
