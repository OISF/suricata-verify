#!/usr/bin/env python3
"""Generate input.pcap: an HTTP/1 request whose header block completes in the
last data packet of the flow, so the transaction sits at the request_headers
state and never advances: no body, no response, then the client closes.

Layout (pcap_cnt):
  1-3   TCP handshake
  4     C: GET /index.html with a complete header block
  5     C: FIN
  6     S: ACK
"""

from scapy.all import Ether, IP, TCP, Raw, wrpcap

ETH_SRC = "00:11:22:33:44:55"
ETH_DST = "66:77:88:99:aa:bb"
SRC = "192.168.0.1"
DST = "192.168.0.2"
SPORT = 44444
DPORT = 80

REQ = (
    b"GET /index.html HTTP/1.1\r\n"
    b"Host: www.example.com\r\n"
    b"User-Agent: curl/7.5\r\n"
    b"\r\n"
)


def main():
    cseq, sseq = 1, 1
    out = []

    def c2s(payload, when, flags="PA"):
        nonlocal cseq
        pkt = (Ether(src=ETH_SRC, dst=ETH_DST) / IP(src=SRC, dst=DST) /
               TCP(sport=SPORT, dport=DPORT, flags=flags, seq=cseq, ack=sseq))
        if payload:
            pkt = pkt / Raw(load=payload)
            cseq += len(payload)
        out.append((when, pkt))

    def s2c(payload, when, flags="PA"):
        nonlocal sseq
        pkt = (Ether(src=ETH_DST, dst=ETH_SRC) / IP(src=DST, dst=SRC) /
               TCP(sport=DPORT, dport=SPORT, flags=flags, seq=sseq, ack=cseq))
        if payload:
            pkt = pkt / Raw(load=payload)
            sseq += len(payload)
        out.append((when, pkt))

    out.append((0.0, Ether(src=ETH_SRC, dst=ETH_DST) / IP(src=SRC, dst=DST) /
                TCP(sport=SPORT, dport=DPORT, flags="S", seq=0)))
    out.append((0.01, Ether(src=ETH_DST, dst=ETH_SRC) / IP(src=DST, dst=SRC) /
                TCP(sport=DPORT, dport=SPORT, flags="SA", seq=0, ack=1)))
    out.append((0.02, Ether(src=ETH_SRC, dst=ETH_DST) / IP(src=SRC, dst=DST) /
                TCP(sport=SPORT, dport=DPORT, flags="A", seq=cseq, ack=sseq)))
    c2s(REQ, 0.04)
    c2s(None, 0.06, flags="FA")
    s2c(None, 0.08)

    for when, pkt in out:
        pkt.time = when
    wrpcap("input.pcap", [pkt for _, pkt in out])
    print("wrote input.pcap with %d packets" % len(out))


if __name__ == "__main__":
    main()
