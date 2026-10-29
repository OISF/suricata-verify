#!/usr/bin/env python3
"""Generate input.pcap: one plain HTTP/1.1 request/response exchange.

Layout (pcap_cnt):
  1-3  TCP handshake
  4    GET /index.html with Host: example.com
  5    server ACK
  6    HTTP/1.1 200 OK response
  7    client FIN/ACK
  8    server FIN/ACK
  9    client ACK
"""

from scapy.all import Ether, IP, TCP, Raw, wrpcap

SRC = "192.168.0.1"
DST = "192.168.0.2"
SPORT = 44444
DPORT = 80

REQ = (
    b"GET /index.html HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"User-Agent: curl/8.0\r\n"
    b"Accept: */*\r\n"
    b"\r\n"
)
RESP = (
    b"HTTP/1.1 200 OK\r\n"
    b"Server: test\r\n"
    b"Content-Length: 0\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)


def frame(pkt):
    return Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / pkt


def main():
    cseq = 1
    sseq = 1
    packets = [
        (frame(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="S", seq=0)), 0.00),
        (frame(IP(src=DST, dst=SRC) / TCP(sport=DPORT, dport=SPORT, flags="SA", seq=0,
                                                     ack=1)), 0.01),
        (frame(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="A", seq=cseq,
                                                     ack=sseq)), 0.02),
        (frame(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="PA", seq=cseq,
                                                     ack=sseq) / Raw(load=REQ)), 0.03),
        (frame(IP(src=DST, dst=SRC) / TCP(sport=DPORT, dport=SPORT, flags="A", seq=sseq,
                                                     ack=cseq + len(REQ))), 0.04),
        (frame(IP(src=DST, dst=SRC) / TCP(sport=DPORT, dport=SPORT, flags="PA", seq=sseq,
                                                     ack=cseq + len(REQ)) / Raw(load=RESP)), 0.05),
    ]
    cseq += len(REQ)
    sseq += len(RESP)
    packets += [
        (frame(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="FA", seq=cseq,
                                                     ack=sseq)), 0.06),
        (frame(IP(src=DST, dst=SRC) / TCP(sport=DPORT, dport=SPORT, flags="FA", seq=sseq,
                                                     ack=cseq)), 0.07),
        (frame(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="A", seq=cseq + 1,
                                                     ack=sseq)), 0.08),
    ]

    for pkt, ts in packets:
        pkt.time = ts

    wrpcap("input.pcap", [pkt for pkt, _ in packets])
    print(f"wrote input.pcap with {len(packets)} packets")


if __name__ == "__main__":
    main()
