#!/usr/bin/env python3
"""Generate input.pcap: a POST whose body is sent after its headers,
answered by 200 OK. Meant to be read in IDS mode, where data is parsed
once the other side acknowledges it, and a direction is inspected on its
next packet.

Layout (pcap_cnt):
  1-3  TCP handshake
  4    client: POST /upload request line and headers
  5    server: ACK, the headers are parsed
  6    client: request body, request side inspected with the headers only
  7    server: HTTP/1.1 200 OK, acknowledges the body, the body is parsed
  8    client: FIN, acknowledges the response, the response is parsed and
       the request side is inspected with the body
  9    server: FIN, response side inspected
  10   client: ACK
"""

from scapy.all import Ether, IP, TCP, Raw, wrpcap

BODY = b"xxxxsecretxxxx"
REQ = b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: %d\r\n\r\n" % len(BODY)
RESP = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"


def c(flags, seq, ack, load=None):
    pkt = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / \
        IP(src="192.168.0.1", dst="192.168.0.2") / \
        TCP(sport=44444, dport=80, flags=flags, seq=seq, ack=ack)
    return pkt / Raw(load=load) if load else pkt


def s(flags, seq, ack, load=None):
    pkt = Ether(src="66:77:88:99:aa:bb", dst="00:11:22:33:44:55") / \
        IP(src="192.168.0.2", dst="192.168.0.1") / \
        TCP(sport=80, dport=44444, flags=flags, seq=seq, ack=ack)
    return pkt / Raw(load=load) if load else pkt


def main():
    cfin = 1 + len(REQ) + len(BODY)
    sfin = 1 + len(RESP)
    packets = [
        c("S", 0, 0),
        s("SA", 0, 1),
        c("A", 1, 1),
        c("PA", 1, 1, REQ),
        s("A", 1, 1 + len(REQ)),
        c("PA", 1 + len(REQ), 1, BODY),
        s("PA", 1, cfin, RESP),
        c("FA", cfin, sfin),
        s("FA", sfin, cfin + 1),
        c("A", cfin + 1, sfin + 1),
    ]
    for i, pkt in enumerate(packets):
        pkt.time = i * 0.01

    wrpcap("input.pcap", packets)
    print(f"wrote input.pcap with {len(packets)} packets")


if __name__ == "__main__":
    main()
