#!/usr/bin/env python3
"""Generate input.pcap: a POST whose server never sends an HTTP response,
so the toclient engine of a `=>` rule can never match this transaction
(Redmine #9087).

Layout (pcap_cnt):
  1-3  TCP handshake
  4    client: POST /upload with headers and body "xxxxsecretxxxx"
  5    server: bare ACK, the request is complete
  6    server: FIN with no application data; there is no response tx to
       inspect, so the toclient engines never run
  7    client: ACK
"""

from scapy.all import Ether, IP, TCP, Raw, wrpcap

BODY = b"xxxxsecretxxxx"
REQ = b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: %d\r\n\r\n" % len(BODY)


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
    cend = 1 + len(REQ) + len(BODY)
    packets = [
        c("S", 0, 0),
        s("SA", 0, 1),
        c("A", 1, 1),
        c("PA", 1, 1, REQ + BODY),
        s("A", 1, cend),
        s("FA", 1, cend),
        c("FA", cend, 2),
        s("A", 2, cend + 1),
    ]
    for i, pkt in enumerate(packets):
        pkt.time = i * 0.01

    wrpcap("input.pcap", packets)
    print(f"wrote input.pcap with {len(packets)} packets")


if __name__ == "__main__":
    main()
