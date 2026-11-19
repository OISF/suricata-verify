#!/usr/bin/env python3
"""Generate input.pcap: a chunked POST whose only chunk is "secret" and
whose terminating chunk arrives in a later packet, answered by 200 OK.
Meant to be read in IPS mode, where each packet is parsed and inspected
when it arrives.

Layout (pcap_cnt):
  1-3  TCP handshake
  4    POST /upload request line and headers, Transfer-Encoding: chunked
  5    chunk "secret": the body is inspected while still in progress
  6    terminating chunk: the request completes, no new body data
  7    HTTP/1.1 200 OK response
  8-10 teardown
"""

from scapy.all import Ether, IP, TCP, Raw, wrpcap

REQ = b"POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n"
CHUNK = b"6\r\nsecret\r\n"
LAST = b"0\r\n\r\n"
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
    chunk = 1 + len(REQ)
    last = chunk + len(CHUNK)
    end = last + len(LAST)
    sfin = 1 + len(RESP)
    packets = [
        c("S", 0, 0),
        s("SA", 0, 1),
        c("A", 1, 1),
        c("PA", 1, 1, REQ),
        c("PA", chunk, 1, CHUNK),
        c("PA", last, 1, LAST),
        s("PA", 1, end, RESP),
        c("FA", end, sfin),
        s("FA", sfin, end + 1),
        c("A", end + 1, sfin + 1),
    ]
    for i, pkt in enumerate(packets):
        pkt.time = i * 0.01

    wrpcap("input.pcap", packets)
    print(f"wrote input.pcap with {len(packets)} packets")


if __name__ == "__main__":
    main()
