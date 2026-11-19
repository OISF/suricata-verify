#!/usr/bin/env python3
"""Generate input.pcap: a chunked POST whose response is sent before the
request body completes, so the toclient half of a `=>` rule finishes
first and the pair is only closed by a later toserver inspection
(Redmine #9087).

Layout (pcap_cnt):
  1-3  TCP handshake
  4    client: POST /upload request line and headers, Transfer-Encoding: chunked
  5    server: HTTP/1.1 200 OK, an early response while the body is still
       streaming; the toclient engines run and complete here
  6    client: chunk "secret"; the toserver half matches for the first time
  7    client: terminating chunk, the request completes, no new body data
  8-10 teardown
"""

from scapy.all import Ether, IP, TCP, Raw, wrpcap

REQ = b"POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n"
RESP = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
CHUNK = b"6\r\nsecret\r\n"
LAST = b"0\r\n\r\n"


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
        s("PA", 1, 1, RESP),
        c("PA", chunk, 1 + len(RESP), CHUNK),
        c("PA", last, 1 + len(RESP), LAST),
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
