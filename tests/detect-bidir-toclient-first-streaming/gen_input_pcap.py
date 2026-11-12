#!/usr/bin/env python3
"""Generate input.pcap: a chunked POST whose early 200 response is still
streaming when the last request body segment arrives, so the toclient half
of a `=>` rule matches first and the toserver pass of the last request
segment must close the pair (Redmine #9087).

While the pair is open, the wrong-variant toclient engines of the rule
(http2 on this http1 flow) sit in the skip branch of the toserver pass.
They can never inspect this flow, so they must not hold the pair open;
before the fix they unconditionally did (other_dir_pending), and the rule
never alerted.

Layout (pcap_cnt):
  1-3  TCP handshake
  4    client: POST /upload request line and headers, Content-Length: 26
  5    client: body segment 1 "the-first-"
  6    server: HTTP/1.1 200 OK, Transfer-Encoding: chunked, first chunk;
       the toclient half matches here, the response is still streaming
  7    server: second chunk, the response is still streaming
  8    client: body segment 2 "part-secret-"; the toserver half matches
       here and closes the pair
  9    client: body segment 3 "tail"; the request completes
  10   server: terminating chunk; the response completes
  11-13 teardown
"""

from scapy.all import Ether, IP, TCP, Raw, wrpcap

REQ = b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 26\r\n\r\n"
B1 = b"the-first-"
B2 = b"part-secret-"
B3 = b"tail"
assert len(B1) + len(B2) + len(B3) == 26

# "stream-data" is 11 bytes (0xb), "-more-data" is 10 bytes (0xa)
R1 = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + b"b\r\nstream-data\r\n"
R2 = b"a\r\n-more-data\r\n"
R3 = b"0\r\n\r\n"


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
    cseq = 1 + len(REQ)
    cseq_b2 = cseq + len(B1)
    cseq_b3 = cseq_b2 + len(B2)
    cend = cseq_b3 + len(B3)
    sseq = 1 + len(R1)
    sseq_r3 = sseq + len(R2)
    send = sseq_r3 + len(R3)

    packets = [
        c("S", 0, 0),
        s("SA", 0, 1),
        c("A", 1, 1),
        c("PA", 1, 1, REQ),
        c("PA", cseq, 1, B1),
        s("PA", 1, cseq, R1),
        s("PA", sseq, cseq, R2),
        c("PA", cseq_b2, 1 + len(R1), B2),
        c("PA", cseq_b3, 1 + len(R1), B3),
        s("PA", sseq_r3, cend, R3),
        c("FA", cend, send),
        s("FA", send, cend + 1),
        c("A", cend + 1, send + 1),
    ]
    for i, pkt in enumerate(packets):
        pkt.time = i * 0.01

    wrpcap("input.pcap", packets)
    print(f"wrote input.pcap with {len(packets)} packets")


if __name__ == "__main__":
    main()
