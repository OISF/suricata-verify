#!/usr/bin/env python3
"""Generate test.pcap for http-bytevar-cross-packet.

One HTTP/1.1 request on a single TCP flow, split across two packets:
packet 1 carries the request line and headers, packet 2 carries the
100-byte body ("xxxMARK" plus 93 "A" bytes, MARK at 3..6). The
test rule's headers section (packet 1's detect run) extracts the
"1" byte of "Content-Length: 100" (ASCII 49) into v1; its body
section (packet 2's detect run) matches "MARK" at depth:v1 -
reachable only when the extracted value survives the packet
boundary. If the value is zeroed at the boundary (the bug),
depth:v1 is 0 and the rule cannot match.
"""

from scapy.all import IP, TCP, Raw, wrpcap

OUTPUT = "test.pcap"

SRC_IP = "192.168.1.100"
DST_IP = "192.168.1.200"
SRC_PORT = 50000
DST_PORT = 80

REQUEST_HEAD = (b"GET /abcde HTTP/1.1\r\n"
                b"Host: test\r\n"
                b"Content-Length: 100\r\n"
                b"\r\n")
BODY = b"xxxMARK" + b"A" * 93  # 100 bytes, MARK at 3..6
RESPONSE = (b"HTTP/1.1 200 OK\r\n"
            b"Content-Length: 2\r\n"
            b"Connection: close\r\n"
            b"\r\n"
            b"ok")


def main():
    cseq, sseq = 1000, 5000
    pkts = []

    def cli(flags, payload=b""):
        p = IP(src=SRC_IP, dst=DST_IP) / TCP(sport=SRC_PORT, dport=DST_PORT,
                                             flags=flags, seq=cseq, ack=sseq)
        return p / Raw(load=payload) if payload else p

    def srv(flags, payload=b""):
        p = IP(src=DST_IP, dst=SRC_IP) / TCP(sport=DST_PORT, dport=SRC_PORT,
                                             flags=flags, seq=sseq, ack=cseq)
        return p / Raw(load=payload) if payload else p

    pkts.append(cli("S"))
    cseq += 1
    pkts.append(srv("SA"))
    sseq += 1
    pkts.append(cli("A"))

    # packet 1: request line + headers (byte_extract writes v1 here)
    pkts.append(cli("PA", REQUEST_HEAD))
    cseq += len(REQUEST_HEAD)
    pkts.append(srv("A"))

    # packet 2: the body, inspected with depth:v1
    pkts.append(cli("PA", BODY))
    cseq += len(BODY)
    pkts.append(srv("PA", RESPONSE))
    sseq += len(RESPONSE)
    pkts.append(cli("A"))

    pkts.append(cli("FA"))
    cseq += 1
    pkts.append(srv("FA"))
    sseq += 1
    pkts.append(cli("A"))

    base = 1700000000.0
    for i, p in enumerate(pkts):
        p.time = base + i * 0.01

    wrpcap(OUTPUT, pkts)
    print(f"Created {OUTPUT} with {len(pkts)} packets")


if __name__ == "__main__":
    main()
