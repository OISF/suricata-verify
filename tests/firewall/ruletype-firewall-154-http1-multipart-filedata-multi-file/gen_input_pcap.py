#!/usr/bin/env python3
"""Generate input.pcap: an HTTP1 multipart/form-data upload with two files.

The first file is plain text and does not contain the content matched by
the filedata firewall rule (content:"%PDF"). The second file does contain
%PDF. The body is streamed in chunks so the files are added to the tx
incrementally.

This pins the per-file state reset: after the first file is inspected (no
match) the rule must remain matchable, so the second file still triggers it.
The rule accepts (and alerts) on the second file; the fail-closed default
policy must NOT be applied.

Layout (pcap_cnt):
  1-3  TCP handshake
  4    POST request line + headers
  5    body part 1 (multipart headers + file 1 start)
  6    body part 2 (file 1 end / file 2 start)
  7    body part 3 (file 2 end, request completes here)
  8    server ACK
  9    HTTP 200 OK response
  10   client ACK
"""

from scapy.all import Ether, IP, TCP, Raw, wrpcap

ETH_SRC = "00:11:22:33:44:55"
ETH_DST = "66:77:88:99:aa:bb"
SRC = "192.168.0.1"
DST = "192.168.0.2"
SPORT = 44444
DPORT = 80

BOUNDARY = "AaB03x"
FILE1_CONTENT = b"no match here, this is the first plain file\n"
FILE2_CONTENT = b"%PDF-1.4 this second file has the pdf magic\n"


def part(name, fname, content):
    return (
        f"--{BOUNDARY}\r\n"
        "Content-Type: application/octet-stream\r\n"
        f'Content-Disposition: form-data; name="{name}"; filename="{fname}"\r\n'
        "\r\n"
    ).encode() + content


BODY = part("f1", "a.txt", FILE1_CONTENT) + part("f2", "c.pdf", FILE2_CONTENT) \
    + f"\r\n--{BOUNDARY}--\r\n".encode()

REQ_HEAD = (
    "POST /upload HTTP/1.1\r\n"
    "Host: upload.example.com\r\n"
    f"Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n"
    f"Content-Length: {len(BODY)}\r\n"
    "\r\n"
).encode()

RESP = (
    "HTTP/1.1 200 OK\r\n"
    "Server: test\r\n"
    "Content-Length: 2\r\n"
    "\r\n"
    "OK"
).encode()


def frame(pkt):
    return Ether(src=ETH_SRC, dst=ETH_DST) / pkt


def main():
    cseq = 1  # after SYN
    sseq = 1  # after SYN
    t = 0.02
    packets = [
        (frame(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="S", seq=0)), 0.0),
        (frame(IP(src=DST, dst=SRC) / TCP(sport=DPORT, dport=SPORT, flags="SA", seq=0, ack=1)), 0.01),
        (frame(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="A", seq=cseq,
                                               ack=sseq)), t),
    ]

    # stream the body in 3 chunks so the two files are added incrementally
    mid1 = len(BODY) // 3
    mid2 = 2 * len(BODY) // 3
    data = [REQ_HEAD, BODY[:mid1], BODY[mid1:mid2], BODY[mid2:]]
    for d in data:
        p = frame(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="PA", seq=cseq,
                                                      ack=sseq) / Raw(load=d))
        packets.append((p, t))
        cseq += len(d)
        t += 0.05

    # server acks the whole request
    packets.append(
        (frame(IP(src=DST, dst=SRC) / TCP(sport=DPORT, dport=SPORT, flags="A", seq=sseq,
                                                     ack=cseq)), t + 0.01))
    # server response
    packets.append(
        (frame(IP(src=DST, dst=SRC) / TCP(sport=DPORT, dport=SPORT, flags="PA", seq=sseq,
                                                     ack=cseq) / Raw(load=RESP)), t + 0.05))
    sseq += len(RESP)
    # client acks the response
    packets.append(
        (frame(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="A", seq=cseq,
                                                     ack=sseq)), t + 0.06))

    for pkt, dt in packets:
        pkt.time = dt

    wrpcap("input.pcap", [pkt for pkt, _ in packets])
    print(f"wrote input.pcap with {len(packets)} packets, body len {len(BODY)}")


if __name__ == "__main__":
    main()
