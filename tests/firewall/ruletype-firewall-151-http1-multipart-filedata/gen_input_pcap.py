#!/usr/bin/env python3
"""Generate input.pcap: an HTTP1 multipart/form-data upload.

The uploaded file is plain text and does not contain the content matched by
the filedata firewall rule (content:"%PDF"), so the request tx completes
without the rule matching and the fail-closed default policy must drop it.

Layout (pcap_cnt):
  1-3  TCP handshake
  4    POST request line + headers
  5    body part 1 (multipart headers + file start)
  6    body part 2 (file end, request completes here)
  7    server ACK
  8    HTTP 200 OK response
  9    client ACK
"""

from scapy.all import Ether, IP, TCP, Raw, wrpcap

ETH_SRC = "00:11:22:33:44:55"
ETH_DST = "66:77:88:99:aa:bb"


def frame(pkt):
    return Ether(src=ETH_SRC, dst=ETH_DST) / pkt

SRC = "192.168.0.1"
DST = "192.168.0.2"
SPORT = 44444
DPORT = 80

BOUNDARY = "AaB03x"
FILE_CONTENT = b"hello world, this is a plain text file\n"

BODY = (
    f"--{BOUNDARY}\r\n"
    "Content-Type: text/plain\r\n"
    f'Content-Disposition: form-data; name="file"; filename="notes.txt"\r\n'
    "\r\n"
).encode() + FILE_CONTENT + f"\r\n--{BOUNDARY}--\r\n".encode()

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


def main():
    cseq = 1  # after SYN
    sseq = 1  # after SYN
    packets = [
        (frame(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="S", seq=0)), 0.0),
        (frame(IP(src=DST, dst=SRC) / TCP(sport=DPORT, dport=SPORT, flags="SA", seq=0, ack=1)), 0.01),
        (frame(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="A", seq=cseq,
                                               ack=sseq)), 0.02),
    ]

    # request: split headers and body into 2 packets so the file is streamed
    mid = len(BODY) // 2
    data = [REQ_HEAD, BODY[:mid], BODY[mid:]]
    t = 0.1
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
