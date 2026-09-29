#!/usr/bin/env python3
"""Generate upload.pcap for the stream reassembly depth ACK tracking test.

One TCP connection (10.0.0.1:1234 <-> 10.0.0.2:80) carrying an HTTP POST with
a 40960 byte body, run through in IPS mode against a stream.reassembly.depth
of 8 KB, so the to-server direction hits the depth and stops collecting data
while the flow keeps carrying bytes.

  * the 3-way handshake, with the sequence numbers of both sides 1 apart,
  * one segment of request headers (131 bytes, no body byte in it),
  * the body in MSS-sized segments of 1000 bytes, the last one short,
  * a bare ACK from the server every ACK_EVERY data segments, so the
    to-server direction keeps being acknowledged after the depth is reached,
  * the response (57 bytes, acknowledging what is left of the body),
  * the close: FIN,ACK from the client, FIN,ACK from the server, final ACK.

The sizes are what the test asserts on, so they are all named constants:
BODY_SIZE has to be well past DEPTH for the to-server direction to stop
collecting, and the ACK pattern has to keep moving for the ACK tracking of
the peer to stay alive.

Only the standard library is used.

    python3 writepcap.py upload.pcap
"""

import socket
import struct
import sys

CLIENT_IP = "10.0.0.1"
SERVER_IP = "10.0.0.2"
CLIENT_MAC = b"\xaa\xbb\xcc\xdd\xee\x01"
SERVER_MAC = b"\xaa\xbb\xcc\xdd\xee\x02"
CLIENT_PORT = 1234
SERVER_PORT = 80

# The sequence numbers of the two sides. Small and 1 apart, so that the
# arithmetic of the test is the one that matters, not the wrap of a big one.
CLIENT_ISN = 1000
SERVER_ISN = 5000

DEPTH = 8 * 1024  # what the test sets stream.reassembly.depth to
MSS = 1000  # size of the data segments of the body
BODY_SIZE = 5 * DEPTH  # well past the depth, and not a multiple of the MSS
ACK_EVERY = 2  # the server acknowledges every second data segment
FILLER = b"\xaa"

URL = b"/ABCDEFGHIJ"
HOST = b"sv.test"

WINDOW = 65535
TTL = 64
IP_ID = 1

# One timestamp for every frame: the test asserts nothing about timing, and the
# flow is far too short to run into a timeout.
TS_SEC = 1790676850
TS_USEC = 411906

SYN, SYNACK, ACK, PSHACK, FINACK = 0x02, 0x12, 0x10, 0x18, 0x11

HEADERS = (
    b"POST " + URL + b" HTTP/1.1\r\n"
    b"Host: " + HOST + b"\r\n"
    b"Content-Type: application/octet-stream\r\n"
    b"Content-Length: " + str(BODY_SIZE).encode() + b"\r\n"
    b"Connection: keep-alive\r\n"
    b"\r\n"
)

RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"


def checksum(b):
    if len(b) % 2:
        b += b"\x00"
    s = 0
    for i in range(0, len(b), 2):
        s += struct.unpack("!H", b[i : i + 2])[0]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def tcp_seg(sport, dport, seq, ack, flags, payload, sip, dip):
    hdr = struct.pack(
        "!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, WINDOW, 0, 0
    )
    pseudo = struct.pack(
        "!4s4sBBH", socket.inet_aton(sip), socket.inet_aton(dip), 0, 6,
        len(hdr) + len(payload),
    )
    ck = checksum(pseudo + hdr + payload)
    return hdr[:16] + struct.pack("!H", ck) + hdr[18:] + payload


def ip4(src, dst, plen):
    hdr = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + plen, IP_ID, 0, TTL, 6, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    )
    return hdr[:10] + struct.pack("!H", checksum(hdr)) + hdr[12:]


def segments():
    """Yield the flow as (to_server, flags, seq, ack, payload) tuples."""
    yield (True, SYN, CLIENT_ISN, 0, b"")
    yield (False, SYNACK, SERVER_ISN, CLIENT_ISN + 1, b"")
    yield (True, ACK, CLIENT_ISN + 1, SERVER_ISN + 1, b"")

    cseq = CLIENT_ISN + 1
    sseq = SERVER_ISN + 1

    # The request line and the headers, in one segment of their own.
    yield (True, PSHACK, cseq, sseq, HEADERS)
    cseq += len(HEADERS)

    # The body in MSS-sized segments, the last one carrying what is left of
    # it. The server ACK's every ACK_EVERY-th one, so the first ACK of the
    # body lands after 2 segments and the headers are not acknowledged on
    # their own.
    body = FILLER * BODY_SIZE
    chunks = [body[i:i + MSS] for i in range(0, len(body), MSS)]
    for i, chunk in enumerate(chunks, start=1):
        yield (True, PSHACK, cseq, sseq, chunk)
        cseq += len(chunk)
        if i % ACK_EVERY == 0:
            yield (False, ACK, sseq, cseq, b"")

    # The response closes out the request, so it carries the last ACK.
    yield (False, PSHACK, sseq, cseq, RESPONSE)
    sseq += len(RESPONSE)

    yield (True, FINACK, cseq, sseq, b"")
    cseq += 1
    yield (False, FINACK, sseq, cseq, b"")
    sseq += 1
    yield (True, ACK, cseq, sseq, b"")


def write_pcap(path):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for to_server, flags, seq, ack, payload in segments():
            if to_server:
                sip, dip = CLIENT_IP, SERVER_IP
                sport, dport = CLIENT_PORT, SERVER_PORT
                eth = SERVER_MAC + CLIENT_MAC + b"\x08\x00"
            else:
                sip, dip = SERVER_IP, CLIENT_IP
                sport, dport = SERVER_PORT, CLIENT_PORT
                eth = CLIENT_MAC + SERVER_MAC + b"\x08\x00"
            seg = tcp_seg(sport, dport, seq, ack, flags, payload, sip, dip)
            pkt = eth + ip4(sip, dip, len(seg)) + seg
            f.write(struct.pack("<IIII", TS_SEC, TS_USEC, len(pkt), len(pkt)))
            f.write(pkt)


if __name__ == "__main__":
    write_pcap(sys.argv[1] if len(sys.argv) > 1 else "upload.pcap")
