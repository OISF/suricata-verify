"""Craft a chunked POST whose trailer fields reuse names from the header section.

Used to check that trailer data stays out of the header buffers and is available
through the trailer buffers. --split ends a segment with "0\r\n" and puts the trailer
lines in the next one, so detection has to handle the transient trailer state.

Checksums are not computed; Suricata needs -k none.
"""

import struct
import sys

OUT = "input.pcap"
SPLIT = "--split" in sys.argv
ARGS = [a for a in sys.argv[1:] if not a.startswith("--")]
if ARGS:
    OUT = ARGS[0]

MSS = 1400
pkts = []  # (client, flags, seq, ack, payload)


def emit(client, flags, payload=b""):
    global cseq, sseq
    pkts.append((client, flags, cseq if client else sseq, sseq if client else cseq, payload))
    # SYN and FIN each consume one sequence number
    extra = 1 if flags & (0x02 | 0x01) else 0
    if client:
        cseq += len(payload) + extra
    else:
        sseq += len(payload) + extra


cseq = sseq = 0
emit(True, 0x02)  # SYN
emit(False, 0x12)  # SYN/ACK
emit(True, 0x10)  # ACK

hdr = (
    b"POST /upload HTTP/1.1\r\n"
    b"Host: localhost\r\n"
    b"User-Agent: Mozilla\r\n"
    b"Trailer: Server-Timing\r\n"
    b"Content-Type: application/x-www-form-urlencoded\r\n"
    b"Transfer-Encoding: chunked\r\n"
    b"\r\n"
)
data = b"p=0123456789" * 20
body = b"%x\r\n" % len(data) + data + b"\r\n"
trailer = b"Server-Timing: trailval\r\nUser-Agent: TRAILER-UA\r\nHost: TRAILER-HOST\r\n\r\n"
req = hdr + body + b"0\r\n" + (b"" if SPLIT else trailer)
tail = trailer if SPLIT else b""

buf = req
while buf:
    emit(True, 0x18, buf[:MSS])
    buf = buf[MSS:]
if tail:
    emit(False, 0x10)  # ACK between the last chunk and the trailer fields
    emit(True, 0x18, tail)

resp = (
    b"HTTP/1.0 200 OK\r\n"
    b"Date: Mon, 31 Aug 2009 20:25:50 GMT\r\n"
    b"Server: Apache\r\n"
    b"Connection: close\r\n"
    b"Content-Type: text/html\r\n"
    b"Content-Length: 12\r\n"
    b"\r\nHello World!"
)
emit(False, 0x18, resp)
emit(True, 0x10)
emit(False, 0x19)  # FIN/ACK
emit(True, 0x10)


def build(client, flags, seq, ack, payload):
    sport, dport = (58919, 80) if client else (80, 58919)
    mac_src = b"\x00\x11\x22\x33\x44\x55" if client else b"\x00\x11\x22\x33\x44\x66"
    mac_dst = b"\x00\x11\x22\x33\x44\x66" if client else b"\x00\x11\x22\x33\x44\x55"
    ip_src = b"\xc0\xa8\x01\x0a" if client else b"\xc0\xa8\x01\x14"
    ip_dst = b"\xc0\xa8\x01\x14" if client else b"\xc0\xa8\x01\x0a"
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + 20 + len(payload),
        1,
        0x4000,
        64,
        6,
        0,
        ip_src,
        ip_dst,
    )
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0)
    return mac_dst + mac_src + b"\x08\x00" + ip + tcp + payload


with open(OUT, "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))  # DLT_EN10MB
    for i, (client, flags, seq, ack, payload) in enumerate(pkts):
        d = build(client, flags, seq, ack, payload)
        f.write(struct.pack("<IIII", 1700000000 + i, 0, len(d), len(d)))
        f.write(d)
print(OUT, "packets:", len(pkts), "split:", bool(SPLIT))
