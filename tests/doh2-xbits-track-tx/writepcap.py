#!/usr/bin/env python3
"""Generate input.pcap for the doh2 xbits:track-tx test.

Two TCP connections of cleartext HTTP/2 (h2c) are written:

Connection 1 (10.0.0.1:41111 -> 10.0.0.2:8053), DNS over HTTP/2:

  * stream 1: a complete DoH exchange (POST + DATA with END_STREAM, response
    HEADERS + DATA with END_STREAM). This is what turns the flow into
    ALPROTO_DOH2 and what gives the HTTP/2 transaction an inner DNS
    transaction on each side. Its query is tx1.example.com.
  * stream 3: the same POST, but its DATA frame has no END_STREAM, so the DoH
    to-server buffer of the next transaction in the parser's buffer stays
    populated. That buffer length is the value the buggy code dereferences
    as a pointer. Because the request body never completes, this transaction
    has no inner DNS transaction and no doh2 hook ever fires on it.
  * stream 5: a second complete DoH exchange, query tx2.example.com. Together
    with stream 1 this gives the flow two transactions that each carry a DNS
    transaction, so a transaction bit set on one can be read back on the
    other.

Connection 2 (10.0.0.1:41112 -> 10.0.0.2:8054), plain HTTP/2: a GET with an
HTML response over two streams. This flow stays ALPROTO_HTTP2, so it shows
that transaction bits keep working for HTTP/2 itself.

Only the standard library is used.

    python3 writepcap.py input.pcap
"""

import socket
import struct
import sys

CLIENT_IP = "10.0.0.1"
SERVER_IP = "10.0.0.2"
CLIENT_MAC = b"\x02\x00\x00\x00\x00\x01"
SERVER_MAC = b"\x02\x00\x00\x00\x00\x02"

H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

FRAME_DATA = 0
FRAME_HEADERS = 1
FRAME_SETTINGS = 4

FLAG_END_STREAM = 0x1
FLAG_END_HEADERS = 0x4

SYN, SYNACK, ACK, PSHACK, FINACK = 0x02, 0x12, 0x10, 0x18, 0x11


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
        "!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0
    )
    pseudo = struct.pack(
        "!4s4sBBH", socket.inet_aton(sip), socket.inet_aton(dip), 0, 6,
        len(hdr) + len(payload),
    )
    ck = checksum(pseudo + hdr + payload)
    return hdr[:16] + struct.pack("!H", ck) + hdr[18:] + payload


def ip4(src, dst, plen):
    hdr = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + plen, 0, 0x4000, 64, 6, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    )
    return hdr[:10] + struct.pack("!H", checksum(hdr)) + hdr[12:]


def frame(ftype, flags, stream_id, payload):
    return (
        struct.pack("!I", len(payload))[1:]
        + struct.pack("!BB", ftype, flags)
        + struct.pack("!I", stream_id & 0x7FFFFFFF)
        + payload
    )


def hpack(name, value):
    """Literal header field without indexing, without Huffman."""
    return (
        b"\x00"
        + struct.pack("!B", len(name)) + name.encode()
        + struct.pack("!B", len(value)) + value.encode()
    )


def dns_name(name):
    return (
        b"".join(struct.pack("!B", len(l)) + l.encode() for l in name.split(".")) + b"\x00"
    )


def dns_msg(tid, name, is_response, answer_ip="93.184.216.34"):
    flags = 0x8180 if is_response else 0x0100
    msg = struct.pack("!HHHHHH", tid, flags, 1, 0, 1 if is_response else 0, 0)
    msg += dns_name(name) + struct.pack("!HH", 1, 1)  # A / IN
    if is_response:
        msg += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4)
        msg += socket.inet_aton(answer_ip)
    return msg


def doh_connection():
    """Client and server payload for the DNS over HTTP/2 connection.

    Streams 1 and 5 are complete DoH exchanges and hold an inner DNS
    transaction each: the ruleset needs two of them to tell the transactions
    apart. Stream 3 stays incomplete on purpose.
    """
    q1 = dns_msg(0x1234, "tx1.example.com", False)
    # padded so that the trailing transaction keeps a small, non-zero DoH
    # to-server buffer
    q3 = dns_msg(0x1236, "crash.example.com", False)
    q3 += b"\x00" * (230 - len(q3))
    q5 = dns_msg(0x1238, "tx2.example.com", False)
    r1 = dns_msg(0x1234, "tx1.example.com", True)
    r5 = dns_msg(0x1238, "tx2.example.com", True)

    post = (
        hpack(":method", "POST")
        + hpack(":path", "/dns-query")
        + hpack(":scheme", "https")
        + hpack(":authority", "dns.example.com")
        + hpack("content-type", "application/dns-message")
    )
    ts = H2_PREFACE + frame(FRAME_SETTINGS, 0, 0, b"")
    for sid, data, dflags in (
        (1, q1, FLAG_END_STREAM),
        (3, q3, 0),
        (5, q5, FLAG_END_STREAM),
    ):
        ts += frame(FRAME_HEADERS, FLAG_END_HEADERS, sid, post)
        ts += frame(FRAME_DATA, dflags, sid, data)

    tc = frame(FRAME_SETTINGS, 0, 0, b"")
    for sid, msg in ((1, r1), (5, r5)):
        tc += frame(
            FRAME_HEADERS, FLAG_END_HEADERS, sid,
            hpack(":status", "200") + hpack("content-type", "application/dns-message"),
        )
        tc += frame(FRAME_DATA, FLAG_END_STREAM, sid, msg)
    return ts, tc


def plain_connection():
    """Client and server payload for the plain HTTP/2 connection."""
    get = (
        hpack(":method", "GET")
        + hpack(":path", "/index.html")
        + hpack(":scheme", "https")
        + hpack(":authority", "www.example.com")
    )
    ts = H2_PREFACE + frame(FRAME_SETTINGS, 0, 0, b"")
    ts += frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, get)
    ts += frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 3, get)

    resp = (
        hpack(":status", "200") + hpack("content-type", "text/html")
    )
    body = b"<html><title>crashme</title><body>hello</body></html>"
    tc = frame(FRAME_SETTINGS, 0, 0, b"")
    for sid in (1, 3):
        tc += frame(FRAME_HEADERS, FLAG_END_HEADERS, sid, resp)
        tc += frame(FRAME_DATA, FLAG_END_STREAM, sid, body)
    return ts, tc


def write_pcap(path):
    conns = [
        (41111, 8053, *doh_connection()),
        (41112, 8054, *plain_connection()),
    ]
    with open(path, "wb") as f:
        f.write(struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        n = 0
        for sport, dport, ts_data, tc_data in conns:
            cseq, sseq = 1000, 2000
            segs = [
                (CLIENT_IP, SERVER_IP, sport, dport, "c", SYN, b""),
                (SERVER_IP, CLIENT_IP, dport, sport, "s", SYNACK, b""),
                (CLIENT_IP, SERVER_IP, sport, dport, "c", ACK, b""),
                (CLIENT_IP, SERVER_IP, sport, dport, "c", PSHACK, ts_data),
                (SERVER_IP, CLIENT_IP, dport, sport, "s", PSHACK, tc_data),
                (CLIENT_IP, SERVER_IP, sport, dport, "c", FINACK, b""),
                (SERVER_IP, CLIENT_IP, dport, sport, "s", FINACK, b""),
            ]
            for sip, dip, sp, dp, side, flags, payload in segs:
                if side == "c":
                    seq, ack = cseq, sseq
                    cseq += max(len(payload), 1) if flags & SYN else len(payload)
                    eth = SERVER_MAC + CLIENT_MAC + b"\x08\x00"
                else:
                    seq, ack = sseq, cseq
                    sseq += max(len(payload), 1) if flags & SYN else len(payload)
                    eth = CLIENT_MAC + SERVER_MAC + b"\x08\x00"
                seg = tcp_seg(sp, dp, seq, ack, flags, payload, sip, dip)
                pkt = eth + ip4(sip, dip, len(seg)) + seg
                f.write(struct.pack("!IIII", n, 0, len(pkt), len(pkt)))
                f.write(pkt)
                n += 1


if __name__ == "__main__":
    write_pcap(sys.argv[1] if len(sys.argv) > 1 else "input.pcap")
