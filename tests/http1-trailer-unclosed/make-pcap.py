"""Craft a chunked request whose trailer block is never terminated.

Flow A: `GET /trl` with `Transfer-Encoding: chunked` and `Trailer: X-TrailerField`, a last
chunk that starts the trailer section, three trailer fields and ~11 KB of filler, no blank
line, then FIN. Flow B: the same traffic with a properly terminated trailer block, so the
normal path is covered next to it.

The trailer block ends only through stream closure here, so the trailer buffers are filled by
the completion of the block through the CLOSED path rather than by a trailer state hook.

Checksums are not computed; Suricata needs -k none.
"""

import struct

MSS = 1400
pkts = []
SEQ = {}


def add(client, flags, ports, payload=b"", skip=0):
    cseq, sseq = SEQ.get(ports, (0, 0))
    seq = cseq if client else sseq
    ack = sseq if client else cseq
    pkts.append((client, flags, ports[0], ports[1], seq, ack, payload))
    extra = 1 if flags & (0x02 | 0x01) else 0
    if client:
        SEQ[ports] = (cseq + len(payload) + extra + skip, sseq)
    else:
        SEQ[ports] = (cseq, sseq + len(payload) + extra + skip)


def span(client, ports, payload, chunk=MSS):
    while payload:
        add(client, 0x18, ports, payload[:chunk])
        payload = payload[chunk:]


def handshake(ports):
    add(True, 0x02, ports)
    add(False, 0x12, ports)
    add(True, 0x10, ports)


FIELDS = b"".join(b"X-F%05d: %s\r\n" % (i, b"b" * 90) for i in range(100))

TRL_A = b"X-TrailerField: u1\r\nX-TF2: u2\r\n"
TRL_B = b"X-TrailerField: tv1\r\nX-TF2: tv2\r\n"
A = (58951, 80)
handshake(A)
add(True, 0x18, A, b"GET /trl HTTP/1.1\r\nHost: t.example\r\nX-Marker: yes\r\nTransfer-Encoding: chunked\r\nTrailer: X-TrailerField\r\n\r\n")
add(True, 0x18, A, b"5\r\nhello\r\n0\r\n")
span(True, A, TRL_A + FIELDS)
add(True, 0x01, A)

B = (58953, 80)
handshake(B)
add(True, 0x18, B, b"GET /trl HTTP/1.1\r\nHost: t.example\r\nX-Marker: yes\r\nTransfer-Encoding: chunked\r\nTrailer: X-TrailerField\r\n\r\n")
add(True, 0x18, B, b"5\r\nhello\r\n0\r\n" + TRL_B + b"\r\n")
add(False, 0x10, B)
add(False, 0x18, B, b"HTTP/1.1 200 OK\r\nServer: T\r\nContent-Length: 0\r\n\r\n")
add(True, 0x01, B)


def build(client, flags, sport, dport, seq, ack, payload):
    mac_src = b"\x00\x11\x22\x33\x44\x55" if client else b"\x00\x11\x22\x33\x44\x66"
    mac_dst = b"\x00\x11\x22\x33\x44\x66" if client else b"\x00\x11\x22\x33\x44\x55"
    ip_src = b"\xc0\xa8\x01\x0a" if client else b"\xc0\xa8\x01\x14"
    ip_dst = b"\xc0\xa8\x01\x14" if client else b"\xc0\xa8\x01\x0a"
    if not client:
        sport, dport = dport, sport
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 40 + len(payload), 1, 0x4000, 64, 6, 0, ip_src, ip_dst
    )
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0)
    return mac_dst + mac_src + b"\x08\x00" + ip + tcp + payload


with open("input.pcap", "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for i, p in enumerate(pkts):
        d = build(*p)
        f.write(struct.pack("<IIII", 1700000000 + i, 0, len(d), len(d)))
        f.write(d)
print("input.pcap packets:", len(pkts))
