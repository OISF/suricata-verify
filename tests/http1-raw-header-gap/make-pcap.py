"""Craft a header block with a segment lost inside it, then closed by FIN.

Flow A: `GET /gap` plus the marker field and one 1352-byte field, then the next segments are
sent with that much sequence space missing (a real gap, STREAM_GAP, not a hole reassembly
papered over), then FIN. Flow B: complete transaction as control.

A gap does not stop htp from finishing the block once the stream closes, so completion-time
buffers must see it on both sides of the gate.

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

A = (58931, 80)
handshake(A)
add(True, 0x18, A, b"GET /gap HTTP/1.1\r\nHost: g.example\r\nX-GapA: a1\r\nUser-Agent: MarkerUA\r\nX-F0: " + b"b" * 1300 + b"\r\n")
add(True, 0x18, A, b"X-F99999: " + b"b" * 90 + b"\r\nX-F99998: " + b"b" * 90 + b"\r\n", skip=1352)
add(True, 0x01, A)

B = (58933, 80)
handshake(B)
add(True, 0x18, B, b"GET /control HTTP/1.1\r\nHost: c.example\r\nX-CtlB: b1\r\n\r\n")
add(False, 0x10, B)
add(False, 0x18, B, b"HTTP/1.1 200 OK\r\nServer: C\r\nContent-Length: 2\r\n\r\nhi")
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
