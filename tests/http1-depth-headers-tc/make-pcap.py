"""Craft a response whose header block is cut by stream reassembly depth.

Flow A: complete request `/depth-resp`; the answer is 200 with `X-RawTC: yes` followed by
~11 KB of response header fields and no blank line, then the server's FIN, so the to_client
direction reaches `stream.reassembly.depth` (2000, set in test.yaml) inside its block.
Flow B: complete transaction as control.

The point is the per-direction split: the to_server direction is inspected normally while the
depth-cut direction is not, and that is what main does too. The response rules must not match.

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
    if payload:
        # the peer acknowledges each segment: unacked bytes are held back from htp
        # (AdjustToAcked), so without this a depth cut would hide the block for pcap reasons
        cc, ss = SEQ[ports]
        if client:
            pkts.append((False, 0x10, ports[0], ports[1], ss, cc, b""))
        else:
            pkts.append((True, 0x10, ports[0], ports[1], cc, ss, b""))


def span(client, ports, payload, chunk=MSS):
    while payload:
        add(client, 0x18, ports, payload[:chunk])
        payload = payload[chunk:]


def handshake(ports):
    add(True, 0x02, ports)
    add(False, 0x12, ports)
    add(True, 0x10, ports)


FIELDS = b"".join(b"X-F%05d: %s\r\n" % (i, b"b" * 90) for i in range(100))

A = (58921, 80)
handshake(A)
add(True, 0x18, A, b"GET /depth-resp HTTP/1.1\r\nHost: d.example\r\nX-ReqA: a1\r\n\r\n")
add(False, 0x10, A)
span(False, A, b"HTTP/1.1 200 OK\r\nServer: S\r\nX-RespA: a2\r\n" + FIELDS)
add(False, 0x01, A)

B = (58923, 80)
handshake(B)
add(True, 0x18, B, b"GET /control HTTP/1.1\r\nHost: c.example\r\nX-ReqB: b1\r\n\r\n")
add(False, 0x10, B)
add(False, 0x18, B, b"HTTP/1.1 200 OK\r\nServer: C\r\nX-RespB: b2\r\nContent-Length: 2\r\n\r\nhi")
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
