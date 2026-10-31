"""Craft a chunked response whose body is stored and whose trailer block spans segments.

One transaction: request; then a response with headers, the body chunk and the terminating `0`
chunk in one segment; then the trailer fields, one per segment, each acknowledged by the peer
(unacked bytes are held back from the parser).

A `filestore` rule on the body marks the transaction in that direction. That is not the same
fact as the reassembly depth limit having been reached, so it must not make a half-received
trailer block look complete: the block stays closed to detection until its blank line arrives.

Checksums are not computed; Suricata needs -k none.
"""

import struct

MSS = 1400


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


A = (58971, 80)
handshake(A)
add(True, 0x18, A, b"GET /f HTTP/1.1\r\nHost: good.example\r\n\r\n")
add(False, 0x18, A, b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
                    b"Content-Type: application/octet-stream\r\n\r\n10\r\nBODYBODYBODYBODY\r\n0\r\n")
for t in (b"X-Tr: abc\r\n", b"X-Mid: 2\r\n", b"X-Other: 1\r\n\r\n"):
    add(False, 0x18, A, t)
add(True, 0x01, A)
add(False, 0x01, A)


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
