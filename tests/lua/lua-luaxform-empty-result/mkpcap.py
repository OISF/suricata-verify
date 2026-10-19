#!/usr/bin/env python3
"""craft N HTTP/1.1 GET + 200 response sessions, one body each (regular pcap)"""
import struct, sys

def csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ip(src, dst):
    return bytes(map(int, src.split("."))), bytes(map(int, dst.split(".")))

def pkt(src, dst, sp, dp, seq, ack, flags, payload=b""):
    s, d = ip(src, dst)
    tcp = struct.pack("!HHIIBBHHH", sp, dp, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
    pseudo = s + d + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", csum(pseudo + tcp)) + tcp[18:]
    iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, s, d)
    iph = iph[:10] + struct.pack("!H", csum(iph)) + iph[12:]
    eth = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x08\x00"
    return eth + iph + tcp

def session(cp, spt, body):
    c, sv = "10.0.0.1", "10.0.0.2"
    cseq, sseq = 1000, 5000
    SYN, ACK, PSH, FIN = 0x02, 0x10, 0x08, 0x01
    req = b"GET /body HTTP/1.1\r\nHost: example.test\r\nUser-Agent: t\r\n\r\n"
    resp = (b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
            b"Content-Length: %d\r\n\r\n" % len(body)) + body
    frames = []
    frames.append(pkt(c, sv, cp, spt, cseq, 0, SYN))
    frames.append(pkt(sv, c, spt, cp, sseq, cseq + 1, SYN | ACK))
    frames.append(pkt(c, sv, cp, spt, cseq + 1, sseq + 1, ACK))
    frames.append(pkt(c, sv, cp, spt, cseq + 1, sseq + 1, PSH | ACK, req))
    cseq += 1 + len(req)
    sseq += 1
    frames.append(pkt(sv, c, spt, cp, sseq, cseq, ACK))
    frames.append(pkt(sv, c, spt, cp, sseq, cseq, PSH | ACK, resp))
    sseq += 1 + len(resp)
    frames.append(pkt(c, sv, cp, spt, cseq, sseq, ACK))
    frames.append(pkt(c, sv, cp, spt, cseq, sseq, FIN | ACK))
    frames.append(pkt(sv, c, spt, cp, sseq + 1, cseq + 1, FIN | ACK))
    frames.append(pkt(c, sv, cp, spt, cp + 1, sseq + 1, ACK))
    return frames

def main(out, bodies):
    frames = []
    t = 1700000000
    for i, body in enumerate(bodies):
        for fr in session(40000 + i, 80, body):
            frames.append((t, fr))
            t += 1
    with open(out, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for t, fr in frames:
            f.write(struct.pack("<IIII", t, 0, len(fr), len(fr)))
            f.write(fr)

if __name__ == "__main__":
    # usage: mkpcap.py <out> <body1-b64> <body2-b64> ...
    b64 = __import__("base64")
    main(sys.argv[1], [b64.b64decode(b) for b in sys.argv[2:]])
