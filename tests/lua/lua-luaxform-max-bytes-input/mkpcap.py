#!/usr/bin/env python3
"""craft one HTTP/1.1 GET + 200 response with a body of N bytes (regular pcap)"""
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

def main(out, body_len):
    c, sv, cp, spt = "10.0.0.1", "10.0.0.2", 40000, 80
    cseq, sseq = 1000, 5000
    SYN, ACK, PSH, FIN = 0x02, 0x10, 0x08, 0x01
    req = b"GET /big HTTP/1.1\r\nHost: example.test\r\nUser-Agent: t\r\n\r\n"
    body = (b"0123456789abcdef" * (body_len // 16 + 1))[:body_len]
    resp = b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\n\r\n" % body_len + body
    frames = []
    frames.append(pkt(c, sv, cp, spt, cseq, 0, SYN))
    frames.append(pkt(sv, c, spt, cp, sseq, cseq + 1, SYN | ACK))
    frames.append(pkt(c, sv, cp, spt, cseq + 1, sseq + 1, ACK))
    frames.append(pkt(c, sv, cp, spt, cseq + 1, sseq + 1, PSH | ACK, req))
    cseq += 1 + len(req)
    sseq += 1
    frames.append(pkt(sv, c, spt, cp, sseq, cseq, ACK))
    for off in range(0, len(resp), 1400):
        seg = resp[off:off + 1400]
        frames.append(pkt(sv, c, spt, cp, sseq, cseq, PSH | ACK, seg))
        sseq += len(seg)
        frames.append(pkt(c, sv, cp, spt, cseq, sseq, ACK))
    frames.append(pkt(c, sv, cp, spt, cseq, sseq, FIN | ACK))
    frames.append(pkt(sv, c, spt, cp, sseq, cseq + 1, FIN | ACK))
    frames.append(pkt(c, sv, cp, spt, cseq + 1, sseq + 1, ACK))
    with open(out, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        t = 1700000000
        for i, fr in enumerate(frames):
            f.write(struct.pack("<IIII", t, i * 1000, len(fr), len(fr)))
            f.write(fr)

if __name__ == "__main__":
    main(sys.argv[1], int(sys.argv[2]))
