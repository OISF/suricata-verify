#!/usr/bin/env python3
"""Generate the HTTP/2 header-limit pcap.

Three txs on one connection (the last references the
entry inserted while decoding /b):

  A: 25 distinct 2000-B literal headers  -> decoded ~51 KiB
     (below the 64-KiB parser list cap, above the 32-KiB logger budget)
  B: one 2000-B dynamic entry + 40 indexed refs -> decoded ~81 KiB
     (parser list cap hit, sentinel stops decoding)
  C: one 20-KiB header value -> parser per-field cap (16 KiB) hit

Expected records: A and B set request_headers_truncated, C sets it too
and never contains the oversized header. No MAX_LIMIT drop.

stdlib only, deterministic.
"""

import struct

OUT = "http2.pcap"

E1 = bytes.fromhex("024200000001")
E2 = bytes.fromhex("024200000002")

CIP, SIP = "192.0.2.10", "192.0.2.99"
CPORT, SPORT = 34567, 443

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
RESP = b"\x88"  # 0x80|8: :status 200 (static 8)


def varlen(mx, n):
    if n < mx:
        return bytes([n])
    rem = n - mx
    out = [mx]
    while rem >= 128:
        out.append((rem & 0x7F) | 0x80)
        rem >>= 7
    out.append(rem)
    return bytes(out)


def idxname(idx, value):
    if idx < 15:
        head = bytes([idx])
    else:
        head = bytes([0x0F, idx - 15])
    return head + varlen(127, len(value)) + value


def lit(name, value):
    """Literal without indexing, literal name (0x00 form)."""
    return b"\x00" + varlen(127, len(name)) + name + varlen(127, len(value)) + value


def push(name, value):
    return b"\x40" + varlen(127, len(name)) + name + varlen(127, len(value)) + value


def h2_frame(ftype, flags, sid, payload):
    return struct.pack(">I", len(payload))[1:] \
        + bytes([ftype, flags]) + (sid & 0x7FFFFFFF).to_bytes(4, "big") + payload


def headers_a():
    b = b"\x82" + idxname(4, b"/a")
    for i in range(1, 26):
        b += lit(b"x-a%02d" % i, (b"A%02d" % i) + b"a" * 1997)
    return b


def headers_b():
    b = b"\x82" + idxname(4, b"/b")
    b += push(b"x-amplify", b"B" * 1995 + b"ZMARK")
    b += b"\xBE" * 40
    return b

def headers_c():
    # references the dynamic entry inserted while decoding /b
    return b"\x82" + idxname(4, b"/c") + b"\xBE"


def headers_d():
    # 20000 HPACK dynamic table size updates: each is one logged entry
    return b"\x82" + idxname(4, b"/flood") + b"\x20" * 4000


def ip_tcp(src, dst, sport, dport, payload, seq, ack, flags, iid):
    tlen = 40 + len(payload)
    iph = bytes([0x45, 0x00]) + tlen.to_bytes(2, "big") \
        + iid.to_bytes(2, "big") + (0x4000).to_bytes(2, "big") \
        + bytes([64, 6, 0, 0]) \
        + bytes(map(int, src.split("."))) + bytes(map(int, dst.split(".")))
    s = sum(struct.unpack(">%dH" % (len(iph) // 2), iph))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    iph = iph[:10] + ((~s) & 0xFFFF).to_bytes(2, "big") + iph[12:]
    th = sport.to_bytes(2, "big") + dport.to_bytes(2, "big") \
        + seq.to_bytes(4, "big") + ack.to_bytes(4, "big") \
        + bytes([0x50, flags]) + (0xFFFF).to_bytes(2, "big")
    pseudo = iph[12:16] + iph[16:20] + bytes([0, 6]) \
        + (len(th) + 4 + len(payload)).to_bytes(2, "big")
    data = pseudo + th + (0).to_bytes(2, "big") + payload
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(">%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    csum = (~s) & 0xFFFF or 0xFFFF
    return iph + th + csum.to_bytes(2, "big") + (0).to_bytes(2, "big") + payload


def frame(et, es, payload):
    return et + es + (0x0800).to_bytes(2, "big") + payload


SYN, SYNACK, ACK, FINACK = 0x02, 0x12, 0x10, 0x11
CSEQ, SSEQ = 1000, 5000
MSS = 1400


def segs(data):
    return [data[i:i + MSS] for i in range(0, len(data), MSS)]


def ip_tcp(src, dst, sport, dport, payload, seq, ack, flags, iid):
    tlen = 40 + len(payload)
    iph = bytes([0x45, 0x00]) + tlen.to_bytes(2, "big") \
        + iid.to_bytes(2, "big") + (0x4000).to_bytes(2, "big") \
        + bytes([64, 6, 0, 0]) \
        + bytes(map(int, src.split("."))) + bytes(map(int, dst.split(".")))
    s = sum(struct.unpack(">%dH" % (len(iph) // 2), iph))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    iph = iph[:10] + ((~s) & 0xFFFF).to_bytes(2, "big") + iph[12:]
    th = sport.to_bytes(2, "big") + dport.to_bytes(2, "big") \
        + seq.to_bytes(4, "big") + ack.to_bytes(4, "big") \
        + bytes([0x50, flags]) + (0xFFFF).to_bytes(2, "big")
    pseudo = iph[12:16] + iph[16:20] + bytes([0, 6]) \
        + (len(th) + 4 + len(payload)).to_bytes(2, "big")
    data = pseudo + th + (0).to_bytes(2, "big") + payload
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(">%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    csum = (~s) & 0xFFFF or 0xFFFF
    return iph + th + csum.to_bytes(2, "big") + (0).to_bytes(2, "big") + payload


def frame(et, es, payload):
    return et + es + (0x0800).to_bytes(2, "big") + payload


SYN, SYNACK, ACK, FINACK = 0x02, 0x12, 0x10, 0x11
CSEQ, SSEQ = 1000, 5000
MSS = 1400


def segs(data):
    return [data[i:i + MSS] for i in range(0, len(data), MSS)]


def header_frames(block, sid, chunk=8000):
    """HEADERS + CONTINUATION frames, END_HEADERS on the last one."""
    parts = [block[i:i + chunk] for i in range(0, len(block), chunk)]
    out = h2_frame(1, 0x0, sid, parts[0])
    for i, p in enumerate(parts[1:]):
        flags = 0x4 if i == len(parts) - 2 else 0x0
        out += h2_frame(9, flags, sid, p)
    return out


def main():
    client = PREFACE + h2_frame(4, 0, 0, b"")
    client += h2_frame(1, 0x4, 1, headers_a()) + h2_frame(0, 0x1, 1, b"")
    client += h2_frame(1, 0x4, 3, headers_b()) + h2_frame(0, 0x1, 3, b"")
    client += h2_frame(1, 0x4, 5, headers_c()) + h2_frame(0, 0x1, 5, b"")
    client += h2_frame(1, 0x4, 7, headers_d()) + h2_frame(0, 0x1, 7, b"")
    server = b""
    for sid in (1, 3, 5, 7):
        server += h2_frame(1, 0x4, sid, RESP) + h2_frame(0, 0x1, sid, b"")

    cs, ss = CSEQ + 1, SSEQ + 1
    f = []
    ts = [0]

    def seg(et, es, src, dst, sp, dp, pl, sq, ak, fl, ts, iid):
        f.append((ts, frame(et, es, ip_tcp(src, dst, sp, dp, pl, sq, ak, fl, iid))))

    def nts():
        ts[0] += 20000
        return ts[0]

    seg(E2, E1, CIP, SIP, CPORT, SPORT, b"", CSEQ, 0, SYN, nts(), 1)
    seg(E1, E2, SIP, CIP, SPORT, CPORT, b"", SSEQ, CSEQ + 1, SYNACK, nts(), 2)
    seg(E2, E1, CIP, SIP, CPORT, SPORT, b"", cs, ss, ACK, nts(), 3)
    sq = cs
    for i, p in enumerate(segs(client)):
        seg(E2, E1, CIP, SIP, CPORT, SPORT, p, sq, ss, ACK, nts(), 4 + i)
        sq += len(p)
    ca = sq
    sq2 = ss
    for i, p in enumerate(segs(server)):
        seg(E1, E2, SIP, CIP, SPORT, CPORT, p, sq2, ca, ACK, nts(), 100 + i)
        sq2 += len(p)
    sa = sq2
    seg(E2, E1, CIP, SIP, CPORT, SPORT, b"", ca, sa, ACK, nts(), 200)
    seg(E1, E2, SIP, CIP, SPORT, CPORT, b"", sa, ca, FINACK, nts(), 201)
    seg(E2, E1, CIP, SIP, CPORT, SPORT, b"", ca, sa + 1, ACK, nts(), 202)
    seg(E2, E1, CIP, SIP, CPORT, SPORT, b"", ca, sa + 1, FINACK, nts(), 203)
    seg(E1, E2, SIP, CIP, SPORT, CPORT, b"", sa + 1, ca + 1, ACK, nts(), 204)

    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 0, 0, 0, 0xFFFF, 1)
    for t, fr in f:
        out += struct.pack("<IIII", t // 10 ** 6, t % 10 ** 6, len(fr), len(fr)) + fr
    with open(OUT, "wb") as fh:
        fh.write(out)
    print("wrote %s: %d bytes, %d frames" % (OUT, len(out), len(f)))


if __name__ == "__main__":
    main()
