#!/usr/bin/env python3
"""Generate the HTTP/1 body-limit pcap.

One flow: POST /upload with a 5 MiB body ('D' pad, 'ZZZZ' tail),
segmented at 1400 B. The test config sets request-body-limit: 0 and
stream.reassembly.depth: 0 so htp stores the whole body; the alert rule
matches the tail marker so the alert is built when the body is complete.

Without the logger cap the record would reach ~11.6 MiB (printable +
base64 of 5 MiB) and hit MAX_LIMIT. With the 100-KiB cap the logged body
is 102400 B and http_request_body_truncated is set.

stdlib only, fixed timestamps: byte-for-byte reproducible.
"""

import struct

OUT = "http1.pcap"

E1 = bytes.fromhex("024200000001")
E2 = bytes.fromhex("024200000002")

CIP, SIP = "192.0.2.10", "192.0.2.99"
SPORT = 80
MSS = 1400

BODY_LEN = 5 * 1024 * 1024
BODY = b"D" * (BODY_LEN - 4) + b"ZZZZ"
RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"

REQ = b"POST /upload HTTP/1.1\r\nHost: 192.0.2.99\r\n" \
    + b"Content-Length: %d\r\n\r\n" % BODY_LEN + BODY


def ip_tcp(src, dst, sport, dport, payload, seq, ack, flags, iid):
    assert 40 + len(payload) <= 0xFFFF
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


def main():
    f = []

    def seg(et, es, src, dst, sp, dp, pl, sq, ak, fl, ts, iid):
        f.append((ts, frame(et, es, ip_tcp(src, dst, sp, dp, pl, sq, ak, fl, iid))))

    cport, cseq, sseq = 43210, 1000, 5000
    cs, ss = cseq + 1, sseq + 1
    seg(E2, E1, CIP, SIP, cport, SPORT, b"", cseq, 0, SYN, 0, 1)
    seg(E1, E2, SIP, CIP, SPORT, cport, b"", sseq, cseq + 1, SYNACK, 10000, 2)
    seg(E2, E1, CIP, SIP, cport, SPORT, b"", cs, ss, ACK, 20000, 3)
    ts, iid, seq = 30000, 4, cs
    for off in range(0, len(REQ), MSS):
        chunk = REQ[off:off + MSS]
        seg(E2, E1, CIP, SIP, cport, SPORT, chunk, seq, ss, ACK, ts, iid)
        seq += len(chunk)
        ts += 20
        iid += 1
    seg(E1, E2, SIP, CIP, SPORT, cport, RESPONSE, ss, seq, ACK, ts + 10000, iid + 1)
    nseq = ss + len(RESPONSE)
    seg(E2, E1, CIP, SIP, cport, SPORT, b"", seq, nseq, ACK, ts + 20000, iid + 2)
    seg(E1, E2, SIP, CIP, SPORT, cport, b"", nseq, seq, FINACK, ts + 30000, iid + 3)
    seg(E2, E1, CIP, SIP, cport, SPORT, b"", seq + 1, nseq + 1, ACK, ts + 40000, iid + 4)
    seg(E2, E1, CIP, SIP, cport, SPORT, b"", seq + 2, nseq + 2, FINACK, ts + 50000, iid + 5)
    seg(E1, E2, SIP, CIP, SPORT, cport, b"", nseq + 2, seq + 3, ACK, ts + 60000, iid + 6)

    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 0, 0, 0, 0xFFFF, 1)
    for ts, fr in f:
        out += struct.pack("<IIII", ts // 10 ** 6, ts % 10 ** 6, len(fr), len(fr)) + fr
    with open(OUT, "wb") as fh:
        fh.write(out)


if __name__ == "__main__":
    main()
