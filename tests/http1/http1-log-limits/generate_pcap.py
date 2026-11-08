#!/usr/bin/env python3
"""Generate the HTTP/1 log-limit pcap.

Four request flows, one tx each:

  A: /<16991 x 'A'>            request line in ONE 17 KB segment
  B: same bytes as A           split into 200-B segments
  C: /xff + 66 x 400-B XFF     concatenated xff = 26530 B
  D: /headers + 34 unique
     1-KiB X-Pad headers       request headers = 34340 B

Defaults: string-log-limit 16 KiB, header-log-limit 32 KiB per
direction. A/B must log the same truncated url (segmentation must not
change the logged value), C must truncate the concatenated xff, D must
hit the header budget and set request_headers_truncated.

stdlib only, computed checksums, fixed timestamps: byte-for-byte
reproducible.
"""

import struct

OUT = "http1.pcap"

E1 = bytes.fromhex("024200000001")
E2 = bytes.fromhex("024200000002")

CIP, SIP = "192.0.2.10", "192.0.2.99"
SPORT = 80

RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"

URL_A = b"/" + b"A" * 16991
REQ_A = b"GET " + URL_A + b" HTTP/1.1\r\nHost: 192.0.2.99\r\n\r\n"

XFF_VALUES = [b"f%04d-" % i + b"X" * 394 for i in range(1, 67)]
REQ_C = b"GET /xff HTTP/1.1\r\nHost: 192.0.2.99\r\n"
for _v in XFF_VALUES:
    REQ_C += b"X-Forwarded-For: " + _v + b"\r\n"
REQ_C += b"\r\n"

REQ_D = b"GET /headers HTTP/1.1\r\nHost: 192.0.2.99\r\n"
for i in range(1, 35):
    REQ_D += b"X-Pad-%02d: " % i + b"P" * 1000 + b"\r\n"
REQ_D += b"\r\n"

assert len(REQ_A) < 18000


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


def flow(f, cport, cseq, sseq, req, t0, iid0, mss):
    def seg(et, es, src, dst, sp, dp, pl, sq, ak, fl, ts, iid):
        f.append((ts, frame(et, es, ip_tcp(src, dst, sp, dp, pl, sq, ak, fl, iid))))

    cs, ss = cseq + 1, sseq + 1
    seg(E2, E1, CIP, SIP, cport, SPORT, b"", cseq, 0, SYN, t0, iid0)
    seg(E1, E2, SIP, CIP, SPORT, cport, b"", sseq, cseq + 1, SYNACK, t0 + 10000, iid0 + 1)
    seg(E2, E1, CIP, SIP, cport, SPORT, b"", cs, ss, ACK, t0 + 20000, iid0 + 2)
    ts, iid, seq = t0 + 30000, iid0 + 3, cs
    for off in range(0, len(req), mss):
        chunk = req[off:off + mss]
        seg(E2, E1, CIP, SIP, cport, SPORT, chunk, seq, ss, ACK, ts, iid)
        seq += len(chunk)
        ts += 20000
        iid += 1
    seg(E1, E2, SIP, CIP, SPORT, cport, RESPONSE, ss, seq, ACK, ts + 10000, iid + 1)
    nseq = ss + len(RESPONSE)
    seg(E2, E1, CIP, SIP, cport, SPORT, b"", seq, nseq, ACK, ts + 20000, iid + 2)
    seg(E1, E2, SIP, CIP, SPORT, cport, b"", nseq, seq, FINACK, ts + 30000, iid + 3)
    seg(E2, E1, CIP, SIP, cport, SPORT, b"", seq + 1, nseq + 1, ACK, ts + 40000, iid + 4)
    seg(E2, E1, CIP, SIP, cport, SPORT, b"", seq + 2, nseq + 2, FINACK, ts + 50000, iid + 5)
    seg(E1, E2, SIP, CIP, SPORT, cport, b"", nseq + 2, seq + 3, ACK, ts + 60000, iid + 6)
    return iid + 7, ts + 60000


def main():
    f = []
    iid, t = flow(f, 43210, 1000, 5000, REQ_A, 0, 1, 60000)
    iid, t = flow(f, 43211, 2000, 6000, REQ_A, t + 100000, iid, 200)
    iid, t = flow(f, 43212, 3000, 7000, REQ_C, t + 100000, iid, 1400)
    iid, t = flow(f, 43213, 4000, 8000, REQ_D, t + 100000, iid, 1400)

    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 0, 0, 0, 0xFFFF, 1)
    for ts, fr in f:
        out += struct.pack("<IIII", ts // 10 ** 6, ts % 10 ** 6, len(fr), len(fr)) + fr
    with open(OUT, "wb") as fh:
        fh.write(out)


if __name__ == "__main__":
    main()
