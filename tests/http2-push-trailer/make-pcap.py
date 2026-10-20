"""Craft an HTTP/2 stream that carries a PUSH_PROMISE while its response body is in flight.

The promised fields arrive as a CONTINUATION on the parent stream, after the parent header
section completed. They must not be read as the parent's trailers. The response then closes with
a trailer block split over HEADERS plus CONTINUATION, which must be trailers.

HPACK literals without indexing only, so no dynamic table state is needed.

usage: python3 make-pcap.py [out.pcap]
"""
import struct
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else "input.pcap"

DATA, HEADERS, CONTINUATION = 0x0, 0x1, 0x9
SETTINGS, PUSH_PROMISE = 0x4, 0x5
END_STREAM, END_HEADERS, ACK = 0x1, 0x4, 0x1
SYN, SYNACK, ACKFLAG, PSHACK, FIN = 0x02, 0x12, 0x10, 0x18, 0x11
CPORT, SPORT = 12345, 80
CADDR, SADDR = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])
CMAC, SMAC = b"\x00\x11\x22\x33\x44\x55", b"\x00\x11\x22\x33\x44\x66"


def lit(name, value):
    return b"\x00" + bytes([len(name)]) + name + bytes([len(value)]) + value


def hdr(fields):
    return b"".join(lit(n, v) for n, v in fields)


def frame(ftype, flags, stream_id, payload=b""):
    return (struct.pack("!I", len(payload))[1:] + bytes([ftype, flags])
            + struct.pack("!I", stream_id & 0x7FFFFFFF) + payload)


nxt = {True: 1, False: 1}


def pkt(client, payload, flags):
    src, dst = (CADDR, SADDR) if client else (SADDR, CADDR)
    sport, dport = (CPORT, SPORT) if client else (SPORT, CPORT)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40 + len(payload), 1, 0x4000, 64, 6, 0, src, dst)
    tcp = struct.pack("!HHIIBBHHH", sport, dport, nxt[client], nxt[not client], 5 << 4, flags,
                      65535, 0, 0)
    nxt[client] += len(payload) + (1 if flags & (0x02 | 0x01) else 0)  # SYN or FIN bit
    mac_dst, mac_src = (SMAC, CMAC) if client else (CMAC, SMAC)
    return mac_dst + mac_src + b"\x08\x00" + ip + tcp + payload


packets = [pkt(True, b"", SYN), pkt(False, b"", SYNACK), pkt(True, b"", ACK)]

preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
req = frame(HEADERS, END_HEADERS, 1, hdr([
    (b":method", b"POST"), (b":path", b"/index.html"), (b":scheme", b"http"),
    (b":authority", b"push.example"),
])) + frame(DATA, END_STREAM, 1, b"q=1")
packets.append(pkt(True, preface + frame(SETTINGS, 0, 0) + req, PSHACK))
packets.append(pkt(False, frame(SETTINGS, ACK, 0), PSHACK))
packets.append(pkt(False, frame(HEADERS, END_HEADERS, 1, hdr([
    (b":status", b"200"), (b"content-type", b"text/html")])), PSHACK))
packets.append(pkt(False, frame(DATA, 0, 1, b"<html>body</html>"), PSHACK))

# push: opens on the parent stream without END_HEADERS, the block is finished by CONTINUATION
push = frame(PUSH_PROMISE, 0, 1, struct.pack("!I", 2) + hdr([(b":scheme", b"http"), (b":method", b"GET")]))
push += frame(CONTINUATION, END_HEADERS, 1, hdr([(b":path", b"/pushed.css"), (b"x-pushed", b"yes")]))
packets.append(pkt(False, push, PSHACK))

# real trailers, also split over two frames, closing the stream
tr = frame(HEADERS, 0, 1, hdr([(b"x-checksum", b"abc")]))
tr += frame(CONTINUATION, END_HEADERS | END_STREAM, 1, hdr([(b"x-status", b"ok")]))
packets.append(pkt(False, tr, PSHACK))
packets.append(pkt(True, b"", ACK))
packets.append(pkt(False, b"", FIN))
packets.append(pkt(True, b"", FIN))

with open(OUT, "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))  # DLT_EN10MB
    for i, p in enumerate(packets):
        f.write(struct.pack("<IIII", 1700000000 + i, 0, len(p), len(p)))
        f.write(p)
print(OUT, "packets:", len(packets))
