"""Craft HTTP/2 trailer blocks split across HEADERS and CONTINUATION in both directions.

RFC 9113 lets a HEADERS frame carry END_STREAM while END_HEADERS stays clear, the block then
being completed by CONTINUATION frames. Each direction of each stream does exactly that here:
one field rides the trailer HEADERS, the rest arrives in a CONTINUATION in the next segment, so
an implementation that reads END_STREAM as "header section done" builds the trailer buffers too
early and never sees the continuation's fields.

HPACK "literal header field without indexing" with new names only, so no dynamic table state is
needed and each block decodes without prior context.

usage: python3 make-pcap.py [out.pcap]
"""
import struct
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else "input.pcap"

DATA, HEADERS, SETTINGS, CONTINUATION = 0x0, 0x1, 0x4, 0x9
END_STREAM, END_HEADERS = 0x1, 0x4
SYN, SYNACK, ACK, PSHACK, FIN = 0x02, 0x12, 0x10, 0x18, 0x11
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
    nxt[client] += len(payload) + (1 if flags & (0x02 | 0x01) else 0)
    mac_dst, mac_src = (SMAC, CMAC) if client else (CMAC, SMAC)
    return mac_dst + mac_src + b"\x08\x00" + ip + tcp + payload


packets = [pkt(True, b"", SYN), pkt(False, b"", SYNACK), pkt(True, b"", ACK)]

preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
packets.append(pkt(True, preface + frame(SETTINGS, 0, 0), PSHACK))
packets.append(pkt(False, frame(SETTINGS, 1, 0), PSHACK))

# stream 1: client trailer block split, server finishes the body with END_STREAM
packets.append(pkt(True, frame(HEADERS, END_HEADERS, 1, hdr([
    (b":method", b"POST"), (b":path", b"/svc/Call"), (b":scheme", b"http"),
    (b":authority", b"suricata.io"), (b"content-type", b"application/grpc"),
    (b"user-agent", b"Mozilla"), (b"te", b"trailers"),
])), PSHACK))
packets.append(pkt(True, frame(DATA, 0, 1, b"\x00\x00\x00\x00\x05hello"), PSHACK))
packets.append(pkt(False, frame(HEADERS, END_HEADERS, 1, hdr([
    (b":status", b"200"), (b"content-type", b"application/grpc")])), PSHACK))
packets.append(pkt(False, frame(DATA, END_STREAM, 1, b"\x00\x00\x00\x00\x02OK"), PSHACK))
# part 1 carries grpc-message, the CONTINUATION carries the fields under test
packets.append(pkt(True, frame(HEADERS, END_STREAM, 1,
                               hdr([(b"grpc-message", b"trailval")])), PSHACK))
packets.append(pkt(True, frame(CONTINUATION, END_HEADERS, 1, hdr([
    (b"user-agent", b"TRAILER-UA"), (b"server-timing", b"done")])), PSHACK))

# stream 3: server trailer block split the same way; client ends with a body-less EOS
packets.append(pkt(True, frame(HEADERS, END_HEADERS | END_STREAM, 3, hdr([
    (b":method", b"GET"), (b":path", b"/svc/Peek"), (b":scheme", b"http"),
    (b":authority", b"suricata.io"), (b"te", b"trailers"),
])), PSHACK))
packets.append(pkt(False, frame(HEADERS, END_HEADERS, 3, hdr([
    (b":status", b"200"), (b"content-type", b"application/grpc")])), PSHACK))
packets.append(pkt(False, frame(HEADERS, END_STREAM, 3,
                               hdr([(b"x-trailer-c", b"CCCC")])), PSHACK))
packets.append(pkt(False, frame(CONTINUATION, END_HEADERS, 3, hdr([
    (b"x-trailer-d", b"SPLITTRAILERD")])), PSHACK))

packets.append(pkt(True, b"", FIN))
packets.append(pkt(False, b"", FIN))

with open(OUT, "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))  # DLT_EN10MB
    for i, p in enumerate(packets):
        f.write(struct.pack("<IIII", 1700000000 + i, 0, len(p), len(p)))
        f.write(p)
print(OUT, "packets:", len(packets))
