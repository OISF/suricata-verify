"""HTTP/2 request whose trailer block references one large HPACK entry many times.

The trailer block holds a literal-with-indexing ``x-amp: <4000 x 'A'>`` (dynamic
index 62, entry size 32 + 5 + 4000 fits the default 4096 table) followed by 12000
copies of the one-byte reference 0xbe, i.e. 12001 field lines in a 16 KB frame.
One wire byte buys one more field line, so this is the amplification case the
logging repeat bound exists for.

usage: python3 make-pcap.py [out.pcap]
"""
import struct
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else "input.pcap"
VLEN = 4000
NREFS = 12000

DATA, HEADERS, SETTINGS = 0x0, 0x1, 0x4
END_STREAM, END_HEADERS = 0x1, 0x4
SYN, SYNACK, ACK, PSHACK, FIN = 0x02, 0x12, 0x10, 0x18, 0x11
CPORT, SPORT = 12345, 80
CADDR, SADDR = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])
CMAC, SMAC = b"\x00\x11\x22\x33\x44\x55", b"\x00\x11\x22\x33\x44\x66"


def hint(value, prefix_bits, first=0):
    """HPACK integer with an N-bit prefix; `first` carries the high flag bits"""
    limit = (1 << prefix_bits) - 1
    if value < limit:
        return bytes([first | value])
    out = [first | limit]
    value -= limit
    while value >= 128:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def lit(name, value):
    """literal header field without indexing, new name"""
    return b"\x00" + hint(len(name), 7) + name + hint(len(value), 7) + value


def lit_idx(name, value):
    """literal header field with incremental indexing, new name"""
    return b"\x40" + hint(len(name), 7) + name + hint(len(value), 7) + value


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
request = frame(HEADERS, END_HEADERS, 1,
                lit(b":method", b"POST") + lit(b":path", b"/amp")
                + lit(b":scheme", b"http") + lit(b":authority", b"suricata.io"))
packets.append(pkt(True, preface + frame(SETTINGS, 0, 0) + request, PSHACK))

packets.append(pkt(False, frame(SETTINGS, 1, 0), PSHACK))
packets.append(pkt(False, frame(HEADERS, END_HEADERS, 1, lit(b":status", b"200")), PSHACK))
packets.append(pkt(False, frame(DATA, END_STREAM, 1, b"hello"), PSHACK))

trailers = lit_idx(b"x-amp", b"A" * VLEN) + b"\xbe" * NREFS
assert len(trailers) <= 16384, len(trailers)
packets.append(pkt(True, frame(HEADERS, END_HEADERS | END_STREAM, 1, trailers), PSHACK))

packets.append(pkt(True, b"", FIN))
packets.append(pkt(False, b"", FIN))

with open(OUT, "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))  # DLT_EN10MB
    for i, p in enumerate(packets):
        f.write(struct.pack("<IIII", 1700000000 + i, 0, len(p), len(p)))
        f.write(p)
print(OUT, "packets:", len(packets), "trailer block bytes:", len(trailers))
