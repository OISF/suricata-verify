"""Craft an HTTP/2 stream pair whose trailer blocks follow a message with no DATA frames.

RFC 9113 allows a trailer section behind a bodyless message, so classification has to key on
block sequence. HEADERS without END_STREAM, then a trailer HEADERS with END_STREAM, in both
directions. HPACK literals without indexing only, no dynamic table needed.

usage: python3 make-pcap.py [out.pcap]
"""
import struct
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else "input.pcap"

HEADERS, SETTINGS = 0x1, 0x4
END_STREAM, END_HEADERS = 0x1, 0x4
SYN, SYNACK, ACK, PSHACK, FIN = 0x02, 0x12, 0x10, 0x18, 0x11
CPORT, SPORT = 12345, 80
CADDR, SADDR = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])
CMAC, SMAC = b"\x00\x11\x22\x33\x44\x55", b"\x00\x11\x22\x33\x44\x66"


def lit(name, value):
    """literal header field without indexing, new name"""
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
request = frame(HEADERS, END_HEADERS, 1, hdr([
    (b":method", b"POST"), (b":path", b"/svc/Call"), (b":scheme", b"http"),
    (b":authority", b"suricata.io"), (b"te", b"trailers"),
]))
packets.append(pkt(True, preface + frame(SETTINGS, 0, 0) + request, PSHACK))
packets.append(pkt(False, frame(SETTINGS, 1, 0), PSHACK))
packets.append(pkt(False, frame(HEADERS, END_HEADERS, 1, hdr([
    (b":status", b"200"), (b"content-type", b"text/plain")])), PSHACK))

# no DATA frames in either direction: the trailer blocks close the streams
packets.append(pkt(True, frame(HEADERS, END_HEADERS | END_STREAM, 1, hdr([
    (b"x-checksum", b"deadbeef"), (b"server-timing", b"done")])), PSHACK))
packets.append(pkt(False, frame(HEADERS, END_HEADERS | END_STREAM, 1, hdr([
    (b"grpc-status", b"0"), (b"user-agent", b"TRAILER-UA")])), PSHACK))
packets.append(pkt(True, b"", ACK))
packets.append(pkt(False, b"", FIN))
packets.append(pkt(True, b"", FIN))

with open(OUT, "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))  # DLT_EN10MB
    for i, p in enumerate(packets):
        f.write(struct.pack("<IIII", 1700000000 + i, 0, len(p), len(p)))
        f.write(p)
print(OUT, "packets:", len(packets))
