#!/usr/bin/env python3
"""Build input.pcap from packet 1 of ../decode-erspan-typeII-01/input.pcap:
ERSPAN Type II packets that must each raise one ERSPAN decoder event on the
GRE packet."""
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "decode-erspan-typeII-01", "input.pcap")
DST = os.path.join(HERE, "input.pcap")

ERSPAN = 42  # 14 ethernet + 20 IPv4 + 8 GRE (sequence) in the source packet
HDR = 8  # ERSPAN Type II header


def ipv4_fixup(pkt):
    struct.pack_into(">H", pkt, 16, len(pkt) - 14)
    struct.pack_into(">H", pkt, 24, 0)
    s = sum(struct.unpack(">10H", bytes(pkt[14:34])))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    struct.pack_into(">H", pkt, 24, ~s & 0xFFFF)
    return pkt


data = open(SRC, "rb").read()
assert data[:4] == b"\xd4\xc3\xb2\xa1", "expected a classic little-endian pcap"
sec, usec, incl, _ = struct.unpack("<IIII", data[24:40])
base = bytearray(data[40:40 + incl])

# 1: version 2 instead of 1: unsupported_version
p1 = bytearray(base)
vv = struct.unpack_from(">H", p1, ERSPAN)[0]
struct.pack_into(">H", p1, ERSPAN, (2 << 12) | (vv & 0x0FFF))

# 2: header cut to 4 of its 8 bytes: header_too_small
p2 = ipv4_fixup(bytearray(base[:ERSPAN + 4]))

# 3: full header, mirrored frame of 10 bytes, too short for ethernet: header_too_small
p3 = ipv4_fixup(bytearray(base[:ERSPAN + HDR + 10]))

out = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)]
for i, p in enumerate((p1, p2, p3)):
    out.append(struct.pack("<IIII", sec + i, usec, len(p), len(p)))
    out.append(bytes(p))
open(DST, "wb").write(b"".join(out))
