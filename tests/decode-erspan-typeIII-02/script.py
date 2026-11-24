#!/usr/bin/env python3
"""Build input.pcap from packet 1 of ../decode-erspan-typeIII-01/input.pcap:
ERSPAN Type III packets that must each raise one ERSPAN decoder event on the
GRE packet."""
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "decode-erspan-typeIII-01", "input.pcap")
DST = os.path.join(HERE, "input.pcap")

ERSPAN = 42  # 14 ethernet + 20 IPv4 + 8 GRE (sequence) in the source packet
HDR = 12  # ERSPAN Type III header
SUBHEADER = bytes([0x0C, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC])


def ipv4_fixup(pkt):
    struct.pack_into(">H", pkt, 16, len(pkt) - 14)
    struct.pack_into(">H", pkt, 24, 0)
    s = sum(struct.unpack(">10H", bytes(pkt[14:34])))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    struct.pack_into(">H", pkt, 24, ~s & 0xFFFF)
    return pkt


def set_o_flag(pkt):
    flags = struct.unpack_from(">H", pkt, ERSPAN + 10)[0]
    struct.pack_into(">H", pkt, ERSPAN + 10, flags | 0x0001)
    pkt[ERSPAN + HDR:ERSPAN + HDR] = SUBHEADER
    return pkt


data = open(SRC, "rb").read()
assert data[:4] == b"\xd4\xc3\xb2\xa1", "expected a classic little-endian pcap"
sec, usec, incl, _ = struct.unpack("<IIII", data[24:40])
base = bytearray(data[40:40 + incl])

# 1: frame type 2 (IP) instead of 0 (ethernet): unsupported_encapsulation
p1 = bytearray(base)
flags = struct.unpack_from(">H", p1, ERSPAN + 10)[0]
struct.pack_into(">H", p1, ERSPAN + 10, flags | (2 << 10))

# 2: version 1 instead of 2: unsupported_version
p2 = bytearray(base)
vv = struct.unpack_from(">H", p2, ERSPAN)[0]
struct.pack_into(">H", p2, ERSPAN, (1 << 12) | (vv & 0x0FFF))

# 3: header cut to 8 of its 12 bytes: header_too_small
p3 = ipv4_fixup(bytearray(base[:ERSPAN + 8]))

# 4: O flag set, sub-header cut to 4 of its 8 bytes: header_too_small
p4 = ipv4_fixup(set_o_flag(bytearray(base))[:ERSPAN + HDR + 4])

# 5: full header, mirrored frame of 10 bytes, too short for ethernet: header_too_small
p5 = ipv4_fixup(bytearray(base[:ERSPAN + HDR + 10]))

# 6: O flag and full sub-header, mirrored frame of 6 bytes: header_too_small
p6 = ipv4_fixup(set_o_flag(bytearray(base))[:ERSPAN + HDR + len(SUBHEADER) + 6])

out = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)]
for i, p in enumerate((p1, p2, p3, p4, p5, p6)):
    out.append(struct.pack("<IIII", sec + i, usec, len(p), len(p)))
    out.append(bytes(p))
open(DST, "wb").write(b"".join(out))
