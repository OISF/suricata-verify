#!/usr/bin/env python3
"""Build input.pcap from ../decode-erspan-typeIII-01/input.pcap.

Every packet gets the ERSPAN Type III O flag, with the 8 byte platform
specific sub-header it announces, and VLAN 23 in the ERSPAN header. The
sub-header bytes are not zero, so a decoder that does not skip it decodes
garbage instead of the mirrored frame.
"""
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "decode-erspan-typeIII-01", "input.pcap")
DST = os.path.join(HERE, "input.pcap")

ERSPAN = 42  # 14 ethernet + 20 IPv4 + 8 GRE (sequence) in the source packets
VLAN = 23
# platform id 3, then platform specific information
SUBHEADER = bytes([0x0C, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC])


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
out = [data[:24]]
off = 24
while off < len(data):
    sec, usec, incl, orig = struct.unpack("<IIII", data[off:off + 16])
    pkt = bytearray(data[off + 16:off + 16 + incl])
    off += 16 + incl
    vv = struct.unpack_from(">H", pkt, ERSPAN)[0]
    assert vv >> 12 == 2, "not ERSPAN Type III"
    struct.pack_into(">H", pkt, ERSPAN, (vv & 0xF000) | VLAN)
    flags = struct.unpack_from(">H", pkt, ERSPAN + 10)[0]
    struct.pack_into(">H", pkt, ERSPAN + 10, flags | 0x0001)
    pkt[ERSPAN + 12:ERSPAN + 12] = SUBHEADER
    pkt = ipv4_fixup(pkt)
    out.append(struct.pack("<IIII", sec, usec, len(pkt), len(pkt)))
    out.append(bytes(pkt))
open(DST, "wb").write(b"".join(out))
