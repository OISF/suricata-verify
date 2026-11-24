#!/usr/bin/env python3
"""Build input.pcap: an ERSPAN Type I packet (GRE without sequence number,
protocol 0x88BE) whose mirrored frame of 10 bytes is too short for an
ethernet header."""
import os
import struct

DST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "input.pcap")


def csum(data):
    s = sum(struct.unpack(">%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def ipv4(src, dst, proto, payload):
    hdr = bytearray(struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0, 64, proto, 0,
                                bytes(map(int, src.split("."))), bytes(map(int, dst.split(".")))))
    struct.pack_into(">H", hdr, 10, csum(bytes(hdr)))
    return bytes(hdr) + payload


gre = struct.pack(">HH", 0x0000, 0x88BE)
frame = bytes(range(10))
pkt = b"\x00\x00\x5e\x00\x53\x02" + b"\x00\x00\x5e\x00\x53\x01" + b"\x08\x00"
pkt += ipv4("192.168.1.4", "192.168.1.2", 47, gre + frame)

out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
out += struct.pack("<IIII", 1700000000, 0, len(pkt), len(pkt)) + pkt
open(DST, "wb").write(out)
