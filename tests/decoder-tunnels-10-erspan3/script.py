#!/usr/bin/env python3
"""Build tunnels.pcap: the same ICMP echo mirrored in two ERSPAN Type III
sessions (321 and 322) from 192.168.1.4 to 192.168.1.2, in GRE with a
sequence number."""
import os
import struct

DST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tunnels.pcap")


def csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(">%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def ipv4(src, dst, proto, payload):
    hdr = bytearray(struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0, 64, proto, 0,
                                bytes(map(int, src.split("."))), bytes(map(int, dst.split(".")))))
    struct.pack_into(">H", hdr, 10, csum(bytes(hdr)))
    return bytes(hdr) + payload


def ether(payload):
    return b"\x00\x00\x5e\x00\x53\x02" + b"\x00\x00\x5e\x00\x53\x01" + b"\x08\x00" + payload


def erspan3(session, frame):
    # version 2, VLAN 0 | COS 0, BSO 0, T 0, session | timestamp | SGT | flags (frame type 0, O 0)
    return struct.pack(">HHIHH", 2 << 12, session & 0x3FF, 0, 0, 0) + frame


def gre(seq, payload):
    return struct.pack(">HHI", 0x1000, 0x22EB, seq) + payload


icmp = bytearray(struct.pack(">BBHHH", 8, 0, 0, 1, 1) + b"peng")
struct.pack_into(">H", icmp, 2, csum(bytes(icmp)))
inner = ether(ipv4("10.1.2.4", "10.1.2.3", 1, bytes(icmp)))

out = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)]
for i, session in enumerate((321, 322)):
    pkt = ether(ipv4("192.168.1.4", "192.168.1.2", 47, gre(i, erspan3(session, inner))))
    out.append(struct.pack("<IIII", 1700000000 + i, 0, len(pkt), len(pkt)) + pkt)
open(DST, "wb").write(b"".join(out))
