#!/usr/bin/env python3
"""Generate dns-flood.pcap: N DNS query/response pairs in one flow."""
import struct
import sys

N = int(sys.argv[1]) if len(sys.argv) > 1 else 2200
OUT = sys.argv[2] if len(sys.argv) > 2 else "dns-flood.pcap"

SRC_IP = "10.0.0.1"
DST_IP = "10.0.0.2"
SPORT = 33333
DPORT = 53


def ip4(s):
    return bytes(int(x) for x in s.split("."))


def csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def eth(dst, src, payload):
    return dst + src + struct.pack("!H", 0x0800) + payload


def ipv4(src, dst, payload, ident):
    total = 20 + len(payload)
    hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total, ident, 0x4000, 64, 17, 0, ip4(src), ip4(dst))
    h = csum(hdr)
    return struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, total, ident, 0x4000, 64, 17, h,
        ip4(src), ip4(dst)) + payload


def udp(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def qname(name):
    out = b""
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\0"


def dns_query(txid, name):
    hdr = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    return hdr + qname(name) + struct.pack("!HH", 1, 1)


def dns_response(txid, name):
    hdr = struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0)
    answer = struct.pack("!HHHIH", 0xC00C, 1, 1, 60, 4) + ip4("10.0.0.2")
    return hdr + qname(name) + struct.pack("!HH", 1, 1) + answer


def main():
    frames = []
    ts = 0.0
    for i in range(N):
        txid = i & 0xFFFF
        name = "q%d.example.com" % i
        f = eth(b"\x02\x00\x00\x00\x00\x02", b"\x02\x00\x00\x00\x00\x01",
                ipv4(SRC_IP, DST_IP, udp(SPORT, DPORT, dns_query(txid, name)), i & 0xFFFF))
        frames.append((ts, f))
        ts += 0.001
        f = eth(b"\x02\x00\x00\x00\x00\x01", b"\x02\x00\x00\x00\x00\x02",
                ipv4(DST_IP, SRC_IP, udp(DPORT, SPORT, dns_response(txid, name)), i & 0xFFFF))
        frames.append((ts, f))
        ts += 0.001

    with open(OUT, "wb") as out:
        out.write(struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, frame in frames:
            sec = int(ts)
            usec = int(round((ts - sec) * 1000000))
            out.write(struct.pack("!IIII", sec, usec, len(frame), len(frame)))
            out.write(frame)


if __name__ == "__main__":
    main()
