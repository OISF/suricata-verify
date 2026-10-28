#!/usr/bin/env python3
"""Generate input.pcap for the multi-rule-group flowbits 'set' prefilter test.

Layout:
  * FLOWS_TO_81 UDP packets, one per new flow, to dst port 81. The 'set' rule
    is part of the port 81-65535 rule group, which has no 'isset' rule and
    therefore no post-rule-match prefilter engine.
  * one final UDP packet from a fresh source port to dst port 80. That group
    has both the 'set' and the 'isset' rule, so the post-rule-match engine
    runs here and the queued work is expanded into the match candidates.

Stdlib only.
"""
import socket
import struct
import sys


def checksum16(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def build_udp(src_ip, dst_ip, sport, dport, ident, payload=b""):
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    total_len = 20 + len(udp)
    iphdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_len, ident, 0x4000, 64, 17, 0,
        src_ip, dst_ip,
    )
    iphdr = iphdr[:10] + struct.pack("!H", checksum16(iphdr)) + iphdr[12:]
    eth = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00"
    return eth + iphdr + udp


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "input.pcap"
    flows_to_81 = int(sys.argv[2]) if len(sys.argv) > 2 else 2000

    src = socket.inet_aton("10.0.0.1")
    dst = socket.inet_aton("10.0.0.2")

    packets = []
    ident = 1
    payload = b"AAAA"
    # Distinct 5-tuples, so each packet newly sets the bit.
    for i in range(flows_to_81):
        packets.append(build_udp(src, dst, 20000 + i, 81, ident & 0xFFFF, payload))
        ident += 1
    # Fresh flow on the port 80 rule group.
    packets.append(build_udp(src, dst, 9090, 80, ident & 0xFFFF, payload))

    with open(out, "wb") as f:
        f.write(struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        ts = 1700000000
        for pkt in packets:
            f.write(struct.pack("!IIII", ts, 0, len(pkt), len(pkt)))
            f.write(pkt)
            ts += 1

    print("wrote %s with %d packets" % (out, len(packets)))


if __name__ == "__main__":
    main()
