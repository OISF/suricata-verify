#!/usr/bin/env python3
# Generates threshold-cache-bounded.pcap.
#
# The capture is designed to exercise the per-thread threshold decision
# cache (src/detect-engine-threshold.c, CheckCache/SetupCache), which only
# applies to IPv4 limit/both thresholds tracked by_src or by_dst.
#
# For each of SOURCES unique source addresses:
#   packet 1 @ t=1000 : first match in the window -> alert (count 1 of 1)
#   packet 2 @ t=1000 : second match -> limit exceeded -> silent match,
#                       this is where the decision cache entry is created
#   packet 3 @ t=1000 : third match -> silent match served from the cache
#                       (cache read path)
# A final packet @ t=1003 from a fresh source (203.0.113.250) alerts and
# triggers one cache housekeeping pass.
#
# Expected results with test.rules (limit, count 1, seconds 1, by_src):
#   - 100001 alert events (one per unique source + final packet)
#   - 200000 suppressed matches (packets 2 and 3 of each source)
#   - the decision cache is asked to hold 100000 distinct entries, far
#     beyond any sane bound; a bounded cache keeps memory flat.
#
# Usage:
#   python3 writepcap.py [output.pcap] [sources]

import socket
import struct
import sys

PAYLOAD = b"CACHE9"
DESTINATION = "198.51.100.9"
DEST_PORT = 9999
SRC_PORT = 40000


def checksum(data):
    if len(data) & 1:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total & 0xffff) + (total >> 16)
    total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def frame(source, ident):
    source_raw = socket.inet_aton(source)
    destination_raw = socket.inet_aton(DESTINATION)
    udp = struct.pack("!HHHH", SRC_PORT, DEST_PORT, 8 + len(PAYLOAD), 0) + PAYLOAD
    ip0 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 20 + len(udp), ident & 0xffff,
        0, 64, 17, 0, source_raw, destination_raw
    )
    ip = ip0[:10] + struct.pack("!H", checksum(ip0)) + ip0[12:]
    # eth dst 02:00:00:00:00:02, eth src 00:00:00:00:00:01, ethertype IPv4
    ethernet = bytes.fromhex("0200000000020200000000010800")
    return ethernet + ip + udp


def source_for(index):
    # 10.0.0.0/8 is large enough for any source count we generate here
    value = index + 1
    return "10.%d.%d.%d" % (
        (value >> 16) & 255,
        (value >> 8) & 255,
        value & 255,
    )


def record(timestamp, packet):
    return struct.pack("<IIII", timestamp, 0, len(packet), len(packet)) + packet


def generate(path, sources):
    with open(path, "wb") as out:
        # classic pcap, endianness native, v2.4, linktype ethernet
        out.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for index in range(sources):
            packet = frame(source_for(index), index)
            out.write(record(1000, packet))
            out.write(record(1000, packet))
            out.write(record(1000, packet))
        out.write(record(1003, frame("203.0.113.250", 65535)))


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "threshold-cache-bounded.pcap"
    sources = int(sys.argv[2]) if len(sys.argv) > 2 else 100000
    generate(path, sources)
    print("wrote %s (%d sources, %d packets)" % (path, sources, sources * 3 + 1))
