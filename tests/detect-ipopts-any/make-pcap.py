#!/usr/bin/env python3
"""Generate the deterministic Ethernet PCAP for the ipopts:any test."""
import ipaddress
from pathlib import Path
import struct


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    acc = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while acc >> 16:
        acc = (acc & 0xFFFF) + (acc >> 16)
    return (~acc) & 0xFFFF


def packet(src_s, dst_s, ident, options=b""):
    src, dst = map(ipaddress.ip_address, (src_s, dst_s))
    payload = b"suricata-verify"
    udp_len = len(payload) + 8
    udp = struct.pack("!HHHH", 45000 + ident, 45001, udp_len, 0) + payload
    if src.version == 4:
        pseudo = src.packed + dst.packed + struct.pack("!BBH", 0, 17, udp_len)
        ihl = 5 + len(options) // 4
        ip = struct.pack(
            "!BBHHHBBH4s4s", 0x40 | ihl, 0, 4 * ihl + udp_len,
            ident, 0, 64, 17, 0, src.packed, dst.packed,
        ) + options
        ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
        ethertype = 0x0800
    else:
        pseudo = src.packed + dst.packed + struct.pack("!I3xB", udp_len, 17)
        ip = struct.pack("!IHBB16s16s", 6 << 28, udp_len, 17, 64, src.packed, dst.packed)
        ethertype = 0x86DD
    udp = udp[:6] + struct.pack("!H", checksum(pseudo + udp) or 0xFFFF) + udp[8:]
    ethernet = bytes.fromhex("020000000002020000000001")
    frame = ethernet + struct.pack("!H", ethertype) + ip + udp
    return frame.ljust(60, b"\0")


def main():
    ipv4 = ("192.0.2.1", "198.51.100.2")
    frames = (
        packet(*ipv4, 1),
        packet(*ipv4, 2, bytes.fromhex("0100000000000000")),          # NOP, EOL and padding
        packet(*ipv4, 3, bytes.fromhex("0707040000000000")),  # RR, EOL
        packet("2001:db8::1", "2001:db8::2", 4),
    )
    pcap = Path(__file__).with_name("input.pcap")
    with pcap.open("wb") as out:
        out.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index, frame in enumerate(frames):
            out.write(struct.pack("<IIII", 1700000000 + index, 0, len(frame), len(frame)))
            out.write(frame)


if __name__ == "__main__":
    main()
