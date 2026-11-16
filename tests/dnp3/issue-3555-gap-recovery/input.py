#!/usr/bin/env python3
"""Generate two DNP3 flows with capture loss in opposite TCP directions."""

from pathlib import Path
import struct

from scapy.all import Ether, IP, TCP, Raw, wrpcap


def crc(data):
    """DNP3 CRC-16 (reflected polynomial 0x3d65, final complement)."""
    value = 0
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ (0xa6bc if value & 1 else 0)
    return struct.pack("<H", value ^ 0xffff)


def frame(request, sequence, marker):
    # One complete transport/application fragment per link frame.
    user = bytes([0xc0 | sequence, 0xc0 | sequence, 1 if request else 0x81])
    if request:
        # READ group 30, any variation, using 32-bit start/stop indices.
        user += bytes([30, 0, 2]) + struct.pack("<II", marker, marker)
    else:
        # RESPONSE: five group 30 variation 1 points, flags ONLINE, same value.
        user += bytes([0, 0, 30, 1, 0, 0, 4])
        user += (b"\x01" + struct.pack("<i", marker)) * 5
    dest, src = (10, 1) if request else (1, 10)
    header = bytes([5, 0x64, 5 + len(user), 0xc4 if request else 0x44])
    header += struct.pack("<HH", dest, src)
    result = header + crc(header)
    for offset in range(0, len(user), 16):
        block = user[offset:offset + 16]
        result += block + crc(block)
    return result


class Connection:
    def __init__(self, packets, sport):
        self.packets = packets
        self.sport = sport
        self.seq = [1000, 5000]

    def packet(self, direction, flags, payload=b"", ack=None):
        client = direction == 0
        ips = ("192.0.2.1", "192.0.2.2")
        macs = ("02:00:00:00:00:01", "02:00:00:00:00:02")
        packet = Ether(src=macs[direction], dst=macs[1 - direction])
        packet /= IP(src=ips[direction], dst=ips[1 - direction], id=len(self.packets))
        packet /= TCP(sport=self.sport if client else 20000,
                      dport=20000 if client else self.sport,
                      seq=self.seq[direction],
                      ack=self.seq[1 - direction] if ack is None else ack,
                      flags=flags, window=32768)
        if payload:
            packet /= Raw(payload)
        packet.time = 1700000000 + len(self.packets) / 1000
        self.packets.append(packet)

    def handshake(self):
        self.packet(0, "S", ack=0)
        self.seq[0] += 1
        self.packet(1, "SA")
        self.seq[1] += 1
        self.packet(0, "A")

    def send(self, direction, payload, lost=False):
        if not lost:
            self.packet(direction, "PA", payload)
        self.seq[direction] += len(payload)
        # The endpoint received even the segment missing from the capture.
        self.packet(1 - direction, "A")

    def finish(self):
        for direction in (0, 1):
            self.packet(direction, "FA")
            self.seq[direction] += 1
            self.packet(1 - direction, "A")


def generate():
    packets = []
    for gap_direction in (0, 1):
        connection = Connection(packets, 40000 + gap_direction)
        connection.handshake()
        for sequence, marker in enumerate((0x11111111, 0x22222222,
                                            0x33333333, 0x44444444)):
            for direction in (0, 1):
                data = frame(direction == 0, sequence, marker)
                if sequence == 1 and direction == gap_direction:
                    # Buffer a partial frame, miss four bytes, then deliver its
                    # tail: recovery must both discard the prefix and resync.
                    connection.send(direction, data[:12])
                    connection.send(direction, data[12:16], lost=True)
                    connection.send(direction, data[16:])
                elif sequence == 2 and direction == gap_direction:
                    # The first good header after the gap crosses TCP segments.
                    connection.send(direction, data[:1])
                    connection.send(direction, data[1:])
                else:
                    connection.send(direction, data)
        connection.finish()
    wrpcap(str(Path(__file__).with_name("input.pcap")), packets)


if __name__ == "__main__":
    generate()
