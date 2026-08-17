#!/usr/bin/env python3
"""Generate input.pcap for the Lua DNS OPT-answer regression."""

import struct

from scapy.all import Ether, IP, Raw, UDP, wrpcap


CLIENT = "192.0.2.1"
SERVER = "192.0.2.53"
CLIENT_PORT = 53000
TXID = 0x1234
OPTIONS = ((10, b"cookie"), (3, b"nsid"))


def dns_header(flags, questions, answers):
    return struct.pack("!HHHHHH", TXID, flags, questions, answers, 0, 0)


def build_pcap():
    question = b"\x00\x00\x01\x00\x01"  # root, A, IN
    request = dns_header(0x0100, 1, 0) + question

    options = b"".join(
        struct.pack("!HH", code, len(data)) + data for code, data in OPTIONS
    )
    opt_answer = (
        b"\x00"  # root name
        + struct.pack("!HHIH", 41, 4096, 0, len(options))
        + options
    )
    response = dns_header(0x8180, 1, 1) + question + opt_answer

    packets = [
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:35")
        / IP(src=CLIENT, dst=SERVER)
        / UDP(sport=CLIENT_PORT, dport=53)
        / Raw(request),
        Ether(src="02:00:00:00:00:35", dst="02:00:00:00:00:01")
        / IP(src=SERVER, dst=CLIENT)
        / UDP(sport=53, dport=CLIENT_PORT)
        / Raw(response),
    ]

    for index, packet in enumerate(packets):
        packet.time = index / 1_000_000

    return packets


if __name__ == "__main__":
    packets = build_pcap()
    wrpcap("input.pcap", packets)
    print(f"wrote {len(packets)} packets to input.pcap")
