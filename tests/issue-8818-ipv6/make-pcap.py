#!/usr/bin/env python3
"""Generate the IPv6 fragment-chain trigger for Redmine issue 8818."""

import struct

from scapy.all import (
    Ether,
    IPv6,
    IPv6ExtHdrDestOpt,
    IPv6ExtHdrFragment,
    PadN,
    Raw,
    wrpcap,
)


SRC_MAC = "02:00:00:00:88:18"
DST_MAC = "02:00:00:00:88:19"
SRC_IP = "2001:db8::8818"
DST_IP = "2001:db8::1"
FRAGMENT_ID = 0x11223344
FRAGMENT_SIZE = 1448
FRAGMENTABLE_LEN = 65528


def ethernet():
    return Ether(src=SRC_MAC, dst=DST_MAC)


def ipv6(next_header):
    return IPv6(src=SRC_IP, dst=DST_IP, nh=next_header, hlim=64)


def main():
    udp_header = struct.pack("!HHHH", 12345, 54321, FRAGMENTABLE_LEN, 0)
    payload = udp_header + b"A" * (FRAGMENTABLE_LEN - len(udp_header))

    packets = []

    # The Destination Options header is part of the unfragmentable portion.
    # Together with 65,528 fragmentable bytes it makes the reassembled IPv6
    # payload 65,536 bytes, one byte beyond the 16-bit payload-length limit.
    first = (
        ethernet()
        / ipv6(60)
        / IPv6ExtHdrDestOpt(nh=44, options=PadN(optdata=b"\x00" * 4))
        / IPv6ExtHdrFragment(nh=17, id=FRAGMENT_ID, offset=0, m=1)
        / Raw(payload[:FRAGMENT_SIZE])
    )
    packets.append(first)

    for offset in range(FRAGMENT_SIZE, 65160, FRAGMENT_SIZE):
        fragment = (
            ethernet()
            / ipv6(44)
            / IPv6ExtHdrFragment(
                nh=17,
                id=FRAGMENT_ID,
                offset=offset // 8,
                m=1,
            )
            / Raw(payload[offset : offset + FRAGMENT_SIZE])
        )
        packets.append(fragment)

    final_offset = 65160
    final = (
        ethernet()
        / ipv6(44)
        / IPv6ExtHdrFragment(
            nh=17,
            id=FRAGMENT_ID,
            offset=final_offset // 8,
            m=0,
        )
        / Raw(payload[final_offset:])
    )
    packets.append(final)

    assert len(packets) == 46
    destopt_len = len(bytes(first[IPv6ExtHdrDestOpt])) - len(
        bytes(first[IPv6ExtHdrFragment])
    )
    assert destopt_len == 8
    assert len(payload[final_offset:]) == 368

    for index, packet in enumerate(packets):
        packet.time = index / 1_000_000

    wrpcap("input.pcap", packets)
    print(f"wrote {len(packets)} packets to input.pcap")


if __name__ == "__main__":
    main()
