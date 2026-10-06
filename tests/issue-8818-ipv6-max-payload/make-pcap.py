#!/usr/bin/env python3
"""Generate a maximum-payload IPv6 fragment chain for Redmine issue 8818."""

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


SRC_MAC = "02:00:00:00:88:16"
DST_MAC = "02:00:00:00:88:17"
SRC_IP = "2001:db8::8818"
DST_IP = "2001:db8::1"
FRAGMENT_ID = 0x55667788
FRAGMENT_SIZE = 1448
FRAGMENTABLE_LEN = 65527
FINAL_OFFSET = 65160
MARKER = b"IPV6-MAX-PAYLOAD-8818"


def ethernet():
    return Ether(src=SRC_MAC, dst=DST_MAC)


def ipv6(next_header):
    return IPv6(src=SRC_IP, dst=DST_IP, nh=next_header, hlim=64)


def main():
    udp_header = struct.pack("!HHHH", 12345, 54321, FRAGMENTABLE_LEN, 0)
    padding_len = FRAGMENTABLE_LEN - len(udp_header) - len(MARKER)
    payload = udp_header + b"A" * padding_len + MARKER

    first = (
        ethernet()
        / ipv6(60)
        / IPv6ExtHdrDestOpt(nh=44, options=PadN(optdata=b"\x00" * 4))
        / IPv6ExtHdrFragment(nh=17, id=FRAGMENT_ID, offset=0, m=1)
        / Raw(payload[:FRAGMENT_SIZE])
    )
    packets = [first]

    for offset in range(FRAGMENT_SIZE, FINAL_OFFSET, FRAGMENT_SIZE):
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

    final = (
        ethernet()
        / ipv6(44)
        / IPv6ExtHdrFragment(
            nh=17,
            id=FRAGMENT_ID,
            offset=FINAL_OFFSET // 8,
            m=0,
        )
        / Raw(payload[FINAL_OFFSET:])
    )
    packets.append(final)

    destopt_len = len(bytes(first[IPv6ExtHdrDestOpt])) - len(
        bytes(first[IPv6ExtHdrFragment])
    )
    assert len(packets) == 46
    assert destopt_len == 8
    assert len(payload[FINAL_OFFSET:]) == 367
    assert destopt_len + len(payload) == 65535
    assert 40 + destopt_len + len(payload) == 65575
    assert payload.endswith(MARKER)

    for index, packet in enumerate(packets):
        packet.time = index / 1_000_000

    wrpcap("input.pcap", packets)
    print(f"wrote {len(packets)} packets to input.pcap")


if __name__ == "__main__":
    main()
