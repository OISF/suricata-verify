#!/usr/bin/env python3
"""Generate the IPv4 fragment-chain counterpart to Redmine issue 8818."""

import struct

from scapy.all import Ether, IP, IPOption_NOP, Raw, wrpcap


SRC_MAC = "02:00:00:00:88:14"
DST_MAC = "02:00:00:00:88:15"
SRC_IP = "192.0.2.1"
DST_IP = "192.0.2.2"
FRAGMENT_ID = 0x8818
FRAGMENT_SIZE = 1448
FRAGMENTABLE_LEN = 65515
FINAL_OFFSET = 65160


def ethernet():
    return Ether(src=SRC_MAC, dst=DST_MAC)


def ipv4(offset, more_fragments, options=None):
    return IP(
        src=SRC_IP,
        dst=DST_IP,
        id=FRAGMENT_ID,
        flags="MF" if more_fragments else 0,
        frag=offset // 8,
        proto=17,
        ttl=64,
        options=options or [],
    )


def main():
    udp_header = struct.pack("!HHHH", 12345, 54321, FRAGMENTABLE_LEN, 0)
    payload = udp_header + b"A" * (FRAGMENTABLE_LEN - len(udp_header))

    # The 40 one-byte NOP options produce the maximum 60-byte IPv4 header.
    # The fragment payload ends at 65,515, which passes a check based on the
    # minimum 20-byte header but exceeds the IPv4 limit with the actual header.
    first = (
        ethernet()
        / ipv4(0, True, [IPOption_NOP() for _ in range(40)])
        / Raw(payload[:FRAGMENT_SIZE])
    )
    packets = [first]

    for offset in range(FRAGMENT_SIZE, FINAL_OFFSET, FRAGMENT_SIZE):
        fragment = (
            ethernet()
            / ipv4(offset, True)
            / Raw(payload[offset : offset + FRAGMENT_SIZE])
        )
        packets.append(fragment)

    final = (
        ethernet()
        / ipv4(FINAL_OFFSET, False)
        / Raw(payload[FINAL_OFFSET:])
    )
    packets.append(final)

    first_header_len = len(bytes(first[IP])) - len(bytes(first[Raw]))
    assert len(packets) == 46
    assert first_header_len == 60
    assert len(payload[FINAL_OFFSET:]) == 355
    assert 20 + len(payload) == 65535
    assert first_header_len + len(payload) == 65575

    for index, packet in enumerate(packets):
        packet.time = index / 1_000_000

    wrpcap("input.pcap", packets)
    print(f"wrote {len(packets)} packets to input.pcap")


if __name__ == "__main__":
    main()
