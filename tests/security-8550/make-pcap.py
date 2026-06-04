#!/usr/bin/env python3
"""Generate input.pcap for Redmine #8550.

The pcap creates a deterministic single-thread reproducer for the old defrag
lock ordering bug: the outer IPv4/GRE packet and the GRE-encapsulated inner
IPv4 fragment deliberately use the same defrag key (src, dst, id, proto).  In
vulnerable builds the outer packet is decoded while its defrag tracker mutex is
still held, and decoding the inner fragment tries to lock the same tracker.
"""

from scapy.all import Ether, GRE, IP, UDP, Raw, fragment, wrpcap

SRC = "10.85.50.1"
DST = "10.85.50.2"
IPID = 0x8550
GRE_IPV4 = 0x0800


def main():
    # Minimal inner IPv4 fragment. It only needs to be recognizable as a
    # fragment; its payload is not decoded before defrag tries to lock the
    # matching tracker.
    inner_frag0 = IP(src=SRC, dst=DST, id=IPID, proto=47, flags="MF") / Raw(b"ABCDEFGH")

    outer = IP(src=SRC, dst=DST, id=IPID, proto=47) / GRE(proto=GRE_IPV4) / inner_frag0
    packets = [
        Ether(src="02:00:00:85:50:01", dst="02:00:00:85:50:02", type=0x0800) / frag
        for frag in fragment(outer, fragsize=16)
    ]
    for idx, pkt in enumerate(packets):
        pkt.time = idx / 1_000_000

    wrpcap("input.pcap", packets)
    print(f"wrote {len(packets)} packets to input.pcap")


if __name__ == "__main__":
    main()
