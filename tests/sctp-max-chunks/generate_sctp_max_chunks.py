#!/usr/bin/env python3

"""Generate one SCTP packet with as many chunks as possible (IPv4 max len)."""

from scapy.all import IP, Raw, raw, wrpcap
from scapy.layers.sctp import SCTP, SCTPChunkAbort


MAX_IPV4_LEN = 65535
OUTPUT = "sctp-max-chunks.pcap"


def main() -> None:
    # ABORT is a minimal 4-byte SCTP chunk in Scapy.
    chunk_bytes = raw(SCTPChunkAbort())
    chunk_size = len(chunk_bytes)

    base = IP(src="192.0.2.1", dst="198.51.100.1") / SCTP(
        sport=12345,
        dport=36412,
        tag=0x11223344,
    )
    base_size = len(raw(base))

    chunk_count = ((MAX_IPV4_LEN - base_size) // chunk_size) - 232
    payload = chunk_bytes * chunk_count

    pkt = base / Raw(load=payload)
    wrpcap(OUTPUT, [pkt])

    print(f"Wrote: {OUTPUT}")
    print(f"Chunk type: abort")
    print(f"Chunk size: {chunk_size} bytes")
    print(f"Chunk count: {chunk_count}")
    print(f"IPv4 packet size: {len(raw(pkt))} bytes")


if __name__ == "__main__":
    main()
