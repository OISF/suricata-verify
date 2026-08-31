#!/usr/bin/env python3

from scapy.all import Ether, IP, Raw, UDP, wrpcap

def ikev1_message(next_payload, declared_length, payload=b""):
    return (
        bytes.fromhex(
            "0102030405060708"  # initiator SPI
            "0000000000000000"  # responder SPI
        )
        + bytes([next_payload, 0x10, 0x02, 0x00])
        + bytes.fromhex("00000000")  # message ID
        + declared_length.to_bytes(4, "big")
        + payload
    )


def make_packet(sport, payload, timestamp):
    packet = (
        Ether(src="00:01:02:03:04:05", dst="05:04:03:02:01:00")
        / IP(src="192.0.2.1", dst="192.0.2.2")
        / UDP(sport=sport, dport=500)
        / Raw(payload)
    )
    packet.time = timestamp
    return packet


# Valid generic payload framing, but the SA has no body or required DOI.
empty_sa = ikev1_message(1, 32, bytes.fromhex("00000004"))

# Header length is one byte larger than the complete UDP payload.
truncated = ikev1_message(0, 29)

# Header length is one byte smaller than the UDP payload.
trailing_data = ikev1_message(0, 28, b"\x00")

packets = [
    make_packet(45000, empty_sa, 1_700_000_000),
    make_packet(45001, truncated, 1_700_000_001),
    make_packet(45002, trailing_data, 1_700_000_002),
]

wrpcap("input.pcap", packets)
