#!/usr/bin/env python3
#
# Generate input.pcap for Redmine #9160: BSD defrag must trim every
# following fragment overlapped by a preferred fragment, not just the
# immediate right-hand neighbour.
#
# Requires scapy. Run from this directory:
#
#   python3 gen-pcap.py

from scapy.all import (
    Ether, IP, IPv6, IPv6ExtHdrFragment, UDP, raw, wrpcap,
)

SPORT = 4444
DPORT = 5555
DST4 = "10.0.0.9"
DST6 = "2001:db8::9"
SRC_MAC = "00:00:00:00:00:01"
DST_MAC = "00:00:00:00:00:02"

packets = []
ts = 1700000000.0


def udp_header(ipcls, src, dst, payload):
    """Return an 8 byte UDP header with a checksum over the expected
    (BSD reassembled) payload."""
    pkt = ipcls(src=src, dst=dst) / UDP(sport=SPORT, dport=DPORT) / payload
    pkt = ipcls(raw(pkt))
    return raw(pkt[UDP])[:8]


def add(ipv6, src, ident, frags):
    """Add a fragment train. frags is a list of (byte offset, data);
    the last entry has MF clear."""
    global ts
    for i, (offset, data) in enumerate(frags):
        assert offset % 8 == 0
        mf = 1 if i < len(frags) - 1 else 0
        if ipv6:
            pkt = Ether(src=SRC_MAC, dst=DST_MAC) / IPv6(src=src, dst=DST6) / IPv6ExtHdrFragment(
                nh=17, offset=offset // 8, m=mf, id=ident) / data
        else:
            pkt = Ether(src=SRC_MAC, dst=DST_MAC) / IP(src=src, dst=DST4, id=ident, proto=17,
                               flags="MF" if mf else 0,
                               frag=offset // 8) / data
        pkt.time = ts
        ts += 1
        packets.append(pkt)


def control(ipv6, src, ident, token):
    """Clean, non-overlapping fragments. Always alerts."""
    ipcls = IPv6 if ipv6 else IP
    dst = DST6 if ipv6 else DST4
    payload = b"a" * 8 + token
    hdr = udp_header(ipcls, src, dst, payload)
    add(ipv6, src, ident, [
        (0, hdr + b"a" * 8),
        (16, token),
    ])


def starts_inside_prev(ipv6, src, ident, token):
    """Preferred fragment starts inside an earlier fragment.

    Fragments (byte offsets into the UDP datagram), in arrival order:
      F1  0..16  UDP header + "a" * 8
      F2 16..32  "b" * 16
      F3 32..48  "c" * 16
      F4  8..48  "x" * 8 + "d" * 16 + token
      F5 48..56  "e" * 8 (last)

    BSD keeps F1 for 8..16 and takes F4 for 16..48, so the token is at
    32..48 of the reassembled datagram. Vulnerable code only trims F2, so
    F3 overwrites the token with "c" * 16.
    """
    ipcls = IPv6 if ipv6 else IP
    dst = DST6 if ipv6 else DST4
    payload = b"a" * 8 + b"d" * 16 + token + b"e" * 8
    hdr = udp_header(ipcls, src, dst, payload)
    add(ipv6, src, ident, [
        (0, hdr + b"a" * 8),
        (16, b"b" * 16),
        (32, b"c" * 16),
        (8, b"x" * 8 + b"d" * 16 + token),
        (48, b"e" * 8),
    ])


def starts_before(ipv6, src, ident, token):
    """Preferred fragment starts before every earlier fragment.

    Fragments (byte offsets into the UDP datagram), in arrival order:
      F1  8..24  "b" * 16
      F2 24..40  "c" * 16
      F3 40..56  "f" * 16
      F4  0..56  UDP header + "d" * 32 + token
      F5 56..64  "e" * 8 (last)

    BSD takes F4 for 0..56. Vulnerable code trims F1 and F2 only, so F3
    overwrites the token with "f" * 16.
    """
    ipcls = IPv6 if ipv6 else IP
    dst = DST6 if ipv6 else DST4
    payload = b"d" * 32 + token + b"e" * 8
    hdr = udp_header(ipcls, src, dst, payload)
    add(ipv6, src, ident, [
        (8, b"b" * 16),
        (24, b"c" * 16),
        (40, b"f" * 16),
        (0, hdr + b"d" * 32 + token),
        (56, b"e" * 8),
    ])


control(False, "10.0.0.1", 0x9161, b"SV9160-V4-CTRLOK")
starts_inside_prev(False, "10.0.0.2", 0x9162, b"SV9160-V4-INSIDE")
starts_before(False, "10.0.0.3", 0x9163, b"SV9160-V4-BEFORE")
control(True, "2001:db8::1", 0x9164, b"SV9160-V6-CTRLOK")
starts_inside_prev(True, "2001:db8::2", 0x9165, b"SV9160-V6-INSIDE")
starts_before(True, "2001:db8::3", 0x9166, b"SV9160-V6-BEFORE")

wrpcap("input.pcap", packets)
