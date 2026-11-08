#!/usr/bin/env python
"""
Generate a DCE/RPC-over-UDP (connectionless) pcap for the dcerpc.is_fragmented
keyword test.

Two REQUEST PDUs on the same UDP flow, each its own transaction:

  1. flags1 = 0x04 (PFCL1_FRAG set)  -> fragmented     (is_fragmented:yes)
  2. flags1 = 0x00 (no frag flag)    -> not fragmented (is_fragmented:no)

For UDP the fragment flag lives in flags1, stored in the low byte of the
per-direction flags of the transaction.
"""

import struct

from scapy.all import Ether, IP, UDP, Raw, wrpcap

CLIENT_IP = "192.168.0.1"
SERVER_IP = "192.168.0.2"


def cl_header(ptype, flags1, flags2, activity, seqnum):
    """Build an 80-byte connectionless DCE/RPC header."""
    h = bytearray(80)
    h[0] = 0x04              # rpc_vers (connectionless == 4)
    h[1] = ptype             # 0 = request
    h[2] = flags1
    h[3] = flags2
    h[4:7] = b"\x10\x00\x00"  # drep (little-endian)
    h[40:56] = activity      # activity UUID
    struct.pack_into("<I", h, 64, seqnum)   # seqnum
    struct.pack_into("<H", h, 74, 0)        # fraglen (no body)
    struct.pack_into("<H", h, 76, 0)        # fragnum (first fragment)
    return bytes(h)


def pkt(payload):
    return (
        Ether(dst="00:00:00:00:00:02", src="00:00:00:00:00:01")
        / IP(src=CLIENT_IP, dst=SERVER_IP)
        / UDP(sport=1025, dport=135) / Raw(load=payload)
    )


def create_pcap():
    frag = cl_header(0x00, 0x04, 0x00, bytes(range(1, 17)), 0)
    nofrag = cl_header(0x00, 0x00, 0x00, bytes(range(17, 33)), 1)
    return [pkt(frag), pkt(nofrag)]


wrpcap("input.pcap", create_pcap())
