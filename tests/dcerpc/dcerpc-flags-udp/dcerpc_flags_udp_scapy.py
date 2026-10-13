#!/usr/bin/env python
"""
Generate a bidirectional DCE/RPC-over-UDP (connectionless) pcap for the
dcerpc.flags keyword test.

Two PDUs forming one transaction (same activity UUID and sequence number):

  1. client -> server : REQUEST  (ptype 0), flags1=0x01 flags2=0x02 -> req_flags  0x0201
  2. server -> client : RESPONSE (ptype 2), flags1=0x03 flags2=0x04 -> resp_flags 0x0403

For UDP the flags field is a u16 built as (flags2 << 8) | flags1, and it is
stored per direction: the request PDU sets req_flags (matched on to_server) and
the response PDU sets resp_flags (matched on to_client).
"""

import struct

from scapy.all import Ether, IP, UDP, Raw, wrpcap

CLIENT_IP = "192.168.0.1"
SERVER_IP = "192.168.0.2"
CLIENT_PORT = 1025
SERVER_PORT = 135

ACTIVITY = bytes(range(1, 17))


def cl_header(ptype, flags1, flags2, activity, seqnum):
    """Build an 80-byte connectionless DCE/RPC header."""
    h = bytearray(80)
    h[0] = 0x04              # rpc_vers (connectionless == 4)
    h[1] = ptype             # 0 = request, 2 = response
    h[2] = flags1
    h[3] = flags2
    h[4:7] = b"\x10\x00\x00"  # drep (little-endian)
    h[7] = 0x00              # serial_hi
    h[40:56] = activity      # activity UUID
    struct.pack_into("<I", h, 64, seqnum)   # seqnum
    struct.pack_into("<H", h, 74, 0)        # fraglen (no body)
    struct.pack_into("<H", h, 76, 0)        # fragnum
    return bytes(h)


def create_pcap():
    req = cl_header(0x00, 0x01, 0x02, ACTIVITY, 0)
    resp = cl_header(0x02, 0x03, 0x04, ACTIVITY, 0)
    return [
        Ether(dst="00:00:00:00:00:02", src="00:00:00:00:00:01")
        / IP(src=CLIENT_IP, dst=SERVER_IP)
        / UDP(sport=CLIENT_PORT, dport=SERVER_PORT) / Raw(load=req),
        Ether(dst="00:00:00:00:00:01", src="00:00:00:00:00:02")
        / IP(src=SERVER_IP, dst=CLIENT_IP)
        / UDP(sport=SERVER_PORT, dport=CLIENT_PORT) / Raw(load=resp),
    ]


wrpcap("input.pcap", create_pcap())
