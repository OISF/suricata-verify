#!/usr/bin/env python
"""
Generate a bidirectional DCE/RPC-over-UDP (connectionless) pcap for the
dcerpc.hdr keyword test.

Two packets that form a single transaction (same activity UUID and sequence
number):

  1. client -> server : connectionless REQUEST  (ptype 0), to_server
  2. server -> client : connectionless RESPONSE (ptype 2), to_client

The DCE/RPC over UDP (connectionless) header is a fixed 80 bytes. Both PDUs
carry no body (fraglen = 0), so the whole packet payload is just the header.
This lets dcerpc.hdr be matched per direction: the request header is exposed on
to_server (udp_req_hdr) and the response header on to_client (udp_resp_hdr).
"""

import struct

from scapy.all import Ether, IP, UDP, Raw, wrpcap

CLIENT_IP = "192.168.0.1"
SERVER_IP = "192.168.0.2"
CLIENT_PORT = 1025
SERVER_PORT = 135

# 16 raw bytes used for the activity UUID; identical in both PDUs so the
# request and the response are paired into the same transaction.
ACTIVITY = bytes(range(1, 17))


def cl_header(ptype, activity, seqnum):
    """Build an 80-byte connectionless DCE/RPC header."""
    h = bytearray(80)
    h[0] = 0x04              # rpc_vers (connectionless == 4)
    h[1] = ptype             # 0 = request, 2 = response
    h[2] = 0x00              # flags1 (no fragment flags -> complete PDU)
    h[3] = 0x00              # flags2
    h[4:7] = b"\x10\x00\x00"  # drep (drep[0] & 0x10 -> little-endian)
    h[7] = 0x00              # serial_hi
    # h[8:24]  object UUID     (zero)
    # h[24:40] interface UUID  (zero)
    h[40:56] = activity      # activity UUID
    # h[56:60] server_boot, h[60:64] if_vers (zero)
    struct.pack_into("<I", h, 64, seqnum)   # seqnum
    # h[68:70] opnum, h[70:72] ihint, h[72:74] ahint (zero)
    struct.pack_into("<H", h, 74, 0)        # fraglen (no body)
    struct.pack_into("<H", h, 76, 0)        # fragnum
    # h[78] auth_proto, h[79] serial_lo (zero)
    return bytes(h)


def create_pcap():
    req = cl_header(0x00, ACTIVITY, 0)
    resp = cl_header(0x02, ACTIVITY, 0)
    eth = {"dst": "00:00:00:00:00:02", "src": "00:00:00:00:00:01"}
    return [
        Ether(**eth) / IP(src=CLIENT_IP, dst=SERVER_IP)
        / UDP(sport=CLIENT_PORT, dport=SERVER_PORT) / Raw(load=req),
        Ether(dst=eth["src"], src=eth["dst"]) / IP(src=SERVER_IP, dst=CLIENT_IP)
        / UDP(sport=SERVER_PORT, dport=CLIENT_PORT) / Raw(load=resp),
    ]


wrpcap("input.pcap", create_pcap())
