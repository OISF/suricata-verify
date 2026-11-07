#!/usr/bin/env python3
"""Generate the nfs-tcp-record-mark-overflow fixture.

RFC 5531 11 makes the RPC record mark a 31 bit byte count for every NFS
version, so a few bytes on the wire can claim close to 2 GiB. The parser
buffers toward whatever the mark claims, so an attacker-paced flow can pin
memory and stall detection. The cap that abandons the flow has to follow
the width of the field, not the v3/v4 payload limits.

One v3 CALL whose mark claims 1 GiB with 92 bytes of real record behind
it, on a TCP session to 2049.
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nfs_sv_common import Pcap, be32, null_verf, unix_cred

CLIENT = ("192.168.7.10", 832)
SERVER = ("192.168.7.20", 2049)

# GETATTR args: a 32 byte handle, followed by nothing
args = be32(32) + bytes(range(32)) + be32(2) + be32(0) + be32(0)
rpc = (
    be32(0x5A5A0001) + be32(0) + be32(2) + be32(100003) + be32(3) + be32(1)
    + unix_cred() + null_verf() + args
)
# is_last | a length the capture cannot come close to satisfying
CLAIM = 0x40000000  # 1 GiB in the 31 bit field
mark = struct.pack(">I", (1 << 31) | CLAIM)
assert CLAIM > len(rpc)

p = Pcap(os.path.join(os.path.dirname(os.path.abspath(__file__)), "input.pcap"))
p.tcp(CLIENT, SERVER, syn=True)
p.tcp(SERVER, CLIENT, synack=True)
p.tcp(CLIENT, SERVER)
p.tcp(CLIENT, SERVER, mark + rpc)
p.tcp(SERVER, CLIENT)
p.close()
