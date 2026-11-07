#!/usr/bin/env python3
"""Generate the nfs4-getattr-maxtransfer fixture.

A v4 GETATTR reply advertising maxread 1024 / maxwrite 2048 via the
FATTR4_MAXREAD/MAXWRITE bits (30/31, uint64 values, word[0] covers
bits 0-31), then a 4096-byte WRITE. The write request must be flagged
with the advisory fsinfo_too_large anomaly while the data is still
tracked (fileinfo size 4096). Before the fix the constants were 40/42
and the bitmap words were combined in the wrong order, so the
advertised ceiling was never stored.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nfs_sv_common import Pcap, be32, be64, fh3, null_verf, v4_reply
import struct


def v4_call_c(xid, cred, prog_data):
    # RFC 3530: the NFS4 program procedure is 1 (COMPOUND); the shared
    # helper's 6 only reaches the partial-scan path
    return struct.pack(">I", (1 << 31) | len_body(xid, cred, prog_data)) + (
        be32(xid) + be32(0) + be32(2) + be32(100003) + be32(4) + be32(1)
        + cred + null_verf() + prog_data
    )


def len_body(xid, cred, prog_data):
    return (
        4 * 6 + len(cred) + len(null_verf()) + len(prog_data)
    )

CLIENT = ("192.168.1.6", 939)
SERVER = ("192.168.1.2", 2049)
FH = bytes(range(32))
NULL_CRED = be32(0) + be32(0)
WRITE_LEN = 4096
MAXWRITE = 2048
MAXREAD = 1024

# GETATTR4resok attrs: bitmap (word0 covers attr bits 0-31: type at 0,
# maxread at 30, maxwrite at 31; word1 covers 32-63: unused), then the
# attrlist4 length (RFC 5661 5.9.1), then the values in bitmap position
# order
# the frame-68-shaped mask (0x0010011a/0x00b0a03a: type, change, size,
# fsid, fileid, mode, numlinks, owner, quota, times, mounted) plus bits
# 30/31, so the value walk must cross the owner string and the 16-byte
# times to reach the ceilings; bare values, attrlist4 length-prefixed
OWNER = b"root@netapp.com" + b"\x00"  # 15 bytes, XDR-padded to 16
# the real frame-68 attrlist (tests/nfs4-01) with bits 30/31 added to
# word0: the value walk must cross the owner strings and the time values
# to reach the ceilings. Preceding the walk's fileid is 44 bytes, so the
# maxread/maxwrite values sit right after it (bit order 20 -> 30 -> 31).
ATTRLIST_PRE = bytes.fromhex("0000000216f82fdf21a82a4800000000000020000000000000f2fa8000000000000000000000000000000040")
ATTRLIST_POST = bytes.fromhex("000001ff0000000a0000000f726f6f74406e65746170702e636f6d000000000f726f6f74406e65746170702e636f6d000000000000002000000000005be0bee819ebe8f8000000005be0bf7c21a82a48000000005be0bf7c21a82a480000000000000062")
attrs = (
    be32(3)
    + be32(0xC010011A)        # word0: real mask + MAXREAD + MAXWRITE
    + be32(0x00B0A03A)       # word1: real mask
    + be32(0)                # word2: real (cnt 3 carries a zero word)
    + be32(160)              # attrlist4 length (144 + 2 ceilings)
    + ATTRLIST_PRE
    + be64(MAXREAD)          # maxread (8B)
    + be64(MAXWRITE)         # maxwrite (8B)
    + ATTRLIST_POST
)
# op codes: Suricata's v4 table (PUTFH=22, GETATTR=9, WRITE=38); the
# GETATTR request op carries the requested attr_bitmap4
getattr_req = (
    fh3(b"") + be32(0) + be32(2)
    + be32(22) + fh3(FH)
    + be32(9) + be32(2) + be32(1) + be32(0)  # GETATTR: want type
)
getattr_res = (
    be32(0) + fh3(b"") + be32(2)
    + be32(22) + be32(0)             # PUTFH ok
    + be32(9) + be32(0) + attrs      # GETATTR ok
)

write_req = (
    fh3(b"") + be32(0) + be32(2)
    + be32(22) + fh3(FH)
    + be32(38)
    + be32(1) + b"\x00" * 12      # stateid
    + be64(0)                     # offset
    + be32(0)                     # stable: UNSTABLE
    + be32(WRITE_LEN)             # count
    + be32(WRITE_LEN)             # data length
    + b"\x42" * WRITE_LEN
)
write_res = (
    be32(0) + fh3(b"") + be32(2)
    + be32(22) + be32(0)
    + be32(38) + be32(0)
    + be32(WRITE_LEN) + be32(0) + be64(0)  # write_size, stable, verf
)

# v4 probing is TCP-only in this parser, like the other v4 fixtures
p = Pcap(os.path.join(os.path.dirname(os.path.abspath(__file__)), "input.pcap"))
p.tcp(CLIENT, SERVER, syn=True)
p.tcp(SERVER, CLIENT, synack=True)
p.tcp(CLIENT, SERVER, pure_ack=True)
p.tcp(CLIENT, SERVER, payload=v4_call_c(0x60000001, NULL_CRED, getattr_req))
p.tcp(SERVER, CLIENT, payload=v4_reply(0x60000001, getattr_res))
p.tcp(CLIENT, SERVER, payload=v4_call_c(0x60000002, NULL_CRED, write_req))
p.tcp(SERVER, CLIENT, payload=v4_reply(0x60000002, write_res))
p.tcp(CLIENT, SERVER, pure_ack=True)
p.close()
print("maxwrite", MAXWRITE, "write", WRITE_LEN)
