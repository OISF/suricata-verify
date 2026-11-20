#!/usr/bin/env python3
"""Generate the nfs3-fsinfo-ceiling fixture.

A v3 FSINFO reply advertising a 4 KiB max transfer size (RFC 1813
3.3.19 layout: post_op_attr + rtmax/rtmult/rtsmax/wtmult/wtsmax/dtpref/
maxfilesize/ttdelta/properties), then a 1 KiB READ (within the ceiling)
and an 8 KiB FILE_SYNC WRITE (above it). The write request must be
flagged with the advisory fsinfo_too_large anomaly while the data is
still tracked (fileinfo size 8192). Before the FSINFO layout fix the
reply parsed a fabricated field order and the wrong ceiling (or no
ceiling) was stored.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nfs_sv_common import (
    Pcap, be32, be64, fh3, v3_fh, v3_call_raw, v3_reply_raw,
)

CLIENT = ("192.168.1.6", 939)
SERVER = ("192.168.1.2", 2049)
FH = v3_fh(0x5A)


def fattr3():
    return b"\x00" * 84


def wcc():
    # pre_op_attr + post_op_attr, both attrs-unset (16 bytes)
    return b"\x00" * 16


def post_op_attr():
    # post_op_fattr3: attr_follows 1 + fattr3 (no status word -- the
    # reply status precedes the resok body)
    return be32(1) + fattr3()


# FSINFO3resok (RFC 1813 3.3.19): post_op_attr + rtmax rtpref rtmult
# wtmax wtpref wtmult dtpref maxfilesize (hyper) ttdelta properties
FSINFO = 4096
# FSINFO3args is a bare filehandle3 (RFC 1813 3.3.19): length then bytes
fsinfo_args = be32(32) + bytes(range(32))
fsinfo_res = (
    be32(0)
    + post_op_attr()
    + be32(FSINFO) + be32(1024) + be32(FSINFO)  # rtmax rtpref rtmult
    + be32(FSINFO) + be32(1024) + be32(FSINFO)  # wtmax wtpref wtmult
    + be32(1024)                                # dtpref
    + be64(0x7FFFFFFF)                          # maxfilesize
    + be32(0) + be32(0)                         # ttdelta (nfstime3)
    + be32(3)                                   # properties: link+symlink
)

# proc numbers: Suricata/Linux v3 table (READLINK=5 READ=6 WRITE=7 FSINFO=19)
# READ3res: status + post_op_attr (the 1999-capture layout this parser
# is built on) + count + eof + data (XDR opaque). The read is the final
# 512 bytes of the written 8 KiB (eof completes the tx and gets it
# logged; its 512 count stays under the 4 KiB ceiling)
read_call = v3_call_raw(0x40000001, 6, FH + be64(7680) + be32(512))
read_res = v3_reply_raw(
    0x40000001,
    be32(0) + be32(1) + b"\x00" * 84 + be32(512) + be32(1) + be32(512) + b"\x41" * 512,
)

write_call = v3_call_raw(
    0x40000002, 7, FH + be64(0) + be32(8192) + be32(2) + be32(8192) + b"\x42" * 8192
)
write_res = v3_reply_raw(
    0x40000002, be32(0) + b"\x00" * 16 + be64(0)  # status + wcc(16) + ctime
)

p = Pcap(os.path.join(os.path.dirname(os.path.abspath(__file__)), "input.pcap"))
p.udp(CLIENT, SERVER, v3_call_raw(0x40000000, 19, fsinfo_args))
p.udp(SERVER, CLIENT, v3_reply_raw(0x40000000, fsinfo_res))
p.udp(CLIENT, SERVER, write_call)
p.udp(SERVER, CLIENT, write_res)
p.udp(CLIENT, SERVER, read_call)
p.udp(SERVER, CLIENT, read_res)
p.close()
