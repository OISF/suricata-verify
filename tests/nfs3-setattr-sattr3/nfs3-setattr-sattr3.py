#!/usr/bin/env python3
"""Generate the nfs3-setattr-sattr3 fixture.

A v3 CREATE (UNCHECKED) resolving "cfile" with a full RFC 1813
CREATE3resok reply, then a SETATTR on the created handle using the
RFC 1813 3.2.4 sattr3 layout: no mode/uid/gid/size, atime
SET_TO_CLIENT_TIME (the 8-byte nfstime3 rides inside the set_atime
union), mtime SET_TO_SERVER_TIME, guard unchecked. Before the sattr3
layout fix the union was parsed as flat bool-flagged words, so a
client-time update desynced the record walk and the SETATTR fileinfo
carried no filename.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nfs_sv_common import Pcap, be32, be64, fh3p, v3_fh, v3_call_raw, v3_reply_raw

CLIENT = ("192.168.1.6", 939)
SERVER = ("192.168.1.2", 2049)
ROOT = v3_fh(0x01)
FH = v3_fh(0x5A)
NAME = b"cfile"
FATTR = b"\x00" * 84


def wcc_full():
    # pre_op_attr (attrs unset) + post_op_attr (attrs set, fattr3)
    return be32(0) + be32(0) + be32(0) + be32(1) + FATTR


# CREATE3args (proc 8, UNCHECKED): diropargs3 + createhow3
create_call = v3_call_raw(
    0x50000001,
    8,
    ROOT + fh3p(NAME) + be32(0) * 7,  # UNCHECKED + empty sattr3
)
# CREATE3resok: status + created (FILE_CHANGE: the handle follows) +
# fh + wcc_data + fattr3
create_res = v3_reply_raw(
    0x50000001, be32(0) + be32(1) + FH + be32(0) + be32(0) + be32(1) + FATTR,
)

# SETATTR3args (RFC 1813 3.3.14, proc 2): fh + sattr3 + sattrguard3.
# sattr3: mode/uid/gid/size unset; atime how 2 + nfstime3; mtime how 1.
sattr3 = (
    be32(0)  # mode unset
    + be32(0)  # uid unset
    + be32(0)  # gid unset
    + be32(0)  # size unset
    + be32(2) + be32(1_000_000_000) + be32(0)  # atime: client nfstime3
    + be32(1)  # mtime: server time
)
guard = be32(0)  # sattrguard3: no check
setattr_call = v3_call_raw(0x50000002, 2, FH + sattr3 + guard)
# SETATTR3resok: status + wcc_data
setattr_res = v3_reply_raw(0x50000002, be32(0) + wcc_full())

p = Pcap(os.path.join(os.path.dirname(os.path.abspath(__file__)), "input.pcap"))
p.udp(CLIENT, SERVER, create_call)
p.udp(SERVER, CLIENT, create_res)
p.udp(CLIENT, SERVER, setattr_call)
p.udp(SERVER, CLIENT, setattr_res)
p.close()
print("sattr3 len", len(sattr3) + len(guard))
