#!/usr/bin/env python3
"""Generate the nfs2-udp-write fixture.

A v2 WRITE over unmarked UDP (the v2 probe is UDP-only, so the
fixture uses the tshark-valid unmarked form) in the RFC 1094 shape:
raw 32-byte file handle, beginoffset/offset/totalcount words and the
XDR-opaque file data (length-prefixed, 8 words shorter than the v3
write args). Before the extent/parser fixes the shared write path
applied the v3 formula (fh_len + 24 + file_len) to the v2 record and
read the data without the XDR length word, so a v2 WRITE desynced the
record walk and the file was rejected as malformed instead of
logged. A preceding LOOKUP pins the v2 reply path (its plain tx is
logged at flow end, after the reply set the state version).
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nfs_sv_common import Pcap, be32, be64

CLIENT = ("192.168.1.6", 939)
SERVER = ("192.168.1.2", 2049)
FH = b"\x5A" * 32
XID = 0x70000001
DATA = b"\x43" * 512


def call_raw(xid, proc, prog_data):
    # unmarked v2 call: AUTH_NULL (type 0, zero length, no body word)
    return (
        be32(xid) + be32(0) + be32(2) + be32(100003) + be32(2) + be32(proc)
        + be32(0) + be32(0) + be32(0) + be32(0) + prog_data
    )


def reply_raw(xid, prog_data):
    return be32(xid) + be32(1) + be32(0) + be32(0) + be32(0) + be32(0) + prog_data


# v2 WRITE args (RFC 1094): fh(32) + beginoffset + offset + totalcount +
# data length (XDR opaque) + data
prog_data = FH + be32(0) + be32(0) + be32(len(DATA)) + be32(len(DATA)) + DATA
write_call = call_raw(XID, 8, prog_data)

# v2 fattr2: 11 words + atime/mtime/ctime nfstime2 (tshark's model of
# the v2 attribute blob)
FATTR2 = (
    be32(1) + be32(0x81A4) + be32(1) + be32(1000) + be32(1000)
    + be32(len(DATA)) + be32(0) + be32(0) + be32(0) + be32(0) + be32(0)
    + be32(1_000_000_000) + be32(0)
    + be32(1_000_000_000) + be32(0)
    + be32(0) + be32(0)
)


# a preceding LOOKUP (proc 4): its tx is a plain tx (logged at flow end,
# after the reply set the state version), so it also pins the v2 reply
# path; the WRITE file tx itself finalizes at request time (stable=2)
ROOT = b"\x01" * 32
NAME = b"cfile"
lookup_call = call_raw(
    XID - 1, 4, ROOT + be32(len(NAME)) + NAME + b"\x00" * ((-len(NAME)) % 4)
)
lookup_reply = reply_raw(XID - 1, be32(0) + FH + FATTR2)
# v2 WRITE reply: tshark models the v2 reply as status + fattr2 +
# cookieverf + count; Suricata's reply path reads only the status, so
# the full shape keeps both dissections clean
write_reply = reply_raw(XID, be32(0) + FATTR2 + be64(0) + be32(len(DATA)))

p = Pcap(os.path.join(os.path.dirname(os.path.abspath(__file__)), "input.pcap"))
p.udp(CLIENT, SERVER, lookup_call)
p.udp(SERVER, CLIENT, lookup_reply)
p.udp(CLIENT, SERVER, write_call)
p.udp(SERVER, CLIENT, write_reply)
p.close()
print("extent", 48 + len(DATA))
