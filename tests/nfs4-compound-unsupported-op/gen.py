#!/usr/bin/env python3
"""Generate input.pcap for tests/nfs4-compound-unsupported-op.

One NFSv4.0 flow: a PUTFH+GETATTR COMPOUND, then five well-formed
COMPOUND {PUTFH, LOCK} calls (RFC 7530 LOCK4args, exist_lock_owner), each
answered with NFS4_OK. LOCK is a defined op the request parser does not
implement, so the compound is valid traffic that is merely not parsed.

Regenerate: python3 gen.py (deterministic, no dependencies).
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nfs_sv_common import Pcap, be32, be64, null_verf, unix_cred

CLIENT = ("10.0.0.1", 870)
SERVER = ("10.0.0.2", 2049)
FH = b"\x01" * 16


def rec(body):
    return struct.pack(">I", (1 << 31) | len(body)) + body


def call(xid, prog):
    # xid, CALL, rpcvers 2, NFS, v4, COMPOUND, AUTH_UNIX, NULL verifier, args
    return rec(be32(xid) + be32(0) + be32(2) + be32(100003) + be32(4) + be32(1)
               + unix_cred() + null_verf() + prog)


def reply(xid, prog):
    # xid, REPLY, MSG_ACCEPTED, NULL verifier, SUCCESS, results
    return rec(be32(xid) + be32(1) + be32(0) + null_verf() + be32(0) + prog)


def args(ops):
    return be32(0) + be32(0) + be32(len(ops)) + b"".join(ops)   # tag "", minor 0


def res(ops):
    return be32(0) + be32(0) + be32(len(ops)) + b"".join(ops)   # NFS4_OK, tag ""


putfh = be32(22) + be32(len(FH)) + FH
getattr_ = be32(9) + be32(2) + be32(0x10) + be32(0)             # bitmap: size
lock = (be32(12) + be32(2) + be32(0) + be64(0) + be64(4096)     # WRITE_LT, no reclaim
        + be32(0)                                                # exist_lock_owner
        + be32(1) + b"\x02" * 12 + be32(1))                      # lock_stateid, seqid
putfh_res = be32(22) + be32(0)
getattr_res = be32(9) + be32(0) + be32(2) + be32(0x10) + be32(0) + be32(8) + be64(4096)
lock_res = be32(12) + be32(0) + be32(1) + b"\x03" * 12          # LOCK4_OK + stateid

p = Pcap(os.path.join(os.path.dirname(os.path.abspath(__file__)), "input.pcap"))
p.tcp(CLIENT, SERVER, syn=True)
p.tcp(SERVER, CLIENT, synack=True)
p.tcp(CLIENT, SERVER, pure_ack=True)
p.tcp(CLIENT, SERVER, payload=call(0x100, args([putfh, getattr_])))
p.tcp(SERVER, CLIENT, payload=reply(0x100, res([putfh_res, getattr_res])))
for i in range(5):
    p.tcp(CLIENT, SERVER, payload=call(0x200 + i, args([putfh, lock])))
    p.tcp(SERVER, CLIENT, payload=reply(0x200 + i, res([putfh_res, lock_res])))
p.close()
