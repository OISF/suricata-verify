#!/usr/bin/env python3
"""Generate input.pcap for tests/nfs4-gss-privacy-partial.

One flow. A PUTFH+GETATTR compound and its reply come first, then a
PUTFH+REMOVE call that is never answered, so a live transaction is around to be
stamped by accident. Then 3 x 9 RPCSEC_GSS DATA/privacy (proc 0, service 3)
COMPOUND calls with a 6000-byte encrypted body and the matching replies, in
three shapes that each take a different code path:

  0x300+  call split over two segments, reply split over two segments
  0x400+  call whole, reply split over two segments
  0x500+  call whole, reply whole

Large krb5p WRITE calls and READ replies look like the first two on the wire.

Regenerate: python3 gen.py (deterministic, no dependencies).
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nfs_sv_common import Pcap, be32, be64, null_verf, unix_cred, gss_cred  # noqa: E402

CLIENT = ("10.0.0.1", 871)
SERVER = ("10.0.0.2", 2049)
FH = b"\x01" * 16
SPLIT = 3000


def rec(body):
    return struct.pack(">I", (1 << 31) | len(body)) + body


def call(xid, cred, prog):
    return rec(be32(xid) + be32(0) + be32(2) + be32(100003) + be32(4) + be32(1)
               + cred + null_verf() + prog)


def reply(xid, prog):
    return rec(be32(xid) + be32(1) + be32(0) + null_verf() + be32(0) + prog)


def compound(ops):
    return be32(0) + be32(0) + be32(len(ops)) + b"".join(ops)


putfh = be32(22) + be32(len(FH)) + FH
getattr_ = be32(9) + be32(2) + be32(0x10) + be32(0)
remove = be32(28) + be32(4) + b"newf"
blob = bytes((i * 7 + 3) & 0xff for i in range(6000))   # stands in for ciphertext

p = Pcap(os.path.join(os.path.dirname(os.path.abspath(__file__)), "input.pcap"))
p.tcp(CLIENT, SERVER, syn=True)
p.tcp(SERVER, CLIENT, synack=True)
p.tcp(CLIENT, SERVER, pure_ack=True)
p.tcp(CLIENT, SERVER, payload=call(0x100, unix_cred(), compound([putfh, getattr_])))
p.tcp(SERVER, CLIENT,
      payload=reply(0x100, compound([be32(22) + be32(0), be32(9) + be32(0)
                                     + be32(2) + be32(0x10) + be32(0) + be32(8) + be64(4096)])))
p.tcp(CLIENT, SERVER, payload=call(0x200, unix_cred(), compound([putfh, remove])))
for base, split_call, split_reply in ((0x300, True, True), (0x400, False, True),
                                      (0x500, False, False)):
    for i in range(3):
        c = call(base + i, gss_cred(0, 3), be32(len(blob)) + blob)
        rp = reply(base + i, be32(len(blob)) + blob)
        if split_call:
            p.tcp(CLIENT, SERVER, payload=c[:SPLIT])
            p.tcp(SERVER, CLIENT, pure_ack=True)
            p.tcp(CLIENT, SERVER, payload=c[SPLIT:])
        else:
            p.tcp(CLIENT, SERVER, payload=c)
        if split_reply:
            p.tcp(SERVER, CLIENT, payload=rp[:SPLIT])
            p.tcp(CLIENT, SERVER, pure_ack=True)
            p.tcp(SERVER, CLIENT, payload=rp[SPLIT:])
        else:
            p.tcp(SERVER, CLIENT, payload=rp)
        p.tcp(CLIENT, SERVER, pure_ack=True)
p.close()
