"""Fixture for nfs3-detect-off-port.

NFSv3 over TCP on a port outside the default port set must still be detected:
no port based probing parser covers it, only the record-marking pattern probe
(to-server), which runs the full probe to confirm the NFS program number.

The second flow is mountd (program 100005) on another odd port: a well formed
record marked ONC RPC CALL whose program number is not NFS, so it must not be
claimed as NFS.

  c->s 10.0.0.10:50000 -> 10.0.0.11:4040  GETATTR, WRITE(64), READ(64)
  s->c 10.0.0.11:4040  -> 10.0.0.10:50000 replies
  c->s 10.0.0.10:50001 -> 10.0.0.11:4041  mountd MNT "/export"
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nfs_sv_common import (
    Pcap,
    be32,
    be64,
    fh3p,
    null_verf,
    rpc_record,
    unix_cred,
    v3_call,
    v3_fh,
    v3_reply,
)

PROC_GETATTR, PROC_READ, PROC_WRITE = 1, 6, 7
SRC, SRV = "10.0.0.10", "10.0.0.11"
NFS_PORT = 4040
MNT_PORT = 4041
RAW_PORT = 4042
DATA = bytes([i & 0xFF for i in range(64)])

FH1 = v3_fh(1)
FH2 = v3_fh(2)


def write_call(xid, fh, offset, data, stable=0):
    return v3_call(
        xid, PROC_WRITE,
        fh + be64(offset) + be32(len(data)) + be32(stable) + be32(len(data)) + data,
    )


def read_call(xid, fh, offset, count):
    return v3_call(xid, PROC_READ, fh + be64(offset) + be32(count))


def read_reply(xid, data, status=0):
    return v3_reply(
        xid,
        be32(status) + be32(0) + be32(len(data)) + be32(1) + be32(len(data)) + data
        + b"\x00" * ((-len(data)) % 4),
    )


p = Pcap(os.path.join(os.path.dirname(os.path.abspath(__file__)), "input.pcap"))
nfs = (SRC, 50000), (SRV, NFS_PORT)
mnt = (SRC, 50001), (SRV, MNT_PORT)
p.tcp(*nfs, syn=True)
p.tcp(*nfs[::-1], synack=True)
p.tcp(*mnt, syn=True)
p.tcp(*mnt[::-1], synack=True)

p.tcp(*nfs, payload=v3_call(1, PROC_GETATTR, FH1))
p.tcp(*nfs[::-1], payload=v3_reply(1, be32(0)))
p.tcp(*nfs, payload=write_call(2, FH2, 0, DATA))
p.tcp(*nfs[::-1], payload=v3_reply(2, be32(0) + be32(len(DATA)) + be32(0)))
p.tcp(*nfs, payload=read_call(3, FH2, 0, len(DATA)))
p.tcp(*nfs[::-1], payload=read_reply(3, DATA))

body = (
    be32(9) + be32(0) + be32(0) + be32(100005) + be32(3) + be32(1)
    + unix_cred() + null_verf() + fh3p(b"/export")
)
p.tcp(*mnt, payload=rpc_record(body))
p.tcp(*mnt[::-1], payload=v3_reply(9, be32(0)))

# a stream that opens like a record marked call but carries no RPC call
# header: protocol detection has to finish for it, not stay pending
raw = (SRC, 50002), (SRV, RAW_PORT)
p.tcp(*raw, syn=True)
p.tcp(*raw[::-1], synack=True)
p.tcp(*raw, payload=b"\x80\x00\x01\x02" + b"\x11" * 20)
p.tcp(*raw[::-1], payload=b"\x80\x00\x01\x02" + b"\x22" * 20)

p.close()
