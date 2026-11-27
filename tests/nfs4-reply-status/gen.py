"""Generate input.pcap: two NFSv4 reply-status cases.

Flow A - PUTFH+WRITE+GETATTR answered WRITE=NFS4_OK, GETATTR=NFS4ERR_IO. The
compound opens a WRITE file transaction; the trailing GETATTR must not replace
the write's own result.

Flow B - a successful exchange, then a CLOSE answered MSG_ACCEPTED with
accept_stat GARBAGE_ARGS. That reply carries no NFS body: the transaction has
to finish with no NFS status instead of raising malformed_data and staying open.
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nfs_sv_common import Pcap, be32, be64, v3_call, v3_fh


def opaque(x):
    return be32(len(x)) + x + b"\x00" * ((-len(x)) % 4)


def rpc_call(xid, ver, proc, args):
    return b"".join(be32(v) for v in (xid, 0, 2, 100003, ver, proc, 0, 0, 0, 0)) + args


def rpc_reply(xid, body, accept=0):
    return b"".join(be32(v) for v in (xid, 1, 0, 0, 0, accept)) + body


def record(b):
    return be32(0x80000000 | len(b)) + b


FH = opaque(b"0123456789abcdef")
PUTFH = be32(22) + FH
WRITE = be32(38) + be32(1) + b"\x02" * 12 + be64(0) + be32(0) + opaque(b"data")
GETATTR = be32(9) + be32(1) + be32(2)
CLOSE = be32(4) + be32(1) + be32(1) + b"\x02" * 12

# flow A: WRITE ok, GETATTR io
a_args = be32(0) + be32(0) + be32(3) + PUTFH + WRITE + GETATTR
a_res = (
    be32(5) + be32(0) + be32(3)
    + (be32(22) + be32(0))
    + (be32(38) + be32(0) + be32(4) + be32(0) + b"\x11" * 8)
    + (be32(9) + be32(5))
)

# flow B: a good CLOSE, then a CLOSE rejected at the RPC level
b_args = be32(0) + be32(0) + be32(2) + PUTFH + CLOSE
b_good = (
    be32(0) + be32(0) + be32(2)
    + (be32(22) + be32(0))
    + (be32(4) + be32(0) + be32(1) + b"\x02" * 12)
)


STATEID4 = be32(1) + b"\x02" * 12
READ_OP = be32(25) + STATEID4 + be64(0) + be32(4)


def flow(p, client_port, steps):
    cli, srv = ("10.1.1.1", client_port), ("10.1.1.2", 2049)
    p.tcp(cli, srv, syn=True)
    p.tcp(srv, cli, synack=True)
    for d, payload in steps:
        if d == "c":
            p.tcp(cli, srv, payload=payload)
        else:
            p.tcp(srv, cli, payload=payload)
            p.tcp(cli, srv, pure_ack=True)


def main():
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "input.pcap")
    p = Pcap(out)
    flow(p, 941, [("c", record(rpc_call(1, 4, 1, a_args))),
                  ("s", record(rpc_reply(1, a_res)))])
    flow(p, 942, [("c", record(rpc_call(99, 4, 1, b_args))),
                  ("s", record(rpc_reply(99, b_good))),
                  ("c", record(rpc_call(2, 4, 1, b_args))),
                  ("s", record(rpc_reply(2, b"", 4)))])

    # flow C: the same displacement for a READ: READ ok, trailing GETATTR io
    c_args = be32(0) + be32(0) + be32(3) + PUTFH + READ_OP + GETATTR
    c_res = (
        be32(6) + be32(0) + be32(3)
        + (be32(22) + be32(0))
        + (be32(25) + be32(0) + be32(1) + opaque(b"data"))
        + (be32(9) + be32(5))
    )
    flow(p, 943, [("c", record(rpc_call(3, 4, 1, c_args))),
                  ("s", record(rpc_reply(3, c_res)))])

    # flow D: v3 call answered PROG_MISMATCH, which carries the version range
    # in the body - it must not be read as NFS data
    d_args = v3_fh(0x51) + be32(5) + b"cfile" + b"\x00" * 3
    # v3_call() already carries the record mark and rpc_reply() writes
    # reply_stat and accept_stat itself, so the body here is only mismatch_info
    # (low, high). A good LOOKUP first lets the to-client probe see an accepted
    # reply, as a real exchange would.
    d_ok = be32(0) + v3_fh(0x52) + be32(0) + be32(0)
    d_res = be32(4) + be32(4)
    flow(p, 944, [("c", v3_call(5, 3, d_args)),
                  ("s", record(rpc_reply(5, d_ok))),
                  ("c", v3_call(4, 3, d_args)),
                  ("s", record(rpc_reply(4, d_res, 2)))])
    p.close()


if __name__ == "__main__":
    main()
