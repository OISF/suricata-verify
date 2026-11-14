"""Fixture for nfs3-write-chunk-status.

One v3 WRITE split into two chunks, in the orders a client can use, plus a
flow where two writes to one handle are in flight together. A write can be
answered by more than one reply, so the status a record reports has to be
chosen: it is the first error any reply carried, and otherwise the status of
the first reply that carried one. A later OK must not hide an earlier
rejection, and a later rejection must not be hidden by an earlier accept.

  flow A (sport 941, fhA) call1 off 0, reply ERR_IO, call2 off 64, reply OK
  flow B (sport 942, fhB) call1, call2, reply ERR_IO, reply OK
  flow C (sport 943, fhC) call1 off 0, reply OK, call2 off 64, reply ERR_NOSPC
  flow D (sport 944, fhD) call1, call2, reply OK, reply ERR_NOSPC
  flow E (sport 945, fhE) call1 FILE_SYNC off 0, call2 UNSTABLE off 64,
                          reply1 ERR_IO, reply2 OK

Flows A and B are the order a Linux client normally uses and the one that was
broken first: the reply path matched a WRITE reply to the file transaction by
the xid of the last chunk sent, so once chunk 2 was on the wire a reply to
chunk 1 found nothing.

Flow E is two transactions, not two chunks. The FILE_SYNC write is complete
and logged from its request, so the reply to it has nothing left to land on;
what must not happen is that its error moves onto the UNSTABLE write, which
its own reply accepted.

WRITE3res carries wcc_data in both the accepted and the failed form, so the
replies here do too; leaving it out reads as a malformed packet to tshark.
The count in an accepted UNSTABLE write is what reached stable storage, so 0.

Regenerate: python3 gen.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nfs_sv_common import Pcap, be32, be64, v3_call, v3_fh, v3_reply

PROC_WRITE = 7
UNSTABLE, FILE_SYNC = 0, 2
NFS3ERR_IO, NFS3ERR_NOSPC = 5, 28
SRC, SRV = "192.168.1.10", "192.168.1.20"
CHUNK = b"A" * 64
FHA = v3_fh(0x51)
FHB = v3_fh(0x52)
FHC = v3_fh(0x53)
FHD = v3_fh(0x54)
FHE = v3_fh(0x55)


def write_call(xid, fh, off, stable=UNSTABLE):
    return v3_call(
        xid, PROC_WRITE,
        fh + be64(off) + be32(len(CHUNK)) + be32(stable) + be32(len(CHUNK)) + CHUNK,
    )


def wcc():
    # wcc_data with no attributes before or after the call
    return be32(0) + be32(0)


def write_ok(stable=UNSTABLE):
    return be32(0) + wcc() + be32(0) + be32(stable) + b"\x11" * 8


def err(status):
    return be32(status) + wcc()


p = Pcap(os.path.join(os.path.dirname(os.path.abspath(__file__)), "input.pcap"))
a_cli, b_cli, c_cli, d_cli, e_cli, srv = (
    (SRC, 941), (SRC, 942), (SRC, 943), (SRC, 944), (SRC, 945), (SRV, 2049),
)


def handshake(cli):
    p.tcp(cli, srv, syn=True)
    p.tcp(srv, cli, synack=True)


# flow A: the two chunks answered in the order they were sent
handshake(a_cli)
p.tcp(a_cli, srv, payload=write_call(1, FHA, 0))
p.tcp(srv, a_cli, payload=v3_reply(1, err(NFS3ERR_IO)))
p.tcp(a_cli, srv, payload=write_call(2, FHA, 64))
p.tcp(srv, a_cli, payload=v3_reply(2, write_ok()))

# flow B: both chunks out before either reply
handshake(b_cli)
p.tcp(b_cli, srv, payload=write_call(1, FHB, 0))
p.tcp(b_cli, srv, payload=write_call(2, FHB, 64))
p.tcp(srv, b_cli, payload=v3_reply(1, err(NFS3ERR_IO)))
p.tcp(srv, b_cli, payload=v3_reply(2, write_ok()))

# flow C: accepted first, rejected second, in order
handshake(c_cli)
p.tcp(c_cli, srv, payload=write_call(1, FHC, 0))
p.tcp(srv, c_cli, payload=v3_reply(1, write_ok()))
p.tcp(c_cli, srv, payload=write_call(2, FHC, 64))
p.tcp(srv, c_cli, payload=v3_reply(2, err(NFS3ERR_NOSPC)))

# flow D: the same, pipelined
handshake(d_cli)
p.tcp(d_cli, srv, payload=write_call(1, FHD, 0))
p.tcp(d_cli, srv, payload=write_call(2, FHD, 64))
p.tcp(srv, d_cli, payload=v3_reply(1, write_ok()))
p.tcp(srv, d_cli, payload=v3_reply(2, err(NFS3ERR_NOSPC)))

# flow E: a FILE_SYNC write and an UNSTABLE write to the same handle
handshake(e_cli)
p.tcp(e_cli, srv, payload=write_call(1, FHE, 0, FILE_SYNC))
p.tcp(e_cli, srv, payload=write_call(2, FHE, 64))
p.tcp(srv, e_cli, payload=v3_reply(1, err(NFS3ERR_IO)))
p.tcp(srv, e_cli, payload=v3_reply(2, write_ok()))

p.close()
