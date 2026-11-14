"""Fixture for nfs3-write-chunk-status.

One v3 WRITE split into two UNSTABLE chunks, in both orders a client can use.
The 9.0 upgrade note says a write is logged with the status of the first reply
record that carries one, so a rejected chunk must not be hidden by a later
accepted one. Two flows, one per order, so a single capture shows both.

  flow A (sport 941, fhA)  call xid 1 (off 0), reply ERR_IO,
                           call xid 2 (off 64), reply OK
  flow B (sport 942, fhB)  call xid 1 (off 0), call xid 2 (off 64),
                           reply ERR_IO, reply OK

Pipelining is what a Linux client normally does, and it used to be the broken
order: the reply path matched a WRITE reply to the file transaction by the xid
of the last chunk sent, so once chunk 2 was on the wire a reply to chunk 1
found nothing, and the OK to chunk 2 overwrote nothing. Logged as OK/0 while
the fileinfo for the same transaction still said ERR_IO.

Regenerate: python3 gen.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nfs_sv_common import Pcap, be32, be64, v3_call, v3_fh, v3_reply

PROC_WRITE = 7
UNSTABLE = 0
NFS3ERR_IO = 5
SRC, SRV = "192.168.1.10", "192.168.1.20"
CHUNK = b"A" * 64
FHA = v3_fh(0x51)
FHB = v3_fh(0x52)


def write_call(xid, fh, off):
    return v3_call(
        xid, PROC_WRITE,
        fh + be64(off) + be32(len(CHUNK)) + be32(UNSTABLE) + be32(len(CHUNK)) + CHUNK,
    )


def write_ok():
    # WRITE3resok: count is what reached stable storage, so 0 for an UNSTABLE
    # write, then committed and the 8-byte writeverf. A non-zero count makes
    # tshark look for reply data that no server sends.
    return be32(0) + be32(0) + be32(UNSTABLE) + b"\x11" * 8


def err():
    return be32(NFS3ERR_IO)


p = Pcap(os.path.join(os.path.dirname(os.path.abspath(__file__)), "input.pcap"))
a_cli, b_cli, srv = (SRC, 941), (SRC, 942), (SRV, 2049)

# flow A: the two chunks answered in the order they were sent
p.tcp(a_cli, srv, syn=True)
p.tcp(srv, a_cli, synack=True)
p.tcp(a_cli, srv, payload=write_call(1, FHA, 0))
p.tcp(srv, a_cli, payload=v3_reply(1, err()))
p.tcp(a_cli, srv, payload=write_call(2, FHA, 64))
p.tcp(srv, a_cli, payload=v3_reply(2, write_ok()))

# flow B: both chunks out before either reply
p.tcp(b_cli, srv, syn=True)
p.tcp(srv, b_cli, synack=True)
p.tcp(b_cli, srv, payload=write_call(1, FHB, 0))
p.tcp(b_cli, srv, payload=write_call(2, FHB, 64))
p.tcp(srv, b_cli, payload=v3_reply(1, err()))
p.tcp(srv, b_cli, payload=v3_reply(2, write_ok()))

p.close()
