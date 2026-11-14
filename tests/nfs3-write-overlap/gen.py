#!/usr/bin/env python3
"""Generate input.pcap for tests/nfs3-write-overlap.

Two NFSv3 WRITE calls to one handle, both UNSTABLE so a single file
transaction stays open across them: offset 0 with 100 bytes of A, then offset
50 with 50 bytes of B. The second starts inside the region the tracker already
holds, which is file_overlap; the v3 path raised it all along and this pins it
against the v4 one, which had to be taught to agree. Only requests are needed,
so the capture carries no replies and the records close with the flow.

Regenerate: python3 gen.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nfs_sv_common import Pcap, be32, be64, v3_call, v3_fh, v3_reply  # noqa: E402

PROC_WRITE = 7
CLIENT = "192.168.1.10"
SERVER = "192.168.1.20"

FH = v3_fh(0xAB)


def write_call(xid, offset, data, stable):
    # WRITE3args: file, offset64, count, stable_how, data (opaque)
    return v3_call(
        xid,
        PROC_WRITE,
        FH
        + be64(offset)
        + be32(len(data))
        + be32(stable)
        + be32(len(data))
        + data
        + b"\x00" * ((-len(data)) % 4),
    )


def wcc():
    # wcc_data with no attributes before or after the call
    return be32(0) + be32(0)


def write_reply(xid):
    # WRITE3resok: status, wcc_data, count, committed, writeverf. UNSTABLE
    # reports count 0 because nothing is on stable storage yet.
    return v3_reply(xid, be32(0) + wcc() + be32(0) + be32(0) + b"\x11" * 8)


p = Pcap(os.path.join(os.path.dirname(os.path.abspath(__file__)), "input.pcap"))
cli, srv = (CLIENT, 6641), (SERVER, 2049)
p.tcp(cli, srv, syn=True)
p.tcp(srv, cli, synack=True)
p.tcp(cli, srv, payload=write_call(0x5A000001, 0, b"A" * 100, 0))
p.tcp(srv, cli, payload=write_reply(0x5A000001))
p.tcp(cli, srv, payload=write_call(0x5A000002, 50, b"B" * 50, 0))
p.tcp(srv, cli, payload=write_reply(0x5A000002))
p.close()
