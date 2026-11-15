#!/usr/bin/env python3
"""Generate input.pcap for tests/nfs-read-overlap.

Two NFSv3 READ calls to one handle. The first, offset 0 count 100, comes back
with 100 bytes and no eof, so the file transaction stays open with 100 bytes
tracked. The second asks for offset 50, inside what the tracker already holds:
that is file_overlap on the read path, the same rule the write path applies.
Regenerate: python3 gen.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nfs_sv_common import Pcap, be32, be64, v3_call, v3_fh, v3_reply  # noqa: E402

PROC_READ = 6
CLIENT = "192.168.1.10"
SERVER = "192.168.1.20"

FH = v3_fh(0xCD)


def read_call(xid, offset, count):
    # READ3args: file, offset64, count
    return v3_call(xid, PROC_READ, FH + be64(offset) + be32(count))


def read_reply(xid, data, count, eof, status=0):
    # READ3resok: status, wcc_data (absent), count, eof, data (opaque)
    return v3_reply(
        xid,
        be32(status)
        + be32(0)
        + be32(count)
        + be32(eof)
        + be32(len(data))
        + data
        + b"\x00" * ((-len(data)) % 4),
    )


p = Pcap(os.path.join(os.path.dirname(os.path.abspath(__file__)), "input.pcap"))
cli, srv = (CLIENT, 6642), (SERVER, 2049)
p.tcp(cli, srv, syn=True)
p.tcp(srv, cli, synack=True)
p.tcp(cli, srv, payload=read_call(0x5B000001, 0, 100))
p.tcp(srv, cli, payload=read_reply(0x5B000001, b"A" * 100, 100, 0))
p.tcp(cli, srv, payload=read_call(0x5B000002, 50, 50))
p.tcp(srv, cli, payload=read_reply(0x5B000002, b"B" * 50, 50, 1))
p.close()
