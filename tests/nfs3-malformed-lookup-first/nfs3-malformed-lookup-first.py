#!/usr/bin/env python3
"""Generate the nfs3-malformed-lookup-first fixture.

LOOKUP has its own request parse, which raised malformed_data on "the last
transaction": none on the first record of a flow, so the event was dropped.
This fixture makes the malformed LOOKUP the first record of the session.

Two v3 CALLs on a TCP session to 2049: a LOOKUP whose args are 3 bytes (a
dirpath3 needs a 32 byte handle plus a name), then an FSSTAT that parses, so
the anomaly is about the argument and not the transport.
"""
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                               "nfs-tcp-record-mark-overflow"))
from nfs_sv_common import Pcap, be32, null_verf, unix_cred

CLIENT = ("192.168.7.10", 832)
SERVER = ("192.168.7.20", 2049)


def call(xid, proc, args):
    return (
        be32(xid) + be32(0) + be32(2) + be32(100003) + be32(3) + be32(proc)
        + unix_cred() + null_verf() + args
    )


# NFSPROC3_LOOKUP is 3; a dirpath3 is a nfspath3, so 3 bytes cannot carry the
# name length let alone the handle.
bad = call(0x5A5A0001, 3, b"\x00\x00\x00")
# NFSPROC3_FSSTAT is 18, a bare filehandle; it is logged even by the default
# procedure filter, unlike GETATTR.
good = call(0x5A5A0002, 18, be32(32) + bytes(range(32)))

p = Pcap(os.path.join(os.path.dirname(os.path.abspath(__file__)), "input.pcap"))
p.tcp(CLIENT, SERVER, syn=True)
p.tcp(SERVER, CLIENT, synack=True)
p.tcp(CLIENT, SERVER)
for rec in (bad, good):
    p.tcp(CLIENT, SERVER, struct.pack(">I", (1 << 31) | len(rec)) + rec)
p.close()
