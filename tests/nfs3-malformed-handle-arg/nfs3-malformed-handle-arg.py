#!/usr/bin/env python3
"""Generate the nfs3-malformed-handle-arg fixture.

The v3 procedures that take a bare filehandle (READ, READLINK, READDIR,
FSSTAT, FSINFO, PATHCONF) wire the handle into the transaction so the record
carries hhash and the resolved name. When the argument is too short to hold
even the 4 byte handle length, the parse has to fail and raise
malformed_data instead of wiring a zero-length handle.

Two v3 CALLs on a TCP session to 2049: a READLINK whose args are 2 bytes,
then an FSSTAT that works, so the session is clearly live and the malformed
one is not an artefact of the transport.
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


# NFSPROC3_READLINK is 5; the argument is a filehandle3, so 2 bytes cannot
# even carry the handle length.
bad = call(0x5A5A0001, 5, b"\x00\x00")
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
