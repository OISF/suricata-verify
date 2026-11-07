#!/usr/bin/env python3
"""Generate the nfs2-malformed-arg-first fixture.

The v2 request path wired file identity with the same
last-transaction event call as v3 had, so a malformed argument on the first
record of a flow was dropped. Same shape as the v3 test, in the v2 procedure
space (RFC 1094 5.2: LOOKUP is 4, READLINK is 5).

Two v2 CALLs and their replies over UDP to 2049 (the TCP probe only accepts
program version 3 and 4, as it does on main, so v2 needs UDP): a LOOKUP whose
args are 3 bytes, then a READLINK with a full 32 byte fhandle2. Both replies
carry an error status, which is all the parser needs to complete them.
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
        be32(xid) + be32(0) + be32(2) + be32(100003) + be32(2) + be32(proc)
        + unix_cred() + null_verf() + args
    )


# NFSPROC2_LOOKUP is 4
bad = call(0x5A5A0001, 4, b"\x00\x00\x00")
# NFSPROC2_READLINK is 5, argument is a fixed 32 byte fhandle2.
good = call(0x5A5A0002, 5, bytes(range(32)))

def reply(xid, status):
    # reply header has no rpcvers word: xid, msgtype=1, reply_stat=0,
    # null verifier, accept_stat=0, then the NFS status
    return be32(xid) + be32(1) + be32(0) + null_verf() + be32(0) + be32(status)


p = Pcap(os.path.join(os.path.dirname(os.path.abspath(__file__)), "input.pcap"))
p.udp(CLIENT, SERVER, bad)
p.udp(SERVER, CLIENT, reply(0x5A5A0001, 2))  # NFS2ERR_NOENT
p.udp(CLIENT, SERVER, good)
p.udp(SERVER, CLIENT, reply(0x5A5A0002, 2))
p.close()
