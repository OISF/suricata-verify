#!/usr/bin/env python3
"""Generate the nfs4-gss-none-write fixture.

A v4 COMPOUND WRITE request with RPCSEC_GSS credentials
(procedure 0, service 1 = rpc_gss_svc_none): the data is not
wrapped, the raw compound is the prog_data. The record claims
20 MiB (above the 16 MiB default max-write-size) and arrives
segmented: the partial scan must scan the raw compound (no
envelope) and reject the claim. Before the service-none fix the
(0, 1) combination hit the scanner's catch-all and the record was
discarded as malformed instead of rejected with the size event.
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nfs_sv_common import Pcap, be32, be64, fh3, gss_cred

CLIENT = ("192.168.1.6", 939)
SERVER = ("192.168.1.2", 2049)
XID = 0x31000001
WRITE_LEN = 20 * 1024 * 1024

# compound: tag + minorversion + ops_cnt + PUTFH + WRITE (prefix only;
# the record claim covers the full WRITE_LEN data)
prog_prefix = (
    fh3(b"")  # tag (len 0)
    + be32(0)  # minorversion
    + be32(2)  # ops_cnt
    + be32(22)  # PUTFH
    + fh3(bytes(range(32)))  # fh32
    + be32(38)  # WRITE
    + be32(1) + b"\x00" * 12  # stateid
    + be64(0)  # offset
    + be32(1)  # stable
    + be32(WRITE_LEN)  # count
    + be32(WRITE_LEN)  # data length
    + b"\x00" * 32  # start of data
)
gss = gss_cred(0, 1)  # procedure 0, service none
header = (
    be32(XID) + be32(0) + be32(2) + be32(100003) + be32(4) + be32(1)
    + gss + be32(0) + be32(0)
)
# full claim: header + the whole write data (20 MiB)
claim = len(header) + (len(prog_prefix) - 32) + WRITE_LEN
seg = struct.pack(">I", (1 << 31) | claim) + header + prog_prefix
assert len(seg) < claim, "the record must arrive segmented"

p = Pcap(os.path.join(os.path.dirname(os.path.abspath(__file__)), "nfs4-gss-none-write.pcap"))
p.tcp(CLIENT, SERVER, syn=True)
p.tcp(SERVER, CLIENT, synack=True)
p.tcp(CLIENT, SERVER, pure_ack=True)
p.tcp(CLIENT, SERVER, payload=seg)
p.close()
print("claim", claim, "segment", len(seg))
