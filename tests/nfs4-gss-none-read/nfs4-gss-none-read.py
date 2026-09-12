#!/usr/bin/env python3
"""Generate the nfs4-gss-none-read fixture.

A complete v4 COMPOUND READ request with RPCSEC_GSS credentials
(procedure 0, service 1 = rpc_gss_svc_none; the request records the
combination in the xidmap), then its reply split across two TCP
segments. The reply record claims 8 KiB (below max-read-size) while
the enclosed compound carries a READ claiming 17 MiB (above the
16 MiB default). The reply-side partial scan must treat the raw
compound as the scan data (no envelope for service none) and reject
the claim. Before the service-none fix the (0, 1) combination hit
the scanner's catch-all and the reply was discarded as malformed
instead of rejected with the size event.
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nfs_sv_common import Pcap, be32, be64, fh3, gss_cred

CLIENT = ("192.168.1.6", 939)
SERVER = ("192.168.1.2", 2049)
XID = 0x31000002
READ_LEN = 17 * 1024 * 1024

gss = gss_cred(0, 1)

# request compound: tag + minorversion + ops_cnt + PUTFH + READ
req_prog = (
    fh3(b"")
    + be32(0)
    + be32(2)
    + be32(22)
    + fh3(bytes(range(32)))
    + be32(25)  # READ
    + be32(1) + b"\x00" * 12  # stateid
    + be64(0)  # offset
    + be32(1)  # stable
    + be32(8192)  # count
    + be32(0)  # data length
)
req_header = (
    be32(XID) + be32(0) + be32(2) + be32(100003) + be32(4) + be32(1)
    + gss + be32(0) + be32(0)
)
req = struct.pack(">I", (1 << 31) | (len(req_header) + len(req_prog))) + req_header + req_prog

# reply compound (raw, no envelope): status + tag + ops_cnt
# + SEQUENCE resok (36 bytes after status) + READ resok claiming READ_LEN
reply_prog = (
    be32(0)  # compound status
    + fh3(b"")  # tag
    + be32(2)  # ops_cnt
    + be32(53)  # SEQUENCE
    + be32(0)  # status
    + b"\x00" * 36  # sessionid + sequenceid + slotids + status_flags
    + be32(25)  # READ
    + be32(0)  # status
    + be32(0)  # eof
    + be32(READ_LEN)  # count
    + be32(READ_LEN)  # data length
    + b"\x00" * 32  # start of data
)
reply_header = be32(XID) + be32(1) + be32(0) + be32(0) + be32(0) + be32(0)
# the record claims 8 KiB: below max-read-size, so only the compound
# scan can catch the 17 MiB inner claim
claim = 8192
seg1 = struct.pack(">I", (1 << 31) | claim) + reply_header + reply_prog[:128]

p = Pcap(os.path.join(os.path.dirname(os.path.abspath(__file__)), "nfs4-gss-none-read.pcap"))
p.tcp(CLIENT, SERVER, syn=True)
p.tcp(SERVER, CLIENT, synack=True)
p.tcp(CLIENT, SERVER, pure_ack=True)
p.tcp(CLIENT, SERVER, payload=req)
p.tcp(SERVER, CLIENT, payload=seg1)
p.close()
print("req", len(req), "claim", claim, "seg1", len(seg1))
