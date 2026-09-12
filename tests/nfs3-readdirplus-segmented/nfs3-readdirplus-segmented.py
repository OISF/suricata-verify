#!/usr/bin/env python3
"""Generate the nfs3-readdirplus-segmented fixture.

A v3 READDIRPLUS request, its reply (one entry) split across two
TCP segments, then a follow-up ACCESS on the entry's filehandle.
Before the metadata-partial fix the segmented reply was skipped (the
entry's handle->name mapping never reached the namemap), so the
ACCESS response fileinfo carried no filename; now it does.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nfs_sv_common import Pcap, be32, be64, fh3, fh3p, v3_call, v3_fh, v3_reply

CLIENT = ("192.168.1.6", 939)
SERVER = ("192.168.1.2", 2049)
XID1 = 0x21000001
XID2 = 0x21000002
ENTRY_NAME = b"entry1"
ENTRY_FH = v3_fh(0x40)

# READDIRPLUS request: dir fh + cookie + verifier + dircount + maxcount
readdir_req = v3_call(
    XID1, 17, v3_fh(0x10) + be64(0) + be64(0) + be32(1024) + be32(1024)
)

# READDIRPLUS reply: status + dir_attr_follows=0 + cookieverf
# + entry_follows=1 + entry (fileid, name, cookie, attr_follows=0,
# handle_follows=1, fh) + eof=1
entry = (
    be64(0)          # fileid3
    + fh3p(ENTRY_NAME)  # name4 (len + data + XDR pad)
    + be64(0)        # dir_cookie8
    + be32(0)        # attr_value_follows
    + be32(1)        # handle_value_follows
    + ENTRY_FH       # post_op_fhandle
)
readdir_reply = v3_reply(
    XID1, be32(0) + be32(0) + be64(0) + be32(1) + entry + be32(1)
)

# ACCESS request on the entry's fh (GETATTR is filtered out of the eve
# log by design: SCNfsTxLoggingIsFiltered)
access_req = v3_call(XID2, 4, v3_fh(0x40) + be32(0x01))
# ACCESS reply: status only
access_reply = v3_reply(XID2, be32(0))

p = Pcap(os.path.join(os.path.dirname(os.path.abspath(__file__)), "nfs3-readdirplus-segmented.pcap"))
p.tcp(CLIENT, SERVER, syn=True)
p.tcp(SERVER, CLIENT, synack=True)
p.tcp(CLIENT, SERVER, pure_ack=True)
p.tcp(CLIENT, SERVER, payload=readdir_req)
# split the reply: 44 bytes (RPC header + partial prog_data), then the rest
p.tcp(SERVER, CLIENT, payload=readdir_reply[:44])
p.tcp(CLIENT, SERVER, pure_ack=True)
p.tcp(SERVER, CLIENT, payload=readdir_reply[44:])
p.tcp(CLIENT, SERVER, pure_ack=True)
p.tcp(CLIENT, SERVER, payload=access_req)
p.tcp(SERVER, CLIENT, payload=access_reply)
p.tcp(CLIENT, SERVER, pure_ack=True)
p.close()
print("readdir_req", len(readdir_req), "readdir_reply", len(readdir_reply))
