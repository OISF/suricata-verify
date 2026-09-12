#!/usr/bin/env python3
"""Generate the nfs3-lookup-segmented fixture.

A v3 LOOKUP request followed by its reply split across two TCP
segments: the reply is only partially buffered when the record loop
reaches it. Before the metadata-partial fix the reply was skipped
(no namemap entry, no response fileinfo); now it is parsed and the
response fileinfo carries the looked-up filename.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nfs_sv_common import Pcap, be32, fh3, v3_call, v3_fh, v3_reply

CLIENT = ("192.168.1.6", 939)
SERVER = ("192.168.1.2", 2049)
XID = 0x11000001
NAME = b"segfile"

# LOOKUP request: dir fh + filename
lookup_req = v3_call(
    XID, 3, v3_fh(0x10) + fh3(NAME) + b"\x00"
)

# LOOKUP reply: status + filehandle + dir_attr_follows=0
lookup_reply = v3_reply(XID, be32(0) + v3_fh(0x20) + be32(0))

p = Pcap(os.path.join(os.path.dirname(os.path.abspath(__file__)), "nfs3-lookup-segmented.pcap"))
p.tcp(CLIENT, SERVER, syn=True)
p.tcp(SERVER, CLIENT, synack=True)
p.tcp(CLIENT, SERVER, pure_ack=True)
p.tcp(CLIENT, SERVER, payload=lookup_req)
# split the reply: 40 bytes (RPC header + partial prog_data), then the rest
p.tcp(SERVER, CLIENT, payload=lookup_reply[:40])
p.tcp(CLIENT, SERVER, pure_ack=True)
p.tcp(SERVER, CLIENT, payload=lookup_reply[40:])
p.tcp(CLIENT, SERVER, pure_ack=True)
p.close()
print(
    "lookup_req",
    len(lookup_req),
    "lookup_reply",
    len(lookup_reply),
)
