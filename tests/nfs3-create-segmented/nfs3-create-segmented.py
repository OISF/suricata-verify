#!/usr/bin/env python3
"""Generate the nfs3-create-segmented fixture.

A v3 CREATE request, its reply split across two TCP segments, then a
follow-up ACCESS on the created filehandle. Before the metadata-partial
fix the segmented CREATE reply was skipped (the created file's
handle->name mapping never reached the namemap), so the ACCESS response
fileinfo carried no filename; now it does.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nfs_sv_common import Pcap, be32, fh3, v3_call, v3_fh, v3_reply

CLIENT = ("192.168.1.6", 939)
SERVER = ("192.168.1.2", 2049)
XID1 = 0x31000001
XID2 = 0x31000002
NAME = b"cfile"
CREATED_FH = v3_fh(0x30)

# CREATE request: dir fh + name + create_mode + verifier
create_req = v3_call(
    XID1, 8, v3_fh(0x10) + fh3(NAME) + b"\x00" * 3 + be32(1) + be32(0) + be32(0)
)

# CREATE reply: status + handle_follows=1 + fh
create_reply = v3_reply(XID1, be32(0) + be32(1) + CREATED_FH)

# ACCESS request on the created fh (GETATTR is filtered out of the eve
# log by design: SCNfsTxLoggingIsFiltered)
access_req = v3_call(XID2, 4, CREATED_FH + be32(0x01))
# ACCESS reply: status only
access_reply = v3_reply(XID2, be32(0))

p = Pcap(os.path.join(os.path.dirname(os.path.abspath(__file__)), "nfs3-create-segmented.pcap"))
p.tcp(CLIENT, SERVER, syn=True)
p.tcp(SERVER, CLIENT, synack=True)
p.tcp(CLIENT, SERVER, pure_ack=True)
p.tcp(CLIENT, SERVER, payload=create_req)
# split the reply: 36 bytes (RPC header + partial prog_data), then the rest
p.tcp(SERVER, CLIENT, payload=create_reply[:36])
p.tcp(CLIENT, SERVER, pure_ack=True)
p.tcp(SERVER, CLIENT, payload=create_reply[36:])
p.tcp(CLIENT, SERVER, pure_ack=True)
p.tcp(CLIENT, SERVER, payload=access_req)
p.tcp(SERVER, CLIENT, payload=access_reply)
p.tcp(CLIENT, SERVER, pure_ack=True)
p.close()
print("create_req", len(create_req), "create_reply", len(create_reply))
