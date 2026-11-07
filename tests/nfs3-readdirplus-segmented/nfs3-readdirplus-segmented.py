#!/usr/bin/env python3
"""Generate the nfs3-readdirplus-segmented fixture.

A v3 READDIRPLUS request, its reply (one entry) split across two
TCP segments, then a follow-up ACCESS on the entry's filehandle.
Before the metadata-partial fix the segmented reply was skipped (the
entry's handle->name mapping never reached the namemap), so the
ACCESS response fileinfo carried no filename; now it does.

fattr3 follows the RFC 1813 data model (size3 = uint64): 84 bytes
total. The dirlist ends with value_follows = 0 and the explicit eof
bool (RFC 1813 3.3.17 dirlistplus3), as real servers send it.
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

# READDIRPLUS reply (rfc 1813 3.3.17): status + post_op_attr dir_attrs +
# cookieverf3 + dirlistplus3 (value_follows chain). The entry carries the
# name_handle used for the follow-up file data; the ACCESS below is on
# that handle.
fattr3 = be32(2) + b"\x00" * 80  # dir type, zeroed attributes (84B: size/used are uint64)
entry = (
    be64(0x0C66_0003)  # fileid3
    + fh3p(ENTRY_NAME)  # name (nfsfname3: len + bytes + XDR pad)
    + be64(0x7C1B_C6AF)  # cookie3
    + be32(1)        # name_attributes follows
    + fattr3
    + be32(1)        # name_handle follows
    + ENTRY_FH
)
# dirlistplus3 (RFC 1813 3.3.17): value_follows-wrapped entry chain,
# trailing value_follows = 0 and the explicit eof bool (real servers,
# incl. the kernel, send the eof word; see tests/nfs3-readdirplus).
dirlist = be32(1) + entry + be32(0) + be32(1)
readdir_reply = v3_reply(
    XID1, be32(0) + be32(1) + fattr3 + be64(0) + dirlist
)

# ACCESS request on the entry's fh (GETATTR is filtered out of the eve
# log by design: SCNfsTxLoggingIsFiltered)
access_req = v3_call(XID2, 4, v3_fh(0x40) + be32(0x01))
# ACCESS reply: status, obj_attributes (not present) and the trailing
# bool word the real captures carry after the nominal reply end
# (nfs3-01's ACCESS replies end the same way).
access_reply = v3_reply(XID2, be32(0) + be32(0) + be32(1))

p = Pcap(os.path.join(os.path.dirname(os.path.abspath(__file__)), "nfs3-readdirplus-segmented.pcap"))
p.tcp(CLIENT, SERVER, syn=True)
p.tcp(SERVER, CLIENT, synack=True)
p.tcp(CLIENT, SERVER, pure_ack=True)
p.tcp(CLIENT, SERVER, payload=readdir_req)
# split the reply inside the entry: 160 bytes (header + partial entry)
p.tcp(SERVER, CLIENT, payload=readdir_reply[:160])
p.tcp(CLIENT, SERVER, pure_ack=True)
p.tcp(SERVER, CLIENT, payload=readdir_reply[160:])
p.tcp(CLIENT, SERVER, pure_ack=True)
p.tcp(CLIENT, SERVER, payload=access_req)
p.tcp(SERVER, CLIENT, payload=access_reply)
p.tcp(CLIENT, SERVER, pure_ack=True)
p.close()
print("readdir_req", len(readdir_req), "readdir_reply", len(readdir_reply))
