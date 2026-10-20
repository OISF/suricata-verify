#!/usr/bin/env python3
"""Generate input.pcap for tests/nfs3-ooo-write-queue-tail-slack-split.

The nfs3-ooo-write-queue-tail-slack capture with one change: WRITE 2's record
slack crosses a TCP segment boundary. WRITE 2 (xid 2, 3000 x 0x42 at offset
4096, out of order) claims its 116-byte args, the 3000 file bytes and 2048 bytes
of slack (0x5a) in its record marker, and arrives in three segments:

- the args plus 1000 file bytes,
- the remaining 2000 file bytes plus the first 1000 slack bytes,
- the last 1048 slack bytes.

WRITE 1 (xid 1, 1000 x 0x41 at 0) and WRITE 3 (xid 3, 3096 x 0x43 at 1000,
FILE_SYNC) are as in the original: the file completes at 7096 bytes.

Regenerate: python3 gen.py (deterministic, no dependencies).
"""
import hashlib
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nfs_sv_common import Pcap, be32, be64, null_verf, unix_cred, v3_fh

CLIENT = ("192.168.1.6", 939)
SERVER = ("192.168.1.2", 2049)
HANDLE = v3_fh(0x40)


def v3_write_req(xid, handle, offset, data, stable, slack=b""):
    body = (
        be32(xid) + be32(0) + be32(2) + be32(100003) + be32(3) + be32(7)
        + unix_cred() + null_verf()
        + handle + be64(offset) + be32(len(data)) + be32(stable) + be32(len(data))
        + data
    )
    return struct.pack(">I", (1 << 31) | (len(body) + len(slack))) + body + slack


write1 = v3_write_req(0x31000001, HANDLE, 0, b"\x41" * 1000, 0)
write2 = v3_write_req(0x31000002, HANDLE, 4096, b"\x42" * 3000, 0, slack=b"\x5a" * 2048)
write3 = v3_write_req(0x31000003, HANDLE, 1000, b"\x43" * 3096, 2)

SPLIT = 4 + 116 + 1000         # marker + args + first file bytes
SLACK_START = SPLIT + 2000      # end of WRITE 2's file data
SLACK_SPLIT = SLACK_START + 1000
assert len(write2) == 5168 and len(write2) - SLACK_START == 2048

p = Pcap(os.path.join(os.path.dirname(os.path.abspath(__file__)), "input.pcap"))
p.tcp(CLIENT, SERVER, syn=True)
p.tcp(SERVER, CLIENT, synack=True)
p.tcp(CLIENT, SERVER, pure_ack=True)
p.tcp(CLIENT, SERVER, payload=write1)
p.tcp(SERVER, CLIENT, pure_ack=True)
p.tcp(CLIENT, SERVER, payload=write2[:SPLIT])
p.tcp(SERVER, CLIENT, pure_ack=True)
p.tcp(CLIENT, SERVER, payload=write2[SPLIT:SLACK_SPLIT])
p.tcp(SERVER, CLIENT, pure_ack=True)
p.tcp(CLIENT, SERVER, payload=write2[SLACK_SPLIT:])
p.tcp(SERVER, CLIENT, pure_ack=True)
p.tcp(CLIENT, SERVER, payload=write3)
p.tcp(SERVER, CLIENT, pure_ack=True)
p.close()

content = b"\x41" * 1000 + b"\x43" * 3096 + b"\x42" * 3000
print("file size", len(content), "sha256", hashlib.sha256(content).hexdigest())
