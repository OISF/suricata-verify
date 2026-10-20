#!/usr/bin/env python3
"""Generate input.pcap for tests/nfs3-ooo-write-queue-tail-slack.

Three v3 WRITE calls on one file (handle H), client to server, no replies:

- WRITE 1 (xid 1): 1000 x 0x41 at offset 0, complete record. The file is
  then tracked up to 1000.
- WRITE 2 (xid 2): 3000 x 0x42 at offset 4096, so out of order. Its record
  marker claims 5164 bytes: the 116-byte args, the 3000 file bytes and 2048
  bytes of slack (0x5a) the sender left inside the record after the args.
  The record is split across two segments: the first carries the args plus
  1000 file bytes, the second carries the remaining 2000 file bytes and the
  whole 2048-byte slack.
- WRITE 3 (xid 3): 3096 x 0x43 at offset 1000, FILE_SYNC, in order: it drains
  the queued chunk and completes the file (7096 bytes).

With max-write-queue-size=4096 the continuation is the decision point: the
file bytes the queue holds are 1000 (first fragment) + 2000 (continuation)
= 3000, under the limit, while file bytes + record slack would be
1000 + 4048 = 5048, over it. So the record slack must not count toward the
queue limit; only the file data the chunk still misses may grow it.

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

XID1 = 0x31000001
XID2 = 0x31000002
XID3 = 0x31000003

# WRITE 2 geometry: 1000 file bytes in the first fragment, 2000 in the
# continuation, plus the slack that sits inside the record claim
W2_DATA = 3000
W2_FIRST = 1000
W2_SLACK = 2048


def claim(rec):
    return int.from_bytes(rec[:4], "big") & 0x7FFFFFFF


def v3_write_req(xid, handle, offset, data, stable, slack=b""):
    """One v3 WRITE call record. The record marker covers the args, the file
    data and any slack the sender left inside the record."""
    body = (
        be32(xid) + be32(0) + be32(2) + be32(100003) + be32(3) + be32(7)
        + unix_cred() + null_verf()
        + handle + be64(offset) + be32(len(data)) + be32(stable) + be32(len(data))
        + data
    )
    return struct.pack(">I", (1 << 31) | (len(body) + len(slack))) + body + slack


write1 = v3_write_req(XID1, HANDLE, 0, b"\x41" * 1000, 0)
write2 = v3_write_req(
    XID2, HANDLE, 4096, b"\x42" * W2_DATA, 0, slack=b"\x5a" * W2_SLACK
)
write3 = v3_write_req(XID3, HANDLE, 1000, b"\x43" * 3096, 2)

# the split point of WRITE 2's record: marker + args + the first file bytes
SPLIT = 4 + 116 + W2_FIRST

assert claim(write1) == 1116 and len(write1) == 1120
assert claim(write2) == 5164 and len(write2) == 5168 and SPLIT == 1120
assert claim(write3) == 3212 and len(write3) == 3216
# the continuation carries the missing file bytes and all of the slack
assert len(write2[SPLIT:]) == (W2_DATA - W2_FIRST) + W2_SLACK

p = Pcap(os.path.join(os.path.dirname(os.path.abspath(__file__)), "input.pcap"))
p.tcp(CLIENT, SERVER, syn=True)
p.tcp(SERVER, CLIENT, synack=True)
p.tcp(CLIENT, SERVER, pure_ack=True)
p.tcp(CLIENT, SERVER, payload=write1)
p.tcp(SERVER, CLIENT, pure_ack=True)
p.tcp(CLIENT, SERVER, payload=write2[:SPLIT])
p.tcp(SERVER, CLIENT, pure_ack=True)
p.tcp(CLIENT, SERVER, payload=write2[SPLIT:])
p.tcp(SERVER, CLIENT, pure_ack=True)
p.tcp(CLIENT, SERVER, payload=write3)
p.tcp(SERVER, CLIENT, pure_ack=True)
p.close()

content = b"\x41" * 1000 + b"\x43" * 3096 + b"\x42" * W2_DATA
print("WRITE 2 claim", claim(write2), "slack", W2_SLACK, "continuation",
      len(write2[SPLIT:]))
print("file size", len(content), "sha256", hashlib.sha256(content).hexdigest())
