#!/usr/bin/env python3
"""Generate the nfs3-name-bounds fixture.

Names reach the transaction whole so ``nfs.name`` and ``nfs.filename`` can still
match past the protocol bound, which leaves the logger holding strings whose
size is only bounded by stream reassembly. Three v3 calls carry names past the
RFC 1813 NFCString3 limit of 1024 bytes: one under the logger's 8 KiB per-field
cap (logged whole), two over it (shortened in place, record marked).

Payloads above ~64 KiB cannot sit in one IPv4 packet, so records are written to
the stream in chunks; the record mark stays on the first byte of each record.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                               "nfs-tcp-record-mark-overflow"))
from nfs_sv_common import Pcap, be32, fh3, v3_call, v3_fh, v3_reply

CLIENT = ("192.168.7.10", 832)
SERVER = ("192.168.7.20", 2049)
CHUNK = 1400

# NFSPROC3_CREATE is 8: dir fh + name + createhow3 (UNCHECKED)
create_req = v3_call(
    0x1001, 8,
    v3_fh(0x10) + fh3(b"A" * 4096) + b"\x00" * 3 + be32(1) + be32(0) + be32(0),
)
create_reply = v3_reply(0x1001, be32(0) + be32(1) + v3_fh(0x30))

# NFSPROC3_LOOKUP is 3: dir fh + name; reply is status + post_op_attr + fh
lookup_req = v3_call(0x1002, 3, v3_fh(0x11) + fh3(b"B" * 40960))
lookup_reply = v3_reply(0x1002, be32(0) + be32(0) + v3_fh(0x31))

# NFSPROC3_RENAME is 14: two diropargs3; reply is status + wcc_data
rename_req = v3_call(
    0x1003, 14,
    v3_fh(0x12) + fh3(b"C" * 20480) + v3_fh(0x13) + fh3(b"D" * 20480),
)
rename_reply = v3_reply(0x1003, be32(0) + be32(0) + be32(0))

flow = [
    (CLIENT, SERVER, create_req),
    (SERVER, CLIENT, create_reply),
    (CLIENT, SERVER, lookup_req),
    (SERVER, CLIENT, lookup_reply),
    (CLIENT, SERVER, rename_req),
    (SERVER, CLIENT, rename_reply),
]

p = Pcap(os.path.join(os.path.dirname(os.path.abspath(__file__)), "input.pcap"))
p.tcp(CLIENT, SERVER, syn=True)
p.tcp(SERVER, CLIENT, synack=True)
p.tcp(CLIENT, SERVER, pure_ack=True)
for src, dst, record in flow:
    for off in range(0, len(record), CHUNK):
        p.tcp(src, dst, payload=record[off:off + CHUNK])
        p.tcp(*(dst, src), pure_ack=True)
p.close()
print("wrote input.pcap:", sum(len(r) for _, _, r in flow), "payload bytes")
