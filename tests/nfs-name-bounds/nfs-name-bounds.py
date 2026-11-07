#!/usr/bin/env python3
"""Generate the nfs-name-bounds fixture.

RFC 1813 3.2 puts no limit on the length of a v3 name, so a name can be as
large as the reassembly buffer allows and it is the logger that has to bound
what it writes. The v3 stream here carries names past any sane record: a 4 KiB
CREATE (logged whole, under the 8 KiB cap), a 40 KiB LOOKUP and a RENAME with a
70 KiB source and a 20 KiB target, all of which must come back shortened with
the in-value marker. The RENAME is the point of the fixture: the source is
logged twice (as ``filename`` and as ``rename.from``), so charging the budget
for the parsed length instead of the written length dropped the field even
though the record was nowhere near the limit.

NFSv2 is the one version that does bound a name, filename<MAXNAMLEN> in
RFC 1094, so a second (v2) stream carries a 300 byte name that must raise
``malformed_data`` while still being logged whole.

Payloads above ~64 KiB cannot sit in one IPv4 packet, so records are chunked
into the stream; the record mark stays on the first byte of each record.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                               "nfs-tcp-record-mark-overflow"))
from nfs_sv_common import Pcap, be32, fh3, v2_call, v2_reply, v3_call, v3_fh, v3_reply

V3 = (("192.168.7.10", 832), ("192.168.7.20", 2049))
V2 = (("192.168.7.11", 833), ("192.168.7.21", 2049))
CHUNK = 1400

# NFSPROC3_CREATE is 8, NFSPROC3_LOOKUP 3, NFSPROC3_RENAME 14.
create_req = v3_call(
    0x1001, 8,
    v3_fh(0x10) + fh3(b"A" * 4096) + be32(0) + b"\x00" * 24,  # UNCHECKED + empty sattr3
)
create_reply = v3_reply(0x1001, be32(0) + be32(1) + v3_fh(0x30)
                  + be32(0) + be32(0) + be32(0))  # obj_attributes + dir_wcc
lookup_req = v3_call(0x1002, 3, v3_fh(0x11) + fh3(b"B" * 40960))
lookup_reply = v3_reply(0x1002, be32(0) + be32(0) + v3_fh(0x31))
rename_req = v3_call(
    0x1003, 14,
    v3_fh(0x12) + fh3(b"C" * 71680) + v3_fh(0x13) + fh3(b"D" * 20480),
)
rename_reply = v3_reply(0x1003, be32(0) * 5)  # status + fromdir_wcc + todir_wcc

# v2 procedure numbers differ from v3: RFC 1094 has LOOKUP 4, RENAME 11.
# A 64 byte filehandle, then filename<MAXNAMLEN 255>.
v2_lookup_req = v2_call(0x2001, 4, b"\x01" * 32 + be32(300) + b"E" * 300)
v2_lookup_reply = v2_reply(0x2001, be32(0) + b"\x00" * 64 + be32(1) + b"\x00" * 64)

flows = {
    V3: [
        (V3[0], V3[1], create_req),
        (V3[1], V3[0], create_reply),
        (V3[0], V3[1], lookup_req),
        (V3[1], V3[0], lookup_reply),
        (V3[0], V3[1], rename_req),
        (V3[1], V3[0], rename_reply),
    ],
    V2: [
        (V2[0], V2[1], v2_lookup_req),
        (V2[1], V2[0], v2_lookup_reply),
    ],
}

p = Pcap(os.path.join(os.path.dirname(os.path.abspath(__file__)), "input.pcap"))
for (client, server), flow in flows.items():
    p.tcp(client, server, syn=True)
    p.tcp(server, client, synack=True)
    p.tcp(client, server, pure_ack=True)
    for src, dst, record in flow:
        for off in range(0, len(record), CHUNK):
            p.tcp(src, dst, payload=record[off:off + CHUNK])
            p.tcp(dst, src, pure_ack=True)
p.close()
print("wrote input.pcap:", sum(len(r) for _, _, r in sum(flows.values(), [])), "payload bytes")
