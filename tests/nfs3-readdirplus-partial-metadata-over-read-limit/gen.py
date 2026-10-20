#!/usr/bin/env python3
"""Generate input.pcap for the v3 READDIRPLUS partial-metadata tests.

Used by tests/nfs3-readdirplus-partial-metadata-over-read-limit (sub-test A)
and, through a relative pcap: reference, by
tests/nfs3-readdirplus-partial-metadata-over-read-limit-bounded (sub-test B,
the control that proves the new max-metadata-size knob is what bounds a
partial metadata reply).

A v3 READDIRPLUS request, its reply split across two TCP segments, then a
follow-up ACCESS on the file handle of one of the entries (ACCESS, not
GETATTR: v3 GETATTR transactions are filtered out of the EVE log by design,
SCNfsTxLoggingIsFiltered).

The reply carries 161 entries, so its record claims 12284 bytes: above the
8192 max-read-size the test sets and above the control's 1024
max-metadata-size (plus the 64-byte headroom), below the 16 MiB metadata
default. The reply is split after 44 stream bytes (the RPC record header
plus 16 bytes of prog_data), so the partial-record path decides whether the
reply is buffered to its end or skipped to the record boundary.

Regenerate: python3 gen.py (deterministic, no dependencies).
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nfs_sv_common import Pcap, be32, be64, fh3, fh3p, v3_call, v3_fh, v3_reply

CLIENT = ("192.168.1.6", 939)
SERVER = ("192.168.1.2", 2049)
DIR_FH = v3_fh(0x10)
XID_READDIRPLUS = 0x21000001
XID_ACCESS = 0x21000002

ENTRY_COUNT = 161
TARGET_INDEX = 42
TARGET_NAME = b"entry042"
# bytes of the reply delivered in the first TCP segment
SPLIT = 44


def entry(follows, name, handle_fill):
    """One READDIRPLUS3entry: fileid, name, cookie, no attributes, handle."""
    return (
        be32(follows)
        + be64(0)
        + fh3p(name)
        + be64(0)
        + be32(0)
        + be32(1)
        + v3_fh(handle_fill)
    )


def entry_handle(index):
    return v3_fh(0x40 + index)


entries = b"".join(
    entry(1, f"entry{i:03d}".encode(), 0x40 + i) for i in range(ENTRY_COUNT)
)
# empty nextentry, then eof
readdirplus_reply = v3_reply(
    XID_READDIRPLUS,
    be32(0) + be32(0) + be64(0) + entries + be32(0) + be32(1),
)
readdirplus_request = v3_call(
    XID_READDIRPLUS, 17, DIR_FH + be64(0) + be64(0) + be32(4096) + be32(32768)
)

access_request = v3_call(XID_ACCESS, 4, entry_handle(TARGET_INDEX) + be32(0x01))
# ACCESS resok3: no attributes returned, the requested bit granted (a bare
# status would dissect as a malformed NFS reply)
access_reply = v3_reply(XID_ACCESS, be32(0) + be32(0) + be32(0x01))

claim = int.from_bytes(readdirplus_reply[:4], "big") & 0x7FFFFFFF
assert claim == 48 + 76 * ENTRY_COUNT and claim % 4 == 0
assert len(readdirplus_reply) == claim + 4
# the second segment carries the rest of the record: the skip (sub-test B)
# must land exactly on the next record marker
assert len(readdirplus_reply[SPLIT:]) == claim + 4 - SPLIT

p = Pcap(os.path.join(os.path.dirname(os.path.abspath(__file__)), "input.pcap"))
p.tcp(CLIENT, SERVER, syn=True)
p.tcp(SERVER, CLIENT, synack=True)
p.tcp(CLIENT, SERVER, pure_ack=True)
p.tcp(CLIENT, SERVER, payload=readdirplus_request)
p.tcp(SERVER, CLIENT, pure_ack=True)
p.tcp(SERVER, CLIENT, payload=readdirplus_reply[:SPLIT])
p.tcp(CLIENT, SERVER, pure_ack=True)
p.tcp(SERVER, CLIENT, payload=readdirplus_reply[SPLIT:])
p.tcp(CLIENT, SERVER, pure_ack=True)
p.tcp(CLIENT, SERVER, payload=access_request)
p.tcp(SERVER, CLIENT, payload=access_reply)
p.tcp(CLIENT, SERVER, pure_ack=True)
p.close()

print(
    "readdirplus reply claim", claim, "record", len(readdirplus_reply),
    "entries", ENTRY_COUNT, "target", TARGET_NAME.decode(),
    "xid", XID_ACCESS,
)
