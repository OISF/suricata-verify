#!/usr/bin/env python3
"""Generate input.pcap for tests/nfs3-split-claim-below-extent.

A v3 WRITE (and a v3 READ reply) whose record claims fewer bytes than its own
args promise: count and data length say 4000, the record really holds 660 (READ
600). The record tail cannot cover the promised file data, so the handler must
reject and skip to the record boundary. Only the split delivery reaches the
partial-record path: unsplit, the args are parsed against the full record.

Flows (client ports 939..942):
  939 write-split : WRITE record split at 420 of 780; the last 360 bytes of the
                    record and a complete LOOKUP call share the next segment
  940 write-whole : the same WRITE in one segment
  941 read-split  : READ reply record split at 348 of 648; the last 300 bytes
                    and the LOOKUP reply share the next segment
  942 read-whole  : the same reply in one segment

Every flow ends with a LOOKUP of cbe-marker-name: it must be parsed, which is
what proves the stream stayed in sync. The file data the WRITE/READ promise is
never delivered, so no file may be stored.

Regenerate: python3 gen.py (deterministic, no dependencies).
"""
import hashlib
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nfs_sv_common import Pcap, be32, be64, null_verf, unix_cred, v3_fh

CLAIM = 4000  # file bytes the args promise
WPRESENT = 660  # file bytes the WRITE record really holds
CPRESENT = 600  # file bytes the READ reply record really holds
WSPLIT, CSPLIT = 4 + 60 + 56 + 300, 4 + 24 + 20 + 300  # delivery boundary
NAME = b"cbe-marker-name"
WTEXT, RTEXT = b"CBE-WRITE-DATA-", b"CBE-READ-DATA-"

CI, SI = "192.168.1.6", "192.168.1.2"
FH = v3_fh(0x40)  # already length-prefixed on the wire
OUT = os.path.dirname(os.path.abspath(__file__))
p = Pcap(os.path.join(OUT, "input.pcap"))


def u32(v):
    return be32(v)


def opaque(b):
    return u32(len(b)) + b + b"\x00" * ((-len(b)) % 4)


def marker(n):
    return struct.pack(">I", (1 << 31) | n)


def pattern(text, n):
    return (text * (n // len(text) + 1))[:n]


def sha(b):
    return hashlib.sha256(b).hexdigest()


def call_record(xid, proc, args):
    body = (
        u32(xid) + u32(0) + u32(2) + u32(100003) + u32(3) + u32(proc)
        + unix_cred() + null_verf() + args
    )
    assert len(body) == 60 + len(args)
    return marker(len(body)) + body


def reply_record(xid, args):
    body = u32(xid) + u32(1) + u32(0) + null_verf() + u32(0) + args
    assert len(body) == 24 + len(args)
    return marker(len(body)) + body


def null_call(xid):
    return call_record(xid, 0, b"")


def null_reply(xid):
    return reply_record(xid, u32(0))


def lookup_call(xid, name):
    return call_record(xid, 3, FH + opaque(name))


def lookup_reply(xid):
    return reply_record(xid, u32(0) + FH + u32(0) + u32(0))


def read_call(xid, count):
    return call_record(xid, 6, FH + be64(0) + u32(count))


def write_record(xid, data_len, present):
    """WRITE call: record holds `present` data bytes but promises data_len."""
    args = (
        FH + be64(0) + u32(data_len) + u32(0) + u32(data_len)
        + pattern(WTEXT, present)
    )
    return call_record(xid, 7, args)


def read_reply_record(xid, data_len, present):
    """READ reply: record holds `present` bytes but promises data_len."""
    args = (
        u32(0) + u32(0) + u32(data_len) + u32(0) + u32(data_len)
        + pattern(RTEXT, present)
    )
    return reply_record(xid, args)


def flow(cport):
    c, s = (CI, cport), (SI, 2049)
    p.tcp(c, s, syn=True)
    p.tcp(s, c, synack=True)
    p.tcp(c, s, pure_ack=True)
    return c, s


# --- 939/940: WRITE, split and whole ---
for n, (cport, xid, split) in enumerate((
        (939, 0x9196_0000, True), (940, 0x9196_0100, False))):
    c, s = flow(cport)
    w = write_record(xid + 1, CLAIM, WPRESENT)
    assert len(w) == 4 + 60 + 56 + WPRESENT and (len(w) - WSPLIT) == 360
    p.tcp(c, s, payload=null_call(xid))
    p.tcp(s, c, payload=null_reply(xid))
    if split:
        p.tcp(c, s, payload=w[:WSPLIT])
        p.tcp(s, c, pure_ack=True)
        p.tcp(c, s, payload=w[WSPLIT:] + lookup_call(xid + 2, NAME))
    else:
        p.tcp(c, s, payload=w + lookup_call(xid + 2, NAME))
    p.tcp(s, c, payload=lookup_reply(xid + 2))
    p.tcp(c, s, pure_ack=True)

# --- 941/942: READ reply, split and whole ---
for cport, xid, split in ((941, 0x9196_0200, True), (942, 0x9196_0300, False)):
    c, s = flow(cport)
    r = read_reply_record(xid + 1, CLAIM, CPRESENT)
    assert len(r) == 4 + 24 + 20 + CPRESENT and (len(r) - CSPLIT) == 300
    p.tcp(c, s, payload=null_call(xid))
    p.tcp(s, c, payload=null_reply(xid))
    p.tcp(c, s, payload=read_call(xid + 1, CLAIM) + lookup_call(xid + 2, NAME))
    if split:
        p.tcp(s, c, payload=r[:CSPLIT])
        p.tcp(c, s, pure_ack=True)
        p.tcp(s, c, payload=r[CSPLIT:] + lookup_reply(xid + 2))
    else:
        p.tcp(s, c, payload=r + lookup_reply(xid + 2))
    p.tcp(c, s, pure_ack=True)

p.close()
print("wrote input.pcap; write data sha", sha(pattern(WTEXT, WPRESENT)),
      "read data sha", sha(pattern(RTEXT, CPRESENT)))
