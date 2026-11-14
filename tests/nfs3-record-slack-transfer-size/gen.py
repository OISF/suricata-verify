#!/usr/bin/env python3
"""Generate input.pcap for tests/nfs3-record-slack-transfer-size.

One TCP connection, client 192.168.1.10:941 -> server 192.168.1.20:2049, laid
out so the segment that completes each file record also carries bytes that are
not file data: XDR fill and a pipelined record of its own. A chunk call then
receives more bytes than the file is owed, and only the file part may reach
nfs.write.size / nfs.read.size.

  W1 WRITE xid 1  FH_A offset    0  2000 bytes 0x41   call claim 2116
  W2 WRITE xid 2  FH_A offset 4096  3000 bytes 0x42   call claim 3116
  R1 READ  xid 3  FH_B offset    0  4099 bytes        call claim  108, reply 4144
  R2 READ  xid 4  FH_C offset    0    64 bytes        call claim  108, reply  108

  C->S a: W1 in full, then W2's marker, args and first 2000 file bytes
  C->S b: W2's last 1000 file bytes, then the R1 and R2 calls in full
  S->C c: R1's marker, header, eof flag and the first 4000 data bytes
  S->C d: R1's last 99 data bytes and its byte of XDR fill, then R2's
          marker and reply in full

So W2's completing call holds 1000 file bytes plus the 224 bytes of two
calls, and R1's holds 99 file bytes plus its pad byte plus a whole second
reply. Counting the input instead of the file bytes the tracker took would
log 3224 for W2 and 4212 for R1, where the files are owed 3000 and 4099 (W1
logs its own 2000, R2 its own 64). The WRITEs go unreplied and complete from
the request, as the parser does from 9.0 on.

Regenerate: python3 gen.py (deterministic, no dependencies).
"""
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nfs_sv_common import (
    Pcap, be32, be64, v3_call, v3_fh, v3_reply,
)

CLIENT = ("192.168.1.10", 941)
SERVER = ("192.168.1.20", 2049)

FH_A = v3_fh(0xA1)  # written by W1/W2
FH_B = v3_fh(0xB2)  # read by R1
FH_C = v3_fh(0xC3)  # read by R2

W1_XID, W2_XID, R1_XID, R2_XID = 1, 2, 3, 4
PROC_WRITE, PROC_READ = 7, 6
# file bytes of W2 that ride in the segment which ends its record
W2_HEAD = 2000
# file bytes of R1 that ride in the segment which ends its record
R1_TAIL = 99

W1_DATA = b"\x41" * 2000
W2_DATA = b"\x42" * 3000
# 4099 % 4 == 3 on purpose: the reply carries XDR fill
R1_DATA = (bytes(range(256)) * 17)[:4099]
R2_DATA = b"\x52" * 64


def call_hdr(xid, proc, args):
    return v3_call(xid, proc, args)


def v3_write_call(xid, fh, offset, data, stable=2):
    return call_hdr(
        xid, PROC_WRITE,
        fh + be64(offset) + be32(len(data)) + be32(stable) + be32(len(data)) + data,
    )


def v3_read_call(xid, fh, offset, count):
    return call_hdr(xid, PROC_READ, fh + be64(offset) + be32(count))


def v3_read_reply(xid, data, eof):
    # READ3res as the parser reads it: status, post_op_attr (absent), count,
    # eof, then the data opaque (length, bytes, XDR pad)
    return v3_reply(
        xid,
        be32(0) + be32(0) + be32(len(data)) + be32(1 if eof else 0)
        + be32(len(data)) + data + b"\x00" * ((-len(data)) % 4),
    )


def claim(rec):
    return int.from_bytes(rec[:4], "big") & 0x7FFFFFFF


w1 = v3_write_call(W1_XID, FH_A, 0, W1_DATA)
w2 = v3_write_call(W2_XID, FH_A, 4096, W2_DATA)
r1_call = v3_read_call(R1_XID, FH_B, 0, len(R1_DATA))
r2_call = v3_read_call(R2_XID, FH_C, 0, len(R2_DATA))
r1_reply = v3_read_reply(R1_XID, R1_DATA, 1)
r2_reply = v3_read_reply(R2_XID, R2_DATA, 1)

R1_FILL = (-len(R1_DATA)) % 4  # 1: the data is 4099 bytes

for rec, want in ((w1, 2116), (w2, 3116), (r1_call, 108), (r2_call, 108),
                  (r1_reply, 44 + len(R1_DATA) + R1_FILL),
                  (r2_reply, 44 + len(R2_DATA))):
    assert claim(rec) == want, (want, claim(rec), len(rec))
assert claim(w1) == len(w1) - 4 and claim(w2) == len(w2) - 4

# W2: args and most of its data in one segment, the rest at the next boundary
W2_SPLIT = 4 + (len(w2) - 4 - len(W2_DATA)) + W2_HEAD
assert W2_SPLIT < len(w2)
SEG_A = w1 + w2[:W2_SPLIT]
SEG_B = w2[W2_SPLIT:] + r1_call + r2_call
# R1: most of its data in one segment, the tail plus the XDR pad in the next
R1_SPLIT = len(r1_reply) - (R1_TAIL + R1_FILL)
assert len(r1_reply) - R1_SPLIT == R1_TAIL + R1_FILL
SEG_C = r1_reply[:R1_SPLIT]
SEG_D = r1_reply[R1_SPLIT:] + r2_reply

assert len(SEG_B) == len(w2) - W2_SPLIT + len(r1_call) + len(r2_call)
# the completing READ segment is the one holding the pad and the next record
assert claim(r1_reply) == len(r1_reply) - 4 and len(R1_DATA) % 4 == 3

p = Pcap(os.path.join(os.path.dirname(os.path.abspath(__file__)), "input.pcap"))
p.tcp(CLIENT, SERVER, syn=True)
p.tcp(SERVER, CLIENT, synack=True)
p.tcp(CLIENT, SERVER, pure_ack=True)
p.tcp(CLIENT, SERVER, payload=SEG_A)
p.tcp(SERVER, CLIENT, pure_ack=True)
p.tcp(CLIENT, SERVER, payload=SEG_B)
p.tcp(SERVER, CLIENT, pure_ack=True)
p.tcp(SERVER, CLIENT, payload=SEG_C)
p.tcp(CLIENT, SERVER, pure_ack=True)
p.tcp(SERVER, CLIENT, payload=SEG_D)
p.close()

wfile = W1_DATA + b"\x00" * (4096 - len(W1_DATA)) + W2_DATA
print("segments", [len(x) for x in (SEG_A, SEG_B, SEG_C, SEG_D)])
print("write tx size", len(W1_DATA) + len(W2_DATA))
print("read tx size", len(R1_DATA), "r2", len(R2_DATA))
print("write file", len(wfile), "sha256", hashlib.sha256(wfile).hexdigest())
print("read file", len(R1_DATA), "sha256", hashlib.sha256(R1_DATA).hexdigest())
