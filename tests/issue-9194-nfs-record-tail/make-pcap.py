#!/usr/bin/env python3
"""Generate input.pcap for the Redmine #9194 NFS record tail test.

A partial NFSv3 WRITE call or READ reply (record >= 512 bytes, first delivery
incomplete) is continued in later deliveries. The record marker gives the end
of the record, which can lie past the end of the file data and its XDR
padding. Every byte up to that end belongs to the record: the continuation
must consume exactly those bytes, whether they arrive in the delivery that
completes the file data or in a later one, and never parse them as an RPC
record or apply them to the next delivery.

Each case is an independent NFSv3/TCP flow (one client source port):

WRITE flows (to server): a partial UNSTABLE WRITE of one file, whose record
may carry a LOOKUP call record (name FAKE-<port>) or zeros after the data and
its padding, then a LOOKUP (REAL-<port>) of the same size as the tail, a
LOOKUP (LAST-<port>), and a COMMIT that closes the file.

READ flows (to client): three pipelined READ calls for three files, then the
partial reply to the first one, whose record may carry a complete fake reply
(FAKEMARKER data) to the second, outstanding READ after the data and its
padding, then the real reply to the second READ (READMARKER data, same size
as the fake), the reply to the third READ (LASTMARKER data), and a LOOKUP.

DUP flows (to client): a READ of 501 bytes (3 bytes of XDR padding) whose
reply is split, then a second reply with the same xid (DUPMARKER data), and a
LOOKUP. When the first delivery holds all of the file data, the READ is
answered, so the second reply must be ignored, as it is when the first
delivery is cut inside the data.

CLOSED flows (to client): two READs of the same file and a READ of a second
file. The eof reply to the first READ is complete, which closes the file, and
is followed in the same segment by the start of the reply to the second READ
(a re-read of 601 bytes, 3 bytes of XDR padding). The next segment holds the
rest of the re-read reply and the reply to the third READ (READMARKER data),
then a LOOKUP follows. When the first delivery of the re-read reply holds all
of its file data but not all of its padding, the padding that follows has no
open file to go to: it must be consumed without being counted as data of the
closed file, as when the re-read reply arrives complete.

Every data segment is ACKed by the peer, so the IDS delivers each segment to
the NFS parser on its own. In the CLOSED flows the client ACKs the two server
segments only once both are sent, so that no packet to the client, on which
the closed file would be logged, comes between the two deliveries.
Deterministic: fixed MACs, sequence numbers, xids and timestamps.

Usage: ./make-pcap.py  (writes input.pcap next to this script and prints the
per-flow table whose sizes and sha256 values are pinned in test.yaml)
"""

import hashlib
import os
import struct

from scapy.all import Ether, IP, TCP, Raw, wrpcap

CLIENT, SERVER, NFS_PORT = "10.0.0.1", "10.0.0.2", 2049
CMAC, SMAC = "02:00:00:00:91:01", "02:00:00:00:91:02"

NFS_PROGRAM, NFS_V3 = 100003, 3
NFSPROC3_LOOKUP, NFSPROC3_READ, NFSPROC3_WRITE, NFSPROC3_COMMIT = 3, 6, 7, 21
UNSTABLE = 0

# Bytes of the partial record in its first delivery: at least the 44 (WRITE)
# and 128 (READ reply) bytes the partial-record paths need, and well inside
# the file data.
FIRST = 300


def u32(v):
    return struct.pack(">I", v)


def u64(v):
    return struct.pack(">Q", v)


def pad_len(n):
    return (4 - n % 4) % 4


def opaque(b):
    return u32(len(b)) + b + b"\0" * pad_len(len(b))


def record(body):
    # RPC record marker: last fragment + length of the body that follows
    return u32(0x80000000 | len(body)) + body


def call(xid, proc, args):
    # CALL, RPC v2, NFS v3, AUTH_NULL credentials and verifier
    return record(u32(xid) + u32(0) + u32(2) + u32(NFS_PROGRAM) + u32(NFS_V3)
                  + u32(proc) + u32(0) + u32(0) + u32(0) + u32(0) + args)


def reply(xid, res):
    # REPLY, MSG_ACCEPTED, AUTH_NULL verifier, SUCCESS
    return record(u32(xid) + u32(1) + u32(0) + u32(0) + u32(0) + u32(0) + res)


def write_args(fh, offset, data, stable):
    # handle, offset, count, stable, data (length, bytes, XDR padding)
    return opaque(fh) + u64(offset) + u32(len(data)) + u32(stable) + opaque(data)


def commit_args(fh):
    return opaque(fh) + u64(0) + u32(0)


def lookup_args(dirfh, name):
    return opaque(dirfh) + opaque(name)


def read_args(fh, offset, count):
    return opaque(fh) + u64(offset) + u32(count)


def read_res(data, eof):
    # NFS3_OK, no attributes, count, eof, data (length, bytes, XDR padding)
    return u32(0) + u32(0) + u32(len(data)) + u32(1 if eof else 0) + opaque(data)


def pattern(text, n):
    return (text * (n // len(text) + 1))[:n]


WRITE_TEXT = b"R9194 WRITE record tail file data. "
READ_TEXT = b"R9194 READ record tail file data. "
DUP_TEXT = b"R9194 READ reply with split padding. "
CLOSED_TEXT = b"R9194 READ reply that closes the file. "
REREAD_TEXT = b"R9194 re-read reply after the file is closed. "

# 64 bytes each, so the fake reply and the real reply have the same size
FAKE_DATA = b"FAKEMARKER" + b"x" * 54
READ_DATA = b"READMARKER" + b"y" * 54
LAST_DATA = b"LASTMARKER" + b"z" * 54
DUP_DATA = b"DUPMARKER" + b"d" * 55
assert len(FAKE_DATA) == len(READ_DATA) == len(LAST_DATA) == len(DUP_DATA) == 64


class Flow:

    def __init__(self, cport, t0_us):
        self.cport = cport
        self.cseq, self.sseq = 1000, 5000
        self.t_us = t0_us
        self.pkts = []

    def _pkt(self, to_server, flags, payload=b"", ack=None):
        # ack: what the packet acknowledges, by default all of the peer's data
        if to_server:
            ack = self.sseq if ack is None else ack
            p = (Ether(src=CMAC, dst=SMAC) / IP(src=CLIENT, dst=SERVER)
                 / TCP(sport=self.cport, dport=NFS_PORT, flags=flags,
                       seq=self.cseq, ack=ack if "A" in flags else 0))
        else:
            ack = self.cseq if ack is None else ack
            p = (Ether(src=SMAC, dst=CMAC) / IP(src=SERVER, dst=CLIENT)
                 / TCP(sport=NFS_PORT, dport=self.cport, flags=flags,
                       seq=self.sseq, ack=ack if "A" in flags else 0))
        if payload:
            p = p / Raw(payload)
        p.time = self.t_us / 1000000
        self.t_us += 1000
        self.pkts.append(p)

    def handshake(self):
        self._pkt(True, "S")
        self.cseq += 1
        self._pkt(False, "SA")
        self.sseq += 1
        self._pkt(True, "A")

    def c2s(self, payload):
        # client segment, then the server ACK that has it delivered on its own
        self._pkt(True, "PA", payload)
        self.cseq += len(payload)
        self._pkt(False, "A")

    def s2c(self, payload):
        # server segment, then the client ACK that has it delivered on its own
        self._pkt(False, "PA", payload)
        self.sseq += len(payload)
        self._pkt(True, "A")

    def s2c_unacked(self, payload):
        # server segment that the client ACKs later: returns the ACK number
        # that has it delivered (see c_ack)
        self._pkt(False, "PA", payload)
        self.sseq += len(payload)
        return self.sseq

    def c_ack(self, ack):
        # client ACK of the server data up to ack
        self._pkt(True, "A", ack=ack)

    def close(self):
        self._pkt(True, "FA")
        self.cseq += 1
        self._pkt(False, "FA")
        self.sseq += 1
        self._pkt(True, "A")


def split_record(rec, tail_len, shape):
    """Split a record whose last tail_len bytes are its tail (the bytes after
    the file data and its padding) into its deliveries. Returns the
    deliveries and the bytes to prepend to the next record's delivery."""
    end = len(rec) - tail_len  # end of the file data and its padding
    if shape == "whole":
        # the complete record in one delivery
        return [rec], b""
    if shape in ("control", "same"):
        # header and part of the data | rest of the data, padding and tail
        return [rec[:FIRST], rec[FIRST:]], b""
    if shape == "own":
        # header and part of the data | rest of the data and padding | tail
        return [rec[:FIRST], rec[FIRST:end], rec[end:]], b""
    if shape == "split":
        # header and part of the data | rest of the data, padding and the
        # first half of the tail | (the second half goes with the next record)
        half = end + tail_len // 2
        return [rec[:FIRST], rec[FIRST:half]], rec[half:]
    raise ValueError(shape)


def write_flow(idx, port, shape, flen, tail_kind, t0_us):
    base = 0x91940000 + (idx << 8)
    fh = bytes([0x91, 0x94, 0x0F, idx]) * 8
    dirfh = bytes([0x91, 0x94, 0x0D, idx]) * 8
    data = pattern(WRITE_TEXT, flen)
    fake = call(base + 0x50, NFSPROC3_LOOKUP, lookup_args(dirfh, b"FAKE-%d" % port))
    real = call(base + 0x51, NFSPROC3_LOOKUP, lookup_args(dirfh, b"REAL-%d" % port))
    last = call(base + 0x52, NFSPROC3_LOOKUP, lookup_args(dirfh, b"LAST-%d" % port))
    commit = call(base + 0x60, NFSPROC3_COMMIT, commit_args(fh))
    assert len(fake) == len(real)
    if tail_kind == "lookup":
        tail = fake
    elif tail_kind == "zero":
        tail = b"\0" * len(fake)
    else:
        tail = b""
    # the tail is inside the WRITE record: the record marker covers it
    rec = call(base + 0x01, NFSPROC3_WRITE, write_args(fh, 0, data, UNSTABLE) + tail)
    assert len(rec) >= 512 and rec.endswith(data + b"\0" * pad_len(flen) + tail)
    segs, carry = split_record(rec, len(tail), shape)
    if shape != "whole":
        assert 44 <= len(segs[0]) < len(rec)
    segs += [carry + real, last, commit]
    assert b"".join(segs) == rec + real + last + commit

    flow = Flow(port, t0_us)
    flow.handshake()
    for seg in segs:
        flow.c2s(seg)
    flow.close()
    return flow.pkts, dict(file_len=flen, rec_len=len(rec), tail=len(tail),
                           segs=[len(s) for s in segs],
                           sha256=hashlib.sha256(data).hexdigest())


def read_flow(idx, port, shape, flen, tail_kind, t0_us):
    base = 0x91940000 + (idx << 8)
    fh_a = bytes([0x91, 0x94, 0x1A, idx]) * 8
    fh_b = bytes([0x91, 0x94, 0x1B, idx]) * 8
    fh_c = bytes([0x91, 0x94, 0x1C, idx]) * 8
    dirfh = bytes([0x91, 0x94, 0x1D, idx]) * 8
    xid_a, xid_b, xid_c = base + 0x10, base + 0x11, base + 0x12
    data = pattern(READ_TEXT, flen)
    fake = reply(xid_b, read_res(FAKE_DATA, True))
    real = reply(xid_b, read_res(READ_DATA, True))
    last = reply(xid_c, read_res(LAST_DATA, True))
    assert len(fake) == len(real)
    tail = fake if tail_kind == "reply" else b""
    # the tail is inside the reply record to xid_a
    rec = reply(xid_a, read_res(data, True) + tail)
    assert len(rec) >= 512 and rec.endswith(data + b"\0" * pad_len(flen) + tail)
    segs, carry = split_record(rec, len(tail), shape)
    if shape != "whole":
        assert 128 <= len(segs[0]) < len(rec)
    segs += [carry + real, last]
    assert b"".join(segs) == rec + real + last

    flow = Flow(port, t0_us)
    flow.handshake()
    flow.c2s(call(xid_a, NFSPROC3_READ, read_args(fh_a, 0, flen)))
    flow.c2s(call(xid_b, NFSPROC3_READ, read_args(fh_b, 0, len(READ_DATA))))
    flow.c2s(call(xid_c, NFSPROC3_READ, read_args(fh_c, 0, len(LAST_DATA))))
    for seg in segs:
        flow.s2c(seg)
    flow.c2s(call(base + 0x13, NFSPROC3_LOOKUP, lookup_args(dirfh, b"FINAL-%d" % port)))
    flow.close()
    return flow.pkts, dict(file_len=flen, rec_len=len(rec), tail=len(tail),
                           segs=[len(s) for s in segs],
                           sha256=hashlib.sha256(data).hexdigest())


# Bytes of the duplicate-reply flows' first reply that arrive after its first
# delivery. The reply ends with 3 bytes of padding.
DUP_CUTS = {
    "cut-data": 100,  # cut inside the file data
    "cut-pad1": 2,    # all file data and 1 pad byte
    "cut-pad0": 3,    # ends on the last file data byte
}


def dup_flow(idx, port, shape, flen, t0_us):
    base = 0x91940000 + (idx << 8)
    fh = bytes([0x91, 0x94, 0x2A, idx]) * 8
    dirfh = bytes([0x91, 0x94, 0x2D, idx]) * 8
    xid = base + 0x20
    data = pattern(DUP_TEXT, flen)
    rec = reply(xid, read_res(data, True))
    dup = reply(xid, read_res(DUP_DATA, True))
    assert len(rec) >= 512 and pad_len(flen) == 3
    cut = len(rec) - DUP_CUTS[shape]
    assert 128 <= cut < len(rec)
    segs = [rec[:cut], rec[cut:], dup]

    flow = Flow(port, t0_us)
    flow.handshake()
    flow.c2s(call(xid, NFSPROC3_READ, read_args(fh, 0, flen)))
    for seg in segs:
        flow.s2c(seg)
    flow.c2s(call(base + 0x21, NFSPROC3_LOOKUP, lookup_args(dirfh, b"FINAL-%d" % port)))
    flow.close()
    return flow.pkts, dict(file_len=flen, rec_len=len(rec), tail=0,
                           segs=[len(s) for s in segs],
                           sha256=hashlib.sha256(data).hexdigest())


# Bytes of the closed-file flows' re-read reply that arrive after its first
# delivery. The reply ends with 3 bytes of padding.
CLOSED_CUTS = {
    "whole": 0,     # the complete record in the first delivery
    "cut-pad1": 2,  # all file data and 1 pad byte
    "cut-pad0": 3,  # ends on the last file data byte
}


def closed_flow(idx, port, shape, flen, t0_us):
    base = 0x91940000 + (idx << 8)
    fh = bytes([0x91, 0x94, 0x3A, idx]) * 8
    fh_k = bytes([0x91, 0x94, 0x3B, idx]) * 8
    dirfh = bytes([0x91, 0x94, 0x3D, idx]) * 8
    xid_a, xid_b, xid_c = base + 0x30, base + 0x31, base + 0x32
    data = pattern(CLOSED_TEXT, flen)
    redata = pattern(REREAD_TEXT, flen)
    # complete eof reply to the first READ: closes the file of fh
    first = reply(xid_a, read_res(data, True))
    # reply to the second READ, a re-read of fh after its file is closed
    rec = reply(xid_b, read_res(redata, True))
    last = reply(xid_c, read_res(READ_DATA, True))
    assert len(rec) >= 512 and pad_len(flen) == 3
    cut = len(rec) - CLOSED_CUTS[shape]
    assert 128 <= cut <= len(rec)
    segs = [first + rec[:cut], rec[cut:] + last]

    flow = Flow(port, t0_us)
    flow.handshake()
    flow.c2s(call(xid_a, NFSPROC3_READ, read_args(fh, 0, flen)))
    flow.c2s(call(xid_b, NFSPROC3_READ, read_args(fh, 0, flen)))
    flow.c2s(call(xid_c, NFSPROC3_READ, read_args(fh_k, 0, len(READ_DATA))))
    # both server segments are sent before the client ACKs them, one by one
    acks = [flow.s2c_unacked(seg) for seg in segs]
    for ack in acks:
        flow.c_ack(ack)
    flow.c2s(call(base + 0x33, NFSPROC3_LOOKUP, lookup_args(dirfh, b"FINAL-%d" % port)))
    flow.close()
    return flow.pkts, dict(file_len=flen, rec_len=len(rec), tail=0,
                           segs=[len(s) for s in segs],
                           sha256=hashlib.sha256(data).hexdigest())


# (label, client port, kind, shape, file length, tail). Only ever append, so
# the earlier flows stay byte-identical.
FLOWS = [
    # WRITE: 600 bytes of file data (no padding)
    ("w-control", 41000, "write", "control", 600, None),
    ("a", 41001, "write", "same", 600, "lookup"),
    ("b", 41002, "write", "own", 600, "lookup"),
    ("c", 41003, "write", "same", 600, "zero"),
    ("split", 41004, "write", "split", 600, "lookup"),
    ("w-whole", 41005, "write", "whole", 600, "lookup"),
    # WRITE: 601 bytes of file data (3 bytes of padding before the tail)
    ("w-control-pad3", 41010, "write", "control", 601, None),
    ("a-pad3", 41011, "write", "same", 601, "lookup"),
    # READ: 600 bytes of file data (no padding)
    ("r-control", 42000, "read", "control", 600, None),
    ("d", 42001, "read", "same", 600, "reply"),
    ("d-own", 42002, "read", "own", 600, "reply"),
    ("r-whole", 42003, "read", "whole", 600, "reply"),
    # READ: 601 bytes of file data (3 bytes of padding before the tail)
    ("r-control-pad3", 42010, "read", "control", 601, None),
    ("d-pad3", 42011, "read", "same", 601, "reply"),
    # duplicate reply: 501 bytes of file data (3 bytes of padding)
    ("e-control", 43000, "dup", "cut-data", 501, None),
    ("e", 43001, "dup", "cut-pad1", 501, None),
    ("e-pad0", 43002, "dup", "cut-pad0", 501, None),
    # closed file: eof reply, then a re-read reply of 601 bytes of file data
    # (3 bytes of padding) for the same handle
    ("f-whole", 44000, "closed", "whole", 601, None),
    ("f", 44001, "closed", "cut-pad1", 601, None),
    ("f-pad0", 44002, "closed", "cut-pad0", 601, None),
]


def main():
    pkts = []
    rows = []
    t0_us = 1760400000 * 1000000
    for idx, (label, port, kind, shape, flen, tail) in enumerate(FLOWS):
        t = t0_us + idx * 1000000
        if kind == "write":
            p, info = write_flow(idx, port, shape, flen, tail, t)
        elif kind == "read":
            p, info = read_flow(idx, port, shape, flen, tail, t)
        elif kind == "dup":
            p, info = dup_flow(idx, port, shape, flen, t)
        else:
            p, info = closed_flow(idx, port, shape, flen, t)
        pkts += p
        rows.append((label, port, info))
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "input.pcap")
    wrpcap(out, pkts)

    print("data sha256: FAKEMARKER %s" % hashlib.sha256(FAKE_DATA).hexdigest())
    print("             READMARKER %s" % hashlib.sha256(READ_DATA).hexdigest())
    print("             LASTMARKER %s" % hashlib.sha256(LAST_DATA).hexdigest())
    print("             DUPMARKER  %s" % hashlib.sha256(DUP_DATA).hexdigest())
    w = max(len(r[0]) for r in rows)
    print("%-*s  port   flen  rec  tail  deliveries           sha256" % (w, "flow"))
    for label, port, i in rows:
        print("%-*s  %5d  %4d  %4d  %3d  %-19s  %s"
              % (w, label, port, i["file_len"], i["rec_len"], i["tail"],
                 ",".join(map(str, i["segs"])), i["sha256"]))


if __name__ == "__main__":
    main()
