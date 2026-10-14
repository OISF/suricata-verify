#!/usr/bin/env python3
#
# Generate input.pcap for the Redmine #9194 NFSv3 READ reply XDR padding test.
#
# Every flow is one TCP connection 10.0.0.1:<port> -> 10.0.0.2:2049:
#
#   1. READ call (xid 0x91941001) for FILE_FH, offset 0
#   2. READ call (xid 0x91942002) for MARK_FH, offset 0 (pipelined)
#   3. READ reply for FILE_FH: a >= 512 byte record whose data length is not
#      a multiple of 4, segmented as described by the flow's shape
#   4. READ reply for MARK_FH (eof=1) carrying MARKER, normally in the same
#      segment as the last bytes (the XDR pad) of reply 3
#   5. LOOKUP call and reply
#
# Every data segment is ACKed by the peer, so the IDS delivers each segment
# to the NFS parser on its own. Timestamps, sequence numbers and addresses
# are fixed so the output is reproducible.
#
# Usage: ./make-pcap.py  (writes input.pcap next to this script)

import os
import struct

from scapy.all import Ether, IP, TCP, Raw, wrpcap

CLIENT, SERVER, NFS_PORT = "10.0.0.1", "10.0.0.2", 2049
CMAC, SMAC = "02:00:00:00:91:01", "02:00:00:00:91:02"

NFS_PROGRAM, NFS_V3 = 100003, 3
NFSPROC3_LOOKUP, NFSPROC3_READ = 3, 6

XID_FILE = 0x91941001
XID_MARK = 0x91942002
XID_LOOKUP = 0x91943003

FILE_FH = bytes([0x91, 0x94, 0x0F, 0x11]) * 8
MARK_FH = bytes([0x91, 0x94, 0x0F, 0x22]) * 8
DIR_FH = bytes([0x91, 0x94, 0x0D, 0x01]) * 8
OBJ_FH = bytes([0x91, 0x94, 0x0F, 0x33]) * 8

MARKER = b"R9194-READ-RESYNC-MARKER-DATA-OK"  # 32 bytes, no XDR pad
assert len(MARKER) % 4 == 0
# A >= 512 byte MARK_FH reply (600 data bytes, no pad) that is itself split;
# MARKER is in its second segment.
MARK_BIG = (b"R9194 next READ reply data. " * 25)[:600 - len(MARKER)] + MARKER
MARK_BIG_FIRST = 200  # bytes of the big MARK_FH reply record in its 1st segment
assert len(MARK_BIG) == 600 and MARK_BIG.count(MARKER) == 1


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


def fattr3(size):
    attrs = (u32(1) + u32(0o644) + u32(1) + u32(0) + u32(0)  # REG mode nlink uid gid
             + u64(size) + u64(size) + u64(0)                 # size used rdev
             + u64(1) + u64(0x9194)                           # fsid fileid
             + u64(0) + u64(0) + u64(0))                      # atime mtime ctime
    assert len(attrs) == 84
    return attrs


def read_args(fh, offset, count):
    return opaque(fh) + u64(offset) + u32(count)


def read_res(data, eof, attrs):
    res = u32(0)  # NFS3_OK
    res += u32(1) + fattr3(len(data)) if attrs else u32(0)
    return res + u32(len(data)) + u32(1 if eof else 0) + opaque(data)


def lookup_args(dirfh, name):
    return opaque(dirfh) + opaque(name)


def lookup_res(fh):
    # NFS3_OK, object handle, no object or directory attributes
    return u32(0) + opaque(fh) + u32(0) + u32(0)


def file_data(n):
    pattern = b"R9194 NFS READ file data before an XDR pad. "
    return (pattern * (n // len(pattern) + 1))[:n]


class Flow:

    def __init__(self, cport, t0_us):
        self.cport = cport
        self.cseq, self.sseq = 1000, 5000
        self.t_us = t0_us
        self.pkts = []

    def _pkt(self, to_server, flags, payload=b""):
        if to_server:
            p = (Ether(src=CMAC, dst=SMAC) / IP(src=CLIENT, dst=SERVER)
                 / TCP(sport=self.cport, dport=NFS_PORT, flags=flags,
                       seq=self.cseq, ack=self.sseq if "A" in flags else 0))
        else:
            p = (Ether(src=SMAC, dst=CMAC) / IP(src=SERVER, dst=CLIENT)
                 / TCP(sport=NFS_PORT, dport=self.cport, flags=flags,
                       seq=self.sseq, ack=self.cseq if "A" in flags else 0))
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
        self._pkt(True, "PA", payload)
        self.cseq += len(payload)
        self._pkt(False, "A")

    def s2c(self, payload):
        self._pkt(False, "PA", payload)
        self.sseq += len(payload)
        self._pkt(True, "A")

    def close(self):
        self._pkt(True, "FA")
        self.cseq += 1
        self._pkt(False, "FA")
        self.sseq += 1
        self._pkt(True, "A")


# Shapes for the FILE_FH READ reply. "cuts" are segment boundaries inside the
# reply record: ("H", n) is n file data bytes after the NFS header, ("D", n)
# is n pad bytes after the last file data byte. With "joined" the MARK_FH
# reply (or its first segment) is appended to the last FILE_FH reply
# segment, else it is sent on its own.
SHAPES = {
    "control": dict(cuts=[], joined=False),
    "control-joined": dict(cuts=[], joined=True),
    "partial-control": dict(cuts=[("H", 200)], joined=True),
    "a": dict(cuts=[("D", 0)], joined=True),
    "b1": dict(cuts=[("D", 1)], joined=True),
    "b2": dict(cuts=[("D", 2)], joined=True),
    "c": dict(cuts=[("H", 200), ("D", 0)], joined=True),
    "d1": dict(cuts=[("H", 200), ("D", 1)], joined=True),
    "d2": dict(cuts=[("H", 200), ("D", 2)], joined=True),
    "pad-alone-a": dict(cuts=[("D", 0)], joined=False),
    "pad-alone-c": dict(cuts=[("H", 200), ("D", 0)], joined=False),
    # the pad itself is split, so a pad-only delivery ends inside the pad
    "split-pad-a": dict(cuts=[("D", 0), ("D", 1)], joined=True),
    "split-pad-b1": dict(cuts=[("D", 1), ("D", 2)], joined=True),
    "split-pad-c": dict(cuts=[("H", 200), ("D", 0), ("D", 1), ("D", 2)],
                        joined=False),
}

# (client port, file data length, attributes follow, eof, shape, big MARK reply)
FLOWS = [
    (40100, 515, False, True, "control", False),
    (40101, 515, False, True, "a", False),
    (40104, 515, False, True, "c", False),
    (40107, 515, False, True, "pad-alone-a", False),
    (40110, 515, False, True, "control-joined", True),
    (40111, 515, False, True, "a", True),

    (40200, 514, False, True, "control", False),
    (40201, 514, False, True, "a", False),
    (40202, 514, False, True, "b1", False),
    (40204, 514, False, True, "c", False),
    (40205, 514, False, True, "d1", False),

    (40300, 513, False, True, "control", False),
    (40301, 513, False, True, "a", False),
    (40302, 513, False, True, "b1", False),
    (40303, 513, False, True, "b2", False),
    (40304, 513, False, True, "c", False),
    (40305, 513, False, True, "d1", False),
    (40306, 513, False, True, "d2", False),
    (40308, 513, False, True, "pad-alone-c", False),
    (40309, 513, False, True, "partial-control", False),

    (40400, 415, True, True, "control", False),
    (40401, 415, True, True, "a", False),
    (40404, 415, True, True, "c", False),

    (40500, 513, False, False, "control", False),
    (40504, 513, False, False, "c", False),

    # pad 3, with the pad itself split across deliveries
    (40310, 513, False, True, "split-pad-a", False),
    (40311, 513, False, True, "split-pad-b1", False),
    (40312, 513, False, True, "split-pad-c", False),
]


def file_reply_segments(data, attrs, eof, shape):
    rec = reply(XID_FILE, read_res(data, eof, attrs))
    # RPC reply header (28) + status, attributes_follow, [attributes],
    # count, eof, data length
    hdr = 28 + 20 + (84 if attrs else 0)
    data_end = hdr + len(data)
    assert rec[hdr:data_end] == data
    assert len(rec) == data_end + pad_len(len(data))
    # partial fast path preconditions: record >= 512 bytes, first delivery
    # >= 128 bytes but incomplete
    assert len(rec) >= 512
    cuts = []
    for base, n in SHAPES[shape]["cuts"]:
        cut = hdr + n if base == "H" else data_end + n
        assert hdr < cut < len(rec) and cut >= 128
        cuts.append(cut)
    segs = []
    prev = 0
    for cut in cuts + [len(rec)]:
        assert cut > prev
        segs.append(rec[prev:cut])
        prev = cut
    return segs


def build_flow(port, data_len, attrs, eof, shape, big_mark, t0_us):
    data = file_data(data_len)
    mark_data = MARK_BIG if big_mark else MARKER
    flow = Flow(port, t0_us)
    flow.handshake()
    flow.c2s(call(XID_FILE, NFSPROC3_READ, read_args(FILE_FH, 0, data_len)))
    flow.c2s(call(XID_MARK, NFSPROC3_READ, read_args(MARK_FH, 0, len(mark_data))))
    segs = file_reply_segments(data, attrs, eof, shape)
    mark = reply(XID_MARK, read_res(mark_data, True, False))
    if big_mark:
        # the following reply takes the partial record path as well
        assert len(mark) >= 512
        mark_segs = [mark[:MARK_BIG_FIRST], mark[MARK_BIG_FIRST:]]
        assert MARKER in mark_segs[1]
    else:
        mark_segs = [mark]
    if SHAPES[shape]["joined"]:
        segs[-1] += mark_segs.pop(0)
    segs += mark_segs
    for seg in segs:
        flow.s2c(seg)
    flow.c2s(call(XID_LOOKUP, NFSPROC3_LOOKUP, lookup_args(DIR_FH, b"r9194-after-read")))
    flow.s2c(reply(XID_LOOKUP, lookup_res(OBJ_FH)))
    flow.close()
    return flow.pkts


def main():
    pkts = []
    t0_us = 1760400000 * 1000000
    for i, (port, data_len, attrs, eof, shape, big_mark) in enumerate(FLOWS):
        pkts += build_flow(port, data_len, attrs, eof, shape, big_mark,
                           t0_us + i * 1000000)
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "input.pcap")
    wrpcap(out, pkts)


if __name__ == "__main__":
    main()
