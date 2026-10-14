#!/usr/bin/env python3
"""Generate input.pcap for the Redmine #9192 NFS READ continuation on a
closed file test.

A READ reply record of at least 512 bytes whose first delivery is incomplete
takes the partial-record path: the rest of its file data is expected as a
continuation in the next deliveries, up to the end of the record given by its
record marker. The continuation looks up the file transaction of the READ's
file handle. A complete READ reply with eof set closes the file of that
transaction, but the transaction stays in the state, and can still be found by
its handle, until it is logged and freed. A continuation for that handle in
the meantime has no open file to go to: it must be consumed up to the end of
its record, exactly, so the next record in the same delivery is parsed.

Each flow is one NFSv3/TCP connection 10.0.0.1:<port> -> 10.0.0.2:2049:

readahead flows: two READ calls for the two parts of the same file (offset
0, then offset 1024, which reaches the eof) and a READ call for a second
file, sent together. The server answers the second part first, with a
complete eof reply that closes the file: as it is out of order, before any
data of the file is stored. Then comes the reply to the offset 0 READ.

reread flows: a READ call for a file, a second READ call for the same file
(a re-read from offset 0), and a READ call for a second file. The complete eof
reply to the first READ closes the file. Then comes the reply to the re-read.

In both shapes the first server segment starts with the eof reply, and the
second one ends with the complete reply to the READ of the second file
(NEXT_DATA, starting with a unique marker). The reply that follows the eof
reply is cut between the two segments as given by the delivery below. A
LOOKUP call and its reply follow.

Deliveries of the two server segments:

  whole  (control) the cut is at a record boundary: the reply that follows
         the eof reply is complete in the second segment, so it never takes
         the partial-record path
  split  the cut is inside the file data of the reply that follows the eof
         reply. Both segments are sent before the client ACKs them, one by
         one, so no packet to the client, on which the closed file would be
         logged and its transaction freed, comes between the two deliveries:
         the continuation finds the transaction with the closed file
  acked  as split, but the client ACKs each segment before the next one is
         sent: the transaction with the closed file is logged and freed
         before the continuation, which then finds no transaction

Every client segment is ACKed by the server, so the IDS delivers each segment
to the NFS parser on its own. Deterministic: fixed MACs, sequence numbers,
xids and timestamps.

Usage: ./make-pcap.py  (writes input.pcap next to this script and prints the
per-flow table whose xids, sizes and sha256 values are pinned in test.yaml:
"size" is the logged size of the closed file and, for the split flows, "vuln"
is the size it is logged with when the continuation goes to its closed
tracker, as on the vulnerable builds)
"""

import hashlib
import os
import struct

from scapy.all import Ether, IP, TCP, Raw, wrpcap

CLIENT, SERVER, NFS_PORT = "10.0.0.1", "10.0.0.2", 2049
CMAC, SMAC = "02:00:00:00:91:21", "02:00:00:00:91:22"

NFS_PROGRAM, NFS_V3 = 100003, 3
NFSPROC3_LOOKUP, NFSPROC3_READ = 3, 6

# READ reply record bytes before the file data: record marker and RPC reply
# header (28), then status, attributes_follow (0), count, eof, data length
READ_HDR = 48

# Bytes of the split reply in the first delivery: at least the 128 bytes the
# partial READ reply path needs, and well inside the file data.
FIRST = 300

# readahead: the file is read in two parts, the second one is short (eof)
RA_PART = 1024
RA_LEN = 1536
# reread: the file is read twice, completely
RR_LEN = 600

RA_TEXT = b"R9192 readahead file data. "
RR_TEXT = b"R9192 file data that is read twice. "

# complete reply to the READ of the second file: 64 bytes, no XDR padding
MARKER = b"R9192-NEXT-FILE-MARKER"
NEXT_DATA = MARKER + b"n" * (64 - len(MARKER))
assert len(NEXT_DATA) == 64
assert MARKER not in RA_TEXT * 2 and MARKER not in RR_TEXT * 2


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


def read_args(fh, offset, count):
    return opaque(fh) + u64(offset) + u32(count)


def read_res(data, eof):
    # NFS3_OK, no attributes, count, eof, data (length, bytes, XDR padding)
    return (u32(0) + u32(0) + u32(len(data)) + u32(1 if eof else 0)
            + opaque(data))


def lookup_args(dirfh, name):
    return opaque(dirfh) + opaque(name)


def lookup_res(fh):
    # NFS3_OK, object handle, no object or directory attributes
    return u32(0) + opaque(fh) + u32(0) + u32(0)


def pattern(text, n):
    return (text * (n // len(text) + 1))[:n]


def sha256(b):
    return hashlib.sha256(b).hexdigest()


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


def deliver(flow, first, rec, nxt, delivery):
    """Send the eof reply (first), the reply that follows it (rec) and the
    reply for the second file (nxt) in two server segments. Returns the
    segment sizes."""
    if delivery == "whole":
        # the eof reply | the complete reply that follows it and nxt
        segs = [first, rec + nxt]
    else:
        # the eof reply, then the header and part of the file data of the
        # reply that follows it | the rest of that reply and nxt
        assert 128 <= FIRST and READ_HDR < FIRST < len(rec)
        segs = [first + rec[:FIRST], rec[FIRST:] + nxt]
    assert b"".join(segs) == first + rec + nxt
    if delivery == "acked":
        for seg in segs:
            flow.s2c(seg)
    else:
        # both server segments are sent before the client ACKs them, one by one
        acks = [flow.s2c_unacked(seg) for seg in segs]
        for ack in acks:
            flow.c_ack(ack)
    return [len(s) for s in segs]


def lookup(flow, base, idx, port):
    dirfh = bytes([0x91, 0x92, 0x3D, idx]) * 8
    objfh = bytes([0x91, 0x92, 0x3E, idx]) * 8
    flow.c2s(call(base + 0x40, NFSPROC3_LOOKUP,
                  lookup_args(dirfh, b"r9192-after-%d" % port)))
    flow.s2c(reply(base + 0x40, lookup_res(objfh)))


def readahead_flow(idx, port, delivery, t0_us):
    base = 0x91920000 + (idx << 8)
    fh = bytes([0x91, 0x92, 0x1A, idx]) * 8
    fh_next = bytes([0x91, 0x92, 0x1B, idx]) * 8
    xid_0, xid_1, xid_next = base + 0x10, base + 0x11, base + 0x12
    data = pattern(RA_TEXT, RA_LEN)
    # complete eof reply to the READ of the second part, answered first
    first = reply(xid_1, read_res(data[RA_PART:], True))
    # reply to the READ at offset 0, the one that is split
    rec = reply(xid_0, read_res(data[:RA_PART], False))
    nxt = reply(xid_next, read_res(NEXT_DATA, True))
    assert len(rec) >= 512 and pad_len(RA_PART) == 0

    flow = Flow(port, t0_us)
    flow.handshake()
    # readahead: the three READ calls are sent together
    flow.c2s(call(xid_0, NFSPROC3_READ, read_args(fh, 0, RA_PART))
             + call(xid_1, NFSPROC3_READ, read_args(fh, RA_PART, RA_PART))
             + call(xid_next, NFSPROC3_READ,
                    read_args(fh_next, 0, len(NEXT_DATA))))
    segs = deliver(flow, first, rec, nxt, delivery)
    lookup(flow, base, idx, port)
    flow.close()
    # The eof part arrives first, out of order, and closes the file before
    # any of its data is stored: the file is logged with 0 bytes.
    closed = b""
    # A continuation that goes to the closed tracker (vulnerable) takes as
    # much of the second segment as the full data length of the split reply,
    # and that is added to the logged size of the closed file.
    swallow = min(segs[1], RA_PART) if delivery != "whole" else 0
    return flow.pkts, dict(xid=xid_0, xid_next=xid_next, segs=segs,
                           size=len(closed), sha256=sha256(closed),
                           swallowed_size=len(closed) + swallow)


def reread_flow(idx, port, delivery, t0_us):
    base = 0x91920000 + (idx << 8)
    fh = bytes([0x91, 0x92, 0x2A, idx]) * 8
    fh_next = bytes([0x91, 0x92, 0x2B, idx]) * 8
    xid_a, xid_b, xid_next = base + 0x20, base + 0x21, base + 0x22
    data = pattern(RR_TEXT, RR_LEN)
    # complete eof reply to the first READ: closes the file
    first = reply(xid_a, read_res(data, True))
    # reply to the re-read, the one that is split
    rec = reply(xid_b, read_res(data, True))
    nxt = reply(xid_next, read_res(NEXT_DATA, True))
    assert len(rec) >= 512 and pad_len(RR_LEN) == 0

    flow = Flow(port, t0_us)
    flow.handshake()
    flow.c2s(call(xid_a, NFSPROC3_READ, read_args(fh, 0, RR_LEN)))
    flow.c2s(call(xid_b, NFSPROC3_READ, read_args(fh, 0, RR_LEN)))
    flow.c2s(call(xid_next, NFSPROC3_READ,
                  read_args(fh_next, 0, len(NEXT_DATA))))
    segs = deliver(flow, first, rec, nxt, delivery)
    lookup(flow, base, idx, port)
    flow.close()
    # see readahead_flow: the file is closed with the data of the first READ
    swallow = min(segs[1], RR_LEN) if delivery != "whole" else 0
    return flow.pkts, dict(xid=xid_a, xid_next=xid_next, segs=segs,
                           size=len(data), sha256=sha256(data),
                           swallowed_size=len(data) + swallow)


# (label, client port, shape, delivery). Only ever append, so the earlier
# flows stay byte-identical.
FLOWS = [
    ("readahead-control", 44101, "readahead", "whole"),
    ("readahead", 44102, "readahead", "split"),
    ("readahead-acked", 44103, "readahead", "acked"),
    ("reread-control", 44111, "reread", "whole"),
    ("reread", 44112, "reread", "split"),
    ("reread-acked", 44113, "reread", "acked"),
]


def main():
    pkts = []
    t0_us = 1760500000 * 1000000
    print("next file: %d bytes sha256 %s" % (len(NEXT_DATA), sha256(NEXT_DATA)))
    print("%-18s %5s %-9s %-10s %-10s %-9s %4s %-4s %s" % (
        "flow", "port", "shape", "xid", "next xid", "segments", "size",
        "vuln", "sha256 of the closed file"))
    for idx, (label, port, shape, delivery) in enumerate(FLOWS):
        build = readahead_flow if shape == "readahead" else reread_flow
        p, info = build(idx, port, delivery, t0_us + idx * 1000000)
        pkts += p
        print("%-18s %5d %-9s %-10d %-10d %-9s %4d %-4s %s" % (
            label, port, shape, info["xid"], info["xid_next"],
            "|".join(str(s) for s in info["segs"]), info["size"],
            info["swallowed_size"] if delivery == "split" else "-",
            info["sha256"]))
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "input.pcap")
    wrpcap(out, pkts)


if __name__ == "__main__":
    main()
