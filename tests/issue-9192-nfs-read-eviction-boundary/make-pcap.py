#!/usr/bin/env python3
#
# Generate input.pcap for the Redmine #9192 NFSv3 READ eviction boundary
# test.
#
# Every flow is one TCP connection 10.0.0.1:<port> -> 10.0.0.2:2049:
#
#   1. READ call (xid 0x91921001) for FILE_FH, offset 0
#   2. the first 200 bytes of its reply record: RPC and READ headers and
#      the first 152 bytes of file data
#   3. NULL calls with distinct xids that are never answered: 1 on the
#      control flows, 600 on the eviction flows, 30 calls per segment
#   4. READ call (xid 0x91922002), offset 0, for MARK_FH, or for FILE_FH
#      again on 41025 and 41026
#   5. ONE segment holding the rest of the FILE_FH reply record (file data
#      that starts with 00 00 00 10, then the XDR pad if any) directly
#      followed by the complete reply (eof=1) to the READ of step 4,
#      carrying MARKER on 41021 to 41024 and REREAD_MARKER on 41025 to 41027
#   6. LOOKUP call and reply
#
# On the eviction flows the 600 calls push the READ xid out of the
# default 512 entry request map, and with max-tx=64 they force-close the
# partially received FILE_FH file transaction. The continuation then has
# no file to go to, and the parser must consume exactly the rest of the
# FILE_FH record to find the next reply in the same segment.
#
# On the eviction flow 41026 the READ of step 4 is for FILE_FH, the handle
# of the force-closed transaction: it creates a new FILE_FH file
# transaction before the continuation arrives. That transaction belongs to
# the new READ, so the continuation must still be consumed without touching
# it, and the new READ's reply must then be extracted with it. 41025 is the
# control of 41026 (1 NULL call), and 41027 is 41026 with the READ of step
# 4 for MARK_FH. These three flows are appended after the original four,
# so those stay unchanged.
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
CMAC, SMAC = "02:00:00:00:91:91", "02:00:00:00:91:92"

NFS_PROGRAM, NFS_V3 = 100003, 3
NFSPROC3_NULL, NFSPROC3_LOOKUP, NFSPROC3_READ = 0, 3, 6

XID_FILE = 0x91921001
XID_MARK = 0x91922002
XID_LOOKUP = 0x91923003
XID_NULL_BASE = 0x91925000

FILE_FH = bytes([0x91, 0x92, 0x0F, 0x11]) * 8
MARK_FH = bytes([0x91, 0x92, 0x0F, 0x22]) * 8
DIR_FH = bytes([0x91, 0x92, 0x0D, 0x01]) * 8
OBJ_FH = bytes([0x91, 0x92, 0x0F, 0x33]) * 8

# READ reply record bytes before the file data: record marker and RPC reply
# header (28), then status, attributes_follow (0), count, eof, data length
READ_HDR = 48
FIRST_SEG = 200           # bytes of the FILE_FH reply record in segment 1
NULLS_PER_SEG = 30        # pipelined NULL calls per client segment

# File data in the first segment, then the continuation. The continuation
# starts with 00 00 00 10: parsed as an RPC record marker it claims a 16
# byte fragment, which the parser rejects as undecodable (fatal).
HEAD_TEXT = b"R9192 READ data delivered before the NULL call burst. "
CONT_START = b"\x00\x00\x00\x10" + b"R9192 continuation"
CONT_TEXT = b" R9192 READ continuation after the eviction."

MARKER = b"R9192-NEXT-RECORD-MARKER-DATA-OK"  # 32 bytes, no XDR pad
assert len(MARKER) % 4 == 0
REREAD_MARKER = b"R9192-REPLACEMENT-READ-MARKER-OK"  # 32 bytes, no XDR pad
assert len(REREAD_MARKER) % 4 == 0

# (client port, FILE_FH data length, NULL calls, handle and file data of
# the second READ)
FLOWS = [
    (41021, 512, 1, MARK_FH, MARKER),    # control, no pad
    (41022, 512, 600, MARK_FH, MARKER),  # eviction, no pad
    (41023, 513, 1, MARK_FH, MARKER),    # control, 3 byte XDR pad
    (41024, 513, 600, MARK_FH, MARKER),  # eviction, 3 byte XDR pad
    # second READ for the same handle as the first one
    (41025, 512, 1, FILE_FH, REREAD_MARKER),    # control
    (41026, 512, 600, FILE_FH, REREAD_MARKER),  # eviction, replacement tx
    # as 41026, but the second READ is for another handle: no replacement
    (41027, 512, 600, MARK_FH, REREAD_MARKER),
]


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
    # NFS3_OK, no file attributes, count, eof, data
    return u32(0) + u32(0) + u32(len(data)) + u32(1 if eof else 0) + opaque(data)


def lookup_args(dirfh, name):
    return opaque(dirfh) + opaque(name)


def lookup_res(fh):
    # NFS3_OK, object handle, no object or directory attributes
    return u32(0) + opaque(fh) + u32(0) + u32(0)


def file_data(n):
    head = (HEAD_TEXT * 3)[:FIRST_SEG - READ_HDR]
    tail = CONT_START + CONT_TEXT * (n // len(CONT_TEXT) + 1)
    return (head + tail)[:n]


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


def build_flow(port, data_len, nulls, mark_fh, mark_data, t0_us):
    data = file_data(data_len)
    rec = reply(XID_FILE, read_res(data, True))
    hdr = READ_HDR
    assert rec[hdr:hdr + data_len] == data
    assert len(rec) == hdr + data_len + pad_len(data_len)
    # partial READ fast path: record >= 512 bytes, first delivery >= 128
    # bytes but incomplete
    assert len(rec) >= 512 and 128 <= FIRST_SEG < hdr + data_len
    cont = rec[FIRST_SEG:]
    assert cont.startswith(CONT_START)
    mark = reply(XID_MARK, read_res(mark_data, True))

    flow = Flow(port, t0_us)
    flow.handshake()
    flow.c2s(call(XID_FILE, NFSPROC3_READ, read_args(FILE_FH, 0, data_len)))
    flow.s2c(rec[:FIRST_SEG])
    xids = [XID_NULL_BASE + i for i in range(nulls)]
    for i in range(0, nulls, NULLS_PER_SEG):
        flow.c2s(b"".join(call(x, NFSPROC3_NULL, b"")
                          for x in xids[i:i + NULLS_PER_SEG]))
    # with mark_fh == FILE_FH and the FILE_FH file tx force-closed, this
    # READ creates a new (replacement) FILE_FH file tx
    flow.c2s(call(XID_MARK, NFSPROC3_READ,
                  read_args(mark_fh, 0, len(mark_data))))
    # the record tail and the next record share one segment
    flow.s2c(cont + mark)
    flow.c2s(call(XID_LOOKUP, NFSPROC3_LOOKUP,
                  lookup_args(DIR_FH, b"r9192-after-boundary")))
    flow.s2c(reply(XID_LOOKUP, lookup_res(OBJ_FH)))
    flow.close()
    return flow.pkts


def main():
    pkts = []
    t0_us = 1760400000 * 1000000
    for i, (port, data_len, nulls, mark_fh, mark_data) in enumerate(FLOWS):
        pkts += build_flow(port, data_len, nulls, mark_fh, mark_data,
                           t0_us + i * 1000000)
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "input.pcap")
    wrpcap(out, pkts)


if __name__ == "__main__":
    main()
