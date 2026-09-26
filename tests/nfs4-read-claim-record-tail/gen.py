#!/usr/bin/env python3
"""Generate input.pcap for tests/nfs4-read-claim-record-tail.

A complete v4 READ reply whose RPC record claim covers its record tail:
the claim (572) is 8 bytes past the parsed body (564), so the record ends
where the next marker starts. The stream advance walks the claim, so none
of those 8 bytes is ever parsed, and a complete record leaves nothing
unbuffered: the file tracker must not be armed with a fill. The next chunk
for the same handle continues the same file; a fill left behind would take
the fill_bytes != 0 arm and truncate it.

The parsed extent of this reply is 532 bytes (20 plus the 512 byte data),
so all 8 bytes of the tail are record tail, not file data.

Regenerate: python3 gen.py
"""
from scapy.all import IP, TCP, Raw, wrpcap

CLIENT = "192.168.0.26"
SERVER = "192.168.0.61"
NFS_PORT = 2049
NFS_PROG = 100003


def be32(v):
    return v.to_bytes(4, "big")


def be64(v):
    return v.to_bytes(8, "big")


def marker(frag_len):
    return (0x80000000 | (frag_len & 0x7FFFFFFF)).to_bytes(4, "big")


def fh3():
    return be32(32) + bytes(range(1, 33))


def req_record(xid, progver, proc, prog_data):
    body = (be32(xid) + be32(0) + be32(2) + be32(NFS_PROG) +
            be32(progver) + be32(proc) + be32(0) + be32(0) +
            be32(0) + be32(0) + prog_data)
    return marker(len(body)) + body


def reply_record(xid, prog_data, frag_len=None, tail=b""):
    body = (be32(xid) + be32(1) + be32(0) + be32(0) +
            be32(0) + be32(0) + prog_data)
    # the tail is part of the record: the claim covers it
    claim = frag_len if frag_len is not None else len(body) + len(tail)
    return marker(claim) + body + tail


def v4_getattr_req(xid):
    putfh = be32(22) + fh3()
    getattr = be32(9) + be32(0) + be32(0)
    return req_record(xid, 4, 1, be32(0) + be32(0) + be32(2) + putfh + getattr)


def v4_getattr_reply(xid):
    putfh = be32(22) + be32(0)
    getattr = be32(9) + be32(6)
    return reply_record(xid, be32(0) + be32(0) + be32(2) + putfh + getattr)


def v4_read_req(xid, offset, count):
    putfh = be32(22) + fh3()
    read = be32(25) + be32(1) + b"\x00" * 12 + be64(offset) + be32(count)
    return req_record(xid, 4, 1, be32(0) + be32(0) + be32(2) + putfh + read)


def v4_read_reply(xid, eof, data):
    # compound status, tag, ops_cnt=1, READ res (status 0, eof, data_len, data)
    prog_data = (be32(0) + be32(0) + be32(1) +
                 be32(25) + be32(0) + be32(eof) + be32(len(data)) + data)
    return reply_record(xid, prog_data)


class Flow:
    def __init__(self, cport, window=64240):
        self.cport = cport
        self.window = window
        self.cseq = 1000
        self.sseq = 5000
        self.ack_c = 0
        self.ack_s = 0
        self.pkts = []

    def tcp(self, d, flags, payload=b""):
        if d == "c":
            p = (IP(src=CLIENT, dst=SERVER) /
                 TCP(sport=self.cport, dport=NFS_PORT, seq=self.cseq,
                     ack=self.ack_c, flags=flags, window=self.window) /
                 Raw(load=payload))
            if payload:
                self.cseq += len(payload)
            elif flags in ("S", "SA"):
                self.cseq += 1
            self.ack_s = self.cseq
        else:
            p = (IP(src=SERVER, dst=CLIENT) /
                 TCP(sport=NFS_PORT, dport=self.cport, seq=self.sseq,
                     ack=self.ack_s, flags=flags, window=self.window) /
                 Raw(load=payload))
            if payload:
                self.sseq += len(payload)
            elif flags in ("S", "SA"):
                self.sseq += 1
            self.ack_c = self.sseq
        self.pkts.append(p)

    def handshake(self):
        self.tcp("c", "S")
        self.cseq = 1001
        self.ack_s = 1001
        self.tcp("s", "SA")
        self.ack_c = 5001
        self.tcp("c", "A")
        self.cseq = 1001
        self.ack_s = 1001

    def data(self, d, payload, seg=32768):
        for i in range(0, len(payload), seg):
            self.tcp(d, "PA", payload[i:i + seg])

    def close(self):
        self.tcp("c", "FA")
        self.tcp("s", "FA")


flow = Flow(910)
flow.handshake()
flow.data("c", v4_getattr_req(0x11111111))
flow.data("s", v4_getattr_reply(0x11111111))
flow.data("c", v4_read_req(0x33333333, 0, 512))
flow.tcp("s", "A")
# reply 1: complete, with an 8 byte record tail inside the claim (572, so
# the record ends 4 byte aligned); the tail is drained by the stream
# advance and must never reach the tracker as a fill
hdr = be32(0x33333333) + be32(1) + be32(0) + be32(0) + be32(0) + be32(0)
prog = (be32(0) + be32(0) + be32(1) +
        be32(25) + be32(0) + be32(0) + be32(512) + b"\x77" * 512)
body = hdr + prog
seg1 = reply_record(0x33333333, prog, tail=b"\x00" * 8)
claim = int.from_bytes(seg1[:4], "big") & 0x7FFFFFFF
assert claim == 572 and claim % 4 == 0 and len(body) == 564
assert len(seg1) == 576
flow.data("s", seg1)
flow.tcp("c", "A")
# reply 2: well-formed, next chunk for the same handle, eof
flow.data("c", v4_read_req(0x44444444, 512, 512))
flow.data("s", v4_read_reply(0x44444444, 1, b"\x88" * 512))
flow.tcp("c", "A")
flow.close()
for i, p in enumerate(flow.pkts, 1):
    p.time = 0.0002 * i
wrpcap("input.pcap", flow.pkts)
print(len(flow.pkts), "pkts, reply1 claim", claim)
