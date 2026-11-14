#!/usr/bin/env python3
"""Generate input.pcap for tests/nfs4-write-overlap.

One v4 COMPOUND WRITE, UNSTABLE, and its reply: the write is 100 bytes at
offset 0, the answer says NFS4_OK with count 100. An UNSTABLE write leaves
the file transaction open for a later COMMIT, so nothing about it is marked
last: before the fix the reply found no transaction to write the status to
(the xid was only recorded for a FILE_SYNC write) and the log line went out
without nfs.status even though the server had answered OK.

Regenerate: python3 gen.py
"""
import os

from scapy.all import IP, TCP, Raw, wrpcap

CLIENT = "192.168.0.44"
SERVER = "192.168.0.71"
NFS_PORT = 2049
NFS_PROG = 100003

OP_PUTFH = 22
OP_WRITE = 38
WRITE_COUNT_A = 100


def be32(v):
    return v.to_bytes(4, "big")


def be64(v):
    return v.to_bytes(8, "big")


def marker(frag_len):
    return (0x80000000 | (frag_len & 0x7FFFFFFF)).to_bytes(4, "big")


def fh():
    return be32(32) + bytes(range(1, 33))


def opaque(data):
    pad = (-len(data)) % 4
    return be32(len(data)) + data + b"\x00" * pad


def req_record(xid, prog_data):
    body = (be32(xid) + be32(0) + be32(2) + be32(NFS_PROG) + be32(4) + be32(1)
            + be32(0) + be32(0) + be32(0) + be32(0) + prog_data)
    return marker(len(body)) + body


def reply_record(xid, prog_data):
    body = (be32(xid) + be32(1) + be32(0) + be32(0)
            + be32(0) + be32(0) + prog_data)
    return marker(len(body)) + body


def compound(ops):
    # tag (empty) + minorversion 1 + ops_cnt + ops
    return be32(0) + be32(1) + be32(len(ops)) + b"".join(ops)


def putfh():
    return be32(OP_PUTFH) + fh()


def write_req(offset, data):
    # stateid (seq + 12 byte uuid), offset, stable 0 = UNSTABLE, count, data
    # WRITE4args: stateid, offset, stable 0 = UNSTABLE, count, then the bytes
    # as an XDR opaque (length, data, fill to 4)
    op = (be32(OP_WRITE) + be32(1) + b"\x00" * 12 + be64(offset) + be32(0)
          + be32(len(data)) + opaque(data))
    return compound([putfh(), op])


def write_reply(count, status=0, committed=2):
    # WRITE4resok: count, committed, writeverf (nfstimeverf, 8 bytes)
    res = be32(OP_WRITE) + be32(status) + be32(count) + be32(committed) + be64(0)
    return compound_status([be32(OP_PUTFH) + be32(status), res])


def compound_status(op_results):
    return be32(0) + be32(0) + be32(len(op_results)) + b"".join(op_results)


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

    def data(self, d, payload):
        self.tcp(d, "PA", payload)

    def close(self):
        self.tcp("c", "FA")
        self.tcp("s", "FA")


flow = Flow(944)
flow.handshake()
flow.data("c", req_record(0x42000001, write_req(0, b"A" * WRITE_COUNT_A)))
flow.data("s", reply_record(0x42000001, write_reply(WRITE_COUNT_A)))
flow.close()

# fixed stamps, so regenerating the fixture reproduces the committed file
for i, p in enumerate(flow.pkts):
    p.time = 0.0002 * i

wrpcap(os.path.join(os.path.dirname(os.path.abspath(__file__)), "input.pcap"), flow.pkts)
print("packets", len(flow.pkts))
