#!/usr/bin/env python3
"""Generate input.pcap for tests/nfs4-write-overlap.

Two v4 COMPOUND WRITEs to the same handle, both UNSTABLE:
offset 0 with 100 bytes of A, then offset 50 with 50 bytes of B. The second
write starts inside the region the file tracker already holds, which is
file_overlap. The v2 and v3 write paths raise it; the v4 one did not, so the
overlapping write was dropped by the tracker with nothing to show that the
inspected file is not what the server stored.

Both writes are UNSTABLE, which keeps one file transaction open across them:
the second write reaches the tracker that already holds 100 bytes. Only the
requests are needed, so the capture carries no replies and the records close
with the flow. Regenerate: python3 gen.py
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
WRITE_COUNT_B = 50
OVERLAP_OFFSET = 50


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


flow = Flow(940)
flow.handshake()
flow.data("c", req_record(0x41000001, write_req(0, b"A" * WRITE_COUNT_A)))
flow.data("c", req_record(0x41000002, write_req(OVERLAP_OFFSET, b"B" * WRITE_COUNT_B)))
flow.close()

# fixed stamps, so regenerating the fixture reproduces the committed file
for i, p in enumerate(flow.pkts):
    p.time = 0.0002 * i

wrpcap(os.path.join(os.path.dirname(os.path.abspath(__file__)), "input.pcap"), flow.pkts)
print("packets", len(flow.pkts))
