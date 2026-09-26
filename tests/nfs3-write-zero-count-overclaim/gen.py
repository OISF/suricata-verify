#!/usr/bin/env python3
"""Generate input.pcap for tests/nfs3-write-zero-count-overclaim.

A v3 WRITE request with count == 0 and file_len == 0 whose RPC record
claim (608) overreaches the parsed extent (96 bytes: 40 RPC header + 56
args) by 512: the args parse, and before the fix the count-0 early return
in process_write_record
ran before the extent/claim check, so the record boundary was dropped and
the claimed remainder (junk) was parsed as a new RPC record on the next
segment, desyncing the stream. A claim above the extent is the record
tail, not malformed data, so the check now runs before the early return
and the zero-count arm skips silently to the record boundary; the
following well-formed WRITE parses and logs its file.

The record is split so the first segment carries only the args
(partial-record path, rec_size >= 512).
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


def fh3b():
    return be32(32) + bytes(range(33, 65))


def req_record(xid, progver, proc, prog_data):
    body = (be32(xid) + be32(0) + be32(2) + be32(NFS_PROG) +
            be32(progver) + be32(proc) + be32(0) + be32(0) +
            be32(0) + be32(0) + prog_data)
    return marker(len(body)) + body


def reply_record(xid, prog_data):
    body = (be32(xid) + be32(1) + be32(0) + be32(0) +
            be32(0) + be32(0) + prog_data)
    return marker(len(body)) + body


def v3_write_req(xid, offset, count, data, stable=0, fh=None):
    if fh is None:
        fh = fh3()
    prog_data = (fh + be64(offset) + be32(count) + be32(stable) +
                 be32(len(data)) + data)
    return req_record(xid, 3, 7, prog_data)


def v3_write_reply(xid, offset, count):
    prog_data = be32(0) + be32(count) + be64(offset) + be32(2)
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


flow = Flow(911)
flow.handshake()
# well-formed v3 WRITE first: attach the app layer, establish the handle
flow.data("c", v3_write_req(0x11111111, 0, 100, b"\x33" * 100))
flow.tcp("s", "A")
flow.data("s", v3_write_reply(0x11111111, 0, 100))
flow.tcp("c", "A")
# zero-count WRITE: the 608-byte claim covers the 96-byte extent plus 512
# bytes of record tail
zargs = fh3() + be64(0) + be32(0) + be32(0) + be32(0)
zhdr = (be32(0x22222222) + be32(0) + be32(2) + be32(NFS_PROG) +
        be32(3) + be32(7) + be32(0) + be32(0) + be32(0) + be32(0))
assert len(zhdr) == 40
zrec = marker(len(zhdr) + len(zargs) + 512) + zhdr + zargs + b"\xaa" * 512
assert len(zrec) == 612
# segment 1: marker + rpc header + full args (100 bytes), record
# incomplete: the zero-count arm must skip its record tail
flow.data("c", zrec[:100], seg=4096)
flow.tcp("s", "A")
# segment 2: the claimed junk remainder, then a well-formed WRITE on the
# second handle: it must parse after the skip, not desync
follow = v3_write_req(0x44444444, 0, 1000, b"\x44" * 1000, fh=fh3b())
flow.data("c", zrec[100:] + follow, seg=64240)
flow.tcp("s", "A")
flow.data("s", v3_write_reply(0x44444444, 0, 1000))
flow.tcp("c", "A")
flow.close()
wrpcap("input.pcap", flow.pkts)
print(len(flow.pkts), "pkts, zero-count record", len(zrec))
