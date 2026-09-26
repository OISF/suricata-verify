#!/usr/bin/env python3
"""Generate input.pcap for tests/nfs3-ooo-file-sync-terminal.

A terminal (FILE_SYNC) v3 WRITE whose chunk is out of order: the tracker
truncates the file at the terminal chunk's newchunk, so the record tail is
consumed, not stored, and the tracker's is_done transition never happens
inside the stream promise. The tx terminal bookkeeping (is_last /
last_xid / done flags) must therefore run at parse time, as the base did:
the promise is_done arm only closes a tx whose tail is actually stored
(in-order live chunk).

W1 opens the file in order (100 bytes, UNSTABLE). W2 is terminal
(FILE_SYNC), 512 bytes at an offset beyond the gap, split so the first
segment carries only the args (partial-record path, claim 608 >= 512):
pre-fix the tx kept last=false / last_xid=0 until flow teardown; post-fix
the tx is closed at the terminal record's parse with last=true and
last_xid = W2's xid.
Regenerate: python3 gen.py
"""
from scapy.all import IP, TCP, Raw, wrpcap
import hashlib
import zlib

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
        self.tcp("s", "A")
        self.tcp("c", "A")


def main():
    flow = Flow(40123)
    flow.handshake()

    # W1: in-order UNSTABLE write, 100 bytes - opens the file
    w1 = v3_write_req(0x2001, 0, 100, b"\x55" * 100)
    flow.data("c", w1)
    flow.tcp("s", "A")
    flow.data("s", v3_write_reply(0x2001, 0, 100))
    flow.tcp("c", "A")

    # W2: terminal FILE_SYNC write, 512 bytes at offset 200 (OOO: the gap
    # 100..200 is never written). Split so the first segment carries only
    # the args (marker + rpc prefix + args = 100 bytes): claim 608 >= 512
    # takes the partial-record path, the tracker truncates the file at the
    # terminal chunk, and the 512-byte tail is consumed, not stored.
    w2 = v3_write_req(0x3001, 200, 512, b"\x66" * 512, stable=2)
    assert len(w2) == 612, len(w2)
    assert len(w2[:100]) == 100
    flow.data("c", w2[:100])
    flow.tcp("s", "A")
    flow.data("c", w2[100:])
    flow.tcp("s", "A")
    flow.data("s", v3_write_reply(0x3001, 200, 512))
    flow.tcp("c", "A")

    flow.close()
    wrpcap("input.pcap", flow.pkts)

    # constants for test.yaml (eve hhash = crc32 of the 32-byte fh data,
    # XDR length prefix stripped - cf. nfs_handle2crc in rust/src/nfs/log.rs)
    print("hhash: 0x%x" % (zlib.crc32(fh3()[4:]) & 0xffffffff))
    print("sha256(w1): %s" % hashlib.sha256(b"\x55" * 100).hexdigest())
    print("w2 xid: %d" % 0x3001)
    print("pkts: %d" % len(flow.pkts))


if __name__ == "__main__":
    main()
