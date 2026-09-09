#!/usr/bin/env python3
"""Generate pcaps for the nfs4-malformed-compound-{request,response} and
nfs-size-limit-zero suricata-verify tests.

NFS RPC framing as consumed by the analyzer:
  request record: marker(frag_len,xid) msgtype rpcver program progver
                  procedure cred_fl cred_len [cred] verf_fl verf_len
                  [verf] progdata
  reply record:   marker xid msgtype reply_state verf_fl verf_len [verf]
                  accept_state progdata

Wire constraints learned from the passing tests in this repo:
  * the FIRST record of each direction must be complete within a single
    packet -- the app layer attaches only once a full record has been
    parsed; a record that spans packets (or claims more than it carries)
    before that point is never parsed.
  * v3 WRITE request progdata: fh offset count stable file_len data,
    where file_len is the data length present in the record (<= count).
  * the claimed record length (marker) must equal the bytes actually
    sent for that record; a claim beyond the available data leaves the
    record incomplete at flow end.
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
    # 1-bit is_last + 31-bit frag_len
    return (0x80000000 | (frag_len & 0x7FFFFFFF)).to_bytes(4, "big")


def req_record(xid, progver, proc, prog_data, frag_len=None):
    body = (be32(xid) + be32(0) + be32(2) + be32(NFS_PROG) +
            be32(progver) + be32(proc) + be32(0) + be32(0) +
            be32(0) + be32(0) + prog_data)
    return marker(frag_len if frag_len is not None else len(body)) + body


def reply_record(xid, prog_data, frag_len=None):
    # xid msgtype reply_state verf_fl verf_len accept_state (no procedure
    # words; the procedure is resolved via the xidmap)
    body = (be32(xid) + be32(1) + be32(0) + be32(0) +
            be32(0) + be32(0) + prog_data)
    return marker(frag_len if frag_len is not None else len(body)) + body


def fh3():
    # fh_length 32 + 32-byte handle
    return be32(32) + bytes(range(1, 33))


def fh3b():
    # a second, distinct file handle (separate file for the read transfer)
    return be32(32) + bytes(range(33, 65))


def v4_getattr_req(xid):
    # PUTFH + GETATTR (empty attr bits): small, complete compound.
    # The GETATTR args must carry the full attrbits (attr_cnt + mask1)
    # or the compound body parse fails Incomplete and the flow never
    # attaches the NFS app parser.
    putfh = be32(22) + fh3()
    getattr = be32(9) + be32(0) + be32(0)
    prog_data = be32(0) + be32(0) + be32(2) + putfh + getattr
    return req_record(xid, 4, 1, prog_data)


def v4_getattr_reply(xid):
    # PUTFH res (status word) + GETATTR res (status 6 -> no attrs follow)
    putfh = be32(22) + be32(0)
    getattr = be32(9) + be32(6)
    prog_data = be32(0) + be32(0) + be32(2) + putfh + getattr
    return reply_record(xid, prog_data)


def v3_write_req(xid, offset, count, data, stable=0):
    # fh offset count stable file_len data. stable=0 (UNSTABLE): the file
    # tx stays open, so the in-progress chunk is fed by later stream data;
    # stable=2 closes the tx and the remaining chunk bytes are dropped.
    prog_data = (fh3() + be64(offset) + be32(count) + be32(stable) +
                 be32(len(data)) + data)
    return req_record(xid, 3, 7, prog_data)


def v3_write_reply(xid, offset, count):
    # status + write_res3 (count offset stable)
    prog_data = be32(0) + be32(count) + be64(offset) + be32(2)
    return reply_record(xid, prog_data)


def v3_read_req(xid, offset, count):
    prog_data = fh3b() + be64(offset) + be32(count)
    return req_record(xid, 3, 6, prog_data)  # NFSPROC3_READ (remapped value used by this branch)


def v3_read_reply(xid, count, data, eof=1):
    # status + post_op_attr(attr_follows=0) + count + eof + data_len + data
    prog_data = be32(0) + be32(0) + be32(count) + be32(eof) + be32(len(data)) + data
    return reply_record(xid, prog_data)


class Flow:
    def __init__(self, cport, window=64240):
        self.cport = cport
        self.window = window
        self.cseq = 1000   # client ISN
        self.sseq = 5000   # server ISN
        self.ack_c = 0     # ack value the client sends (server position)
        self.ack_s = 0     # ack value the server sends (client position)
        self.pkts = []

    def tcp(self, d, flags, payload=b""):
        # SYN/SYN-ACK consume one sequence number; data packets consume
        # exactly their payload length (no gaps in the stream)
        if d == "c":
            p = (IP(src=CLIENT, dst=SERVER) /
                 TCP(sport=self.cport, dport=NFS_PORT, seq=self.cseq,
                     ack=self.ack_c, flags=flags, window=self.window) /
                 Raw(load=payload))
            self.cseq += len(payload) if payload else 1
            # the server will ack up to the client's new position
            self.ack_s = self.cseq
        else:
            p = (IP(src=SERVER, dst=CLIENT) /
                 TCP(sport=NFS_PORT, dport=self.cport, seq=self.sseq,
                     ack=self.ack_s, flags=flags, window=self.window) /
                 Raw(load=payload))
            self.sseq += len(payload) if payload else 1
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

    def data_acked(self, d, payload, seg=32768):
        # like data(), but the peer acks after every segment: the stream
        # engine only feeds the app layer data within the peer's advertised
        # window, so unacked bursts beyond the window stall.
        for i in range(0, len(payload), seg):
            self.tcp(d, "PA", payload[i:i + seg])
            self.tcp("s" if d == "c" else "c", "A")

    def close(self):
        # mirror the existing NFS tests: end the exchange with an ACK
        # (the flow tears down on timeout); no FINs
        if self.cseq > 1001:
            self.tcp("s", "A")


# ---------------------------------------------------------------- test A
flow = Flow(880)
flow.handshake()
# small, complete v4 exchange first: the app layer attaches on the first
# fully parsed record in each direction
flow.data("c", v4_getattr_req(0x11111111))
flow.data("s", v4_getattr_reply(0x11111111))
# structurally malformed v4 COMPOUND request: claims an 8 KiB record
# (two 4 KiB packets) and carries ops_cnt=100, above the 64-op bound.
# The error is definitive from the first 4 KiB buffered: the record must
# be rejected + skipped instead of being buffered toward the claim.
hdr = (be32(0x22222222) + be32(0) + be32(2) + be32(NFS_PROG) +
       be32(4) + be32(1) + be32(0) + be32(0) + be32(0) + be32(0))
bad = be32(0) + be32(0) + be32(100)          # tag minorver ops_cnt
p1 = marker(8188) + hdr + bad + b"\xaa" * (4096 - 4 - 40 - 12)
p2 = b"\xaa" * 4096
# interleave a pure server ACK between the two fragments so the stream
# engine feeds the first 4 KiB on its own: the scanner must see the
# definitive ops_cnt=100 structural error from the partial data and
# reject the record before buffering toward the 8 KiB claim.
flow.data("c", p1, seg=4096)
flow.tcp("s", "A")
flow.data("c", p2, seg=4096)
flow.close()
wrpcap("tests/nfs4-malformed-compound-request/input.pcap", flow.pkts)
print("test A:", len(flow.pkts), "pkts")

# ---------------------------------------------------------------- test B
flow = Flow(881)
flow.handshake()
flow.data("c", v4_getattr_req(0x33333333))
flow.data("s", v4_getattr_reply(0x33333333))
flow.data("c", v4_getattr_req(0x44444444))
# structurally malformed v4 COMPOUND reply for xid 0x44444444: same 8 KiB
# claim / two 4 KiB packets / ops_cnt=100 as test A, on the response side
rhdr = (be32(0x44444444) + be32(1) + be32(0) + be32(0) +
        be32(0) + be32(0))               # ..verf_len accept_state
bad = be32(0) + be32(0) + be32(100)          # status tag ops_cnt
p1 = marker(8188) + rhdr + bad + b"\xbb" * (4096 - 4 - 28 - 12)
p2 = b"\xbb" * 4096
flow.data("s", p1 + p2, seg=4096)
flow.tcp("c", "A")
wrpcap("tests/nfs4-malformed-compound-response/input.pcap", flow.pkts)
print("test B:", len(flow.pkts), "pkts")

# ---------------------------------------------------------------- test C
flow = Flow(882)
flow.handshake()
SIZE = 17 * 1024 * 1024 + 512 * 1024  # 17.5 MiB, above the 16 MiB defaults
assert SIZE % 4 == 0
# small v3 exchange first (complete first record in each direction), then
# the 17.5 MiB transfers: with max-write-size / max-read-size set to 0 the
# size checks are disabled and both transfers must log in full. The writes
# are non-overlapping (offset 0 / 8) so the file ends up exactly SIZE.
flow.data("c", v3_write_req(0x55555555, 0, 8, b"\x41" * 8))
flow.data("s", v3_write_reply(0x55555555, 0, 8))
flow.data_acked("c", v3_write_req(0x66666666, 8, SIZE - 8, b"\x41" * (SIZE - 8)))
flow.data("s", v3_write_reply(0x66666666, 8, SIZE - 8))
flow.data("c", v3_read_req(0x77777777, 0, SIZE))
flow.data_acked("s", v3_read_reply(0x77777777, SIZE, b"\x42" * SIZE))
flow.close()
wrpcap("tests/nfs-size-limit-zero/input.pcap", flow.pkts)
print("test C:", len(flow.pkts), "pkts, size", SIZE)
