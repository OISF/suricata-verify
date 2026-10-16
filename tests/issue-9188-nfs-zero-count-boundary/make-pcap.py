#!/usr/bin/env python3
"""Generate input.pcap for the Redmine #9188 zero-count partial-record test.

See https://redmine.openinfosecfoundation.org/issues/9188.

An NFSv3 WRITE call or READ reply with count 0 has no file data, but its RPC
record can still be longer than its header. When such a record is 512 bytes
or larger and its first parser delivery is incomplete, it takes the NFS TCP
partial-record fast path. The unread tail of the record must then be skipped
to the record boundary given by the record marker, so the next RPC record is
parsed from the right offset.

Each flow uses a distinct client source port. The attack flows deliver a
zero-count record split; each has a control flow carrying the same bytes
complete (un-split), which the complete-record path skips by its marker on
every build. Bait records embedded in an unread tail must never be parsed,
proving the skip lands exactly on the record boundary instead of resyncing.

Deterministic: fixed IPs, ports, sequence numbers and timestamps. Regenerate
with ./make-pcap.py (writes input.pcap in this directory). scapy 2.8.
"""
import hashlib
import os
import struct

from scapy.all import Ether, IP, TCP, Raw, wrpcap

NULL, LOOKUP, READ, WRITE, REMOVE = 0, 3, 6, 7, 12
NFS_PROGRAM = 100003


def u32(v):
    return struct.pack(">I", v & 0xFFFFFFFF)


def u64(v):
    return struct.pack(">Q", v & 0xFFFFFFFFFFFFFFFF)


def frag_hdr(length, last=True):
    return u32((0x80000000 if last else 0) | (length & 0x7FFFFFFF))


def xdr_opaque(b):
    pad = (4 - len(b) % 4) % 4
    return u32(len(b)) + b + b"\x00" * pad


# ---- RPC record builders (AUTH_NULL) -------------------------------------
def rpc_call(xid, proc, prog, frag_len=None):
    body = (
        u32(xid) + u32(0)          # msgtype CALL
        + u32(2) + u32(NFS_PROGRAM) + u32(3) + u32(proc)
        + u32(0) + u32(0)          # credentials AUTH_NULL
        + u32(0) + u32(0)          # verifier AUTH_NULL
        + prog
    )
    if frag_len is None:
        frag_len = len(body)
    return frag_hdr(frag_len) + body


def rpc_reply(xid, prog, frag_len=None):
    body = (
        u32(xid) + u32(1)          # msgtype REPLY
        + u32(0)                   # reply_state MSG_ACCEPTED
        + u32(0) + u32(0)          # verifier flavor + length 0
        + u32(0)                   # accept_state SUCCESS
        + prog
    )
    if frag_len is None:
        frag_len = len(body)
    return frag_hdr(frag_len) + body


# ---- NFSv3 program bodies ------------------------------------------------
def diropargs(fh, name):
    """LOOKUP3args and REMOVE3args."""
    return xdr_opaque(fh) + xdr_opaque(name)


def read_args(fh, offset=0, count=512):
    return xdr_opaque(fh) + u64(offset) + u32(count)


def write_head(fh, count, data_len, offset=0, stable=1):
    """WRITE3args up to and including the data length."""
    return xdr_opaque(fh) + u64(offset) + u32(count) + u32(stable) + u32(data_len)


def read_reply_prog(data, count, eof, attr_follows=0):
    """NFSv3 READ reply body (status OK)."""
    b = u32(0)                      # status NFS3_OK
    b += u32(attr_follows)
    if attr_follows == 1:
        b += b"\x00" * 84
    b += u32(count) + u32(eof) + u32(len(data))
    pad = (4 - len(data) % 4) % 4
    return b + data + b"\x00" * pad


def read_reply(xid, data, eof=1, attr_follows=0):
    return rpc_reply(xid, read_reply_prog(data, len(data), eof, attr_follows))


def padded(prefix, total):
    """Pad a record prefix out to its full record size."""
    assert len(prefix) <= total, (len(prefix), total)
    return prefix + b"\x00" * (total - len(prefix))


# ---- flow helper ---------------------------------------------------------
class Flow:
    def __init__(self, cport, t0, sport=2049, c="10.0.0.1", s="10.0.0.2"):
        self.c, self.s, self.cp, self.sp = c, s, cport, sport
        self.cseq, self.sseq = 1000, 5000
        self.t = t0
        self.pkts = []

    def _p(self, to_server, flags, payload=b""):
        # The ack field is only meaningful with the ACK flag set: the initial
        # SYN carries ack 0, else Suricata raises stream.pkt_broken_ack.
        if to_server:
            ack = self.sseq if "A" in flags else 0
            p = (Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
                 / IP(src=self.c, dst=self.s)
                 / TCP(sport=self.cp, dport=self.sp, flags=flags,
                       seq=self.cseq, ack=ack))
        else:
            ack = self.cseq if "A" in flags else 0
            p = (Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")
                 / IP(src=self.s, dst=self.c)
                 / TCP(sport=self.sp, dport=self.cp, flags=flags,
                       seq=self.sseq, ack=ack))
        if payload:
            p = p / Raw(payload)
        p.time = self.t
        self.t += 0.001
        self.pkts.append(p)

    def handshake(self):
        self._p(True, "S"); self.cseq += 1
        self._p(False, "SA"); self.sseq += 1
        self._p(True, "A")

    def c2s(self, payload):
        self._p(True, "PA", payload); self.cseq += len(payload)
        self._p(False, "A")

    def c2s_lost(self, payload):
        """A client segment the sensor never sees: the server ACKs it along
        with the next segment, which makes it a stream gap."""
        self.cseq += len(payload)

    def s2c(self, payload):
        self._p(False, "PA", payload); self.sseq += len(payload)
        self._p(True, "A")

    def close(self):
        self._p(True, "FA"); self.cseq += 1
        self._p(False, "FA"); self.sseq += 1
        self._p(True, "A")


H1 = b"R9188FH1"           # file handles (8 bytes)
H2 = b"R9188FH2"
H3 = b"R9188FH3"
BIG_REC = 800              # claimed fragment length -> 804-byte record
REC = BIG_REC + 4
HUGE_REC = 4000            # -> 4004-byte record, tail spans several segments


def marker(tag):
    """36 bytes of READ reply data carrying a marker."""
    m = b"R9188" + tag + b"-" + b"0123456789" * 3
    return m[:36]


MARK_R = marker(b"MARK-R")    # genuine replies, must be extracted
MARK_D = marker(b"MARK-D")
MARK_E = marker(b"MARK-E")
MARK_Z = marker(b"MARK-Z")
BAIT_TC = marker(b"BAIT-TC")  # embedded reply data, must never be parsed
DUP = marker(b"DUPXID")       # duplicate-xid reply data, must be ignored
BAIT_TS = b"R9188BAIT-TS"     # embedded LOOKUP name, must never be parsed
CANARY = b"R9188REMOVE"       # genuine REMOVE name after the boundary


def canary_remove(xid):
    return rpc_call(xid, REMOVE, diropargs(H3, CANARY))


def zero_write(xid, frag_len=BIG_REC, embed=b""):
    """A WRITE call with count = data length = 0, padded out to its full
    record size. Its 76-byte header is self-consistent; the rest of the
    record (optionally starting with an embedded record) is unread tail."""
    head = rpc_call(xid, WRITE, write_head(H1, 0, 0), frag_len=frag_len)
    assert len(head) == 76, len(head)
    return head, padded(head + embed, frag_len + 4)


def zero_read_reply(xid, frag_len=BIG_REC, attr_follows=1, embed=b""):
    """A READ reply with count = data length = 0 (eof), padded out to its
    full record size. The header is 132 bytes with attributes, 48 without."""
    head = rpc_reply(xid, read_reply_prog(b"", 0, 1, attr_follows),
                     frag_len=frag_len)
    assert len(head) == (132 if attr_follows else 48), len(head)
    return head, padded(head + embed, frag_len + 4)


flows = []

# ---- To-server (WRITE) flows ---------------------------------------------
# Flow w-attack (sport 3101): NULL, the 76-byte header of an 804-byte
# zero-count WRITE, then its 728-byte unread tail (an embedded LOOKUP for
# R9188BAIT-TS + zeros) and the genuine REMOVE (R9188REMOVE) in one segment.
bait_ts = rpc_call(0x10F1, LOOKUP, diropargs(H2, BAIT_TS))
w_head, w_rec = zero_write(0x1001, embed=bait_ts)
assert w_rec[len(w_head):].startswith(bait_ts)
fw = Flow(3101, 1.0)
fw.handshake()
fw.c2s(rpc_call(0x1000, NULL, b""))
fw.c2s(w_head)
fw.c2s(w_rec[len(w_head):] + canary_remove(0x1002))
fw.close()
flows.append(fw)

# Flow w-control (sport 3102): the same bytes, the WRITE record complete.
fwc = Flow(3102, 2.0)
fwc.handshake()
fwc.c2s(rpc_call(0x1000, NULL, b""))
fwc.c2s(w_rec + canary_remove(0x1002))
fwc.close()
flows.append(fwc)

# Flow w-consecutive (sport 3103): the first delivery holds the header and
# 24 bytes of the tail; the next segment completes the record and starts a
# second zero-count WRITE, which is partial again, mid-segment.
a_head, a_rec = zero_write(0x1101)
b_head, b_rec = zero_write(0x1102)
fwm = Flow(3103, 3.0)
fwm.handshake()
fwm.c2s(rpc_call(0x1100, NULL, b""))
fwm.c2s(a_rec[:len(a_head) + 24])
fwm.c2s(a_rec[len(a_head) + 24:] + b_head)
fwm.c2s(b_rec[len(b_head):] + canary_remove(0x1103))
fwm.close()
flows.append(fwm)

# Flow w-multiseg (sport 3104): a 4004-byte zero-count WRITE whose 3928-byte
# tail spans three segments, the last one also carrying the REMOVE.
h_head, h_rec = zero_write(0x1201, frag_len=HUGE_REC)
h_tail = h_rec[len(h_head):]
fwh = Flow(3104, 4.0)
fwh.handshake()
fwh.c2s(rpc_call(0x1200, NULL, b""))
fwh.c2s(h_head)
fwh.c2s(h_tail[:1300])
fwh.c2s(h_tail[1300:2600])
fwh.c2s(h_tail[2600:] + canary_remove(0x1202))
fwh.close()
flows.append(fwh)

# Flow w-gap (sport 3105): as w-attack, but the sensor misses the first 300
# bytes of the tail (a stream gap). The rest of the tail starts with an
# embedded LOOKUP for R9188BAIT-TS: the gap is part of the skip, and the
# rest of the skip must not be probed for records.
bait_gap = rpc_call(0x13F1, LOOKUP, diropargs(H2, BAIT_TS))
g_head, g_rec = zero_write(0x1301)
g_tail = g_rec[len(g_head):]
g_tail = g_tail[:300] + bait_gap + g_tail[300 + len(bait_gap):]
assert len(g_head) + len(g_tail) == REC
fwg = Flow(3105, 5.0)
fwg.handshake()
fwg.c2s(rpc_call(0x1300, NULL, b""))
fwg.c2s(g_head)
fwg.c2s_lost(g_tail[:300])
fwg.c2s(g_tail[300:] + canary_remove(0x1302))
fwg.close()
flows.append(fwg)

# ---- To-client (READ reply) flows ----------------------------------------
# Flow r-attack (sport 3106): READ calls 0x2001 (H1, answered by an 804-byte
# zero-count reply with attributes), 0x2002 (H2, outstanding, matched only
# by the reply embedded in the tail) and 0x2003 (H3, the genuine reply).
# The first 132 bytes of the zero-count reply, then its 672-byte tail (an
# embedded reply with R9188BAIT-TC data + zeros) and the genuine reply
# (R9188MARK-R) in one segment, then a to-server REMOVE.
bait_tc = read_reply(0x2002, BAIT_TC)
r_head, r_rec = zero_read_reply(0x2001, embed=bait_tc)
assert r_rec[len(r_head):].startswith(bait_tc)
fr = Flow(3106, 6.0)
fr.handshake()
fr.c2s(rpc_call(0x2001, READ, read_args(H1)))
fr.c2s(rpc_call(0x2002, READ, read_args(H2)))
fr.c2s(rpc_call(0x2003, READ, read_args(H3)))
fr.s2c(r_head)
fr.s2c(r_rec[len(r_head):] + read_reply(0x2003, MARK_R))
fr.c2s(canary_remove(0x2004))
fr.close()
flows.append(fr)

# Flow r-control (sport 3107): the same bytes, the zero-count reply complete.
frc = Flow(3107, 7.0)
frc.handshake()
frc.c2s(rpc_call(0x2001, READ, read_args(H1)))
frc.c2s(rpc_call(0x2002, READ, read_args(H2)))
frc.c2s(rpc_call(0x2003, READ, read_args(H3)))
frc.s2c(r_rec + read_reply(0x2003, MARK_R))
frc.c2s(canary_remove(0x2004))
frc.close()
flows.append(frc)

# Flow r-dupxid (sport 3108): an 804-byte zero-count reply without
# attributes to READ 0x2101 (H1). The first delivery holds its 48-byte
# header and 92 bytes of the tail, then the rest of the tail. A valid reply
# reusing xid 0x2101 (R9188DUPXID) follows: the zero-count reply ended the
# request, as on the complete path, so it must be ignored. Then the reply to
# READ 0x2102 (H2, R9188MARK-D) and a to-server REMOVE.
d_head, d_rec = zero_read_reply(0x2101, attr_follows=0)
fd = Flow(3108, 8.0)
fd.handshake()
fd.c2s(rpc_call(0x2101, READ, read_args(H1)))
fd.c2s(rpc_call(0x2102, READ, read_args(H2)))
fd.s2c(d_rec[:140])
fd.s2c(d_rec[140:])
fd.s2c(read_reply(0x2101, DUP))
fd.s2c(read_reply(0x2102, MARK_D))
fd.c2s(canary_remove(0x2103))
fd.close()
flows.append(fd)

# Flow r-dupxid-control (sport 3109): the same, the zero-count reply complete.
fdc = Flow(3109, 9.0)
fdc.handshake()
fdc.c2s(rpc_call(0x2101, READ, read_args(H1)))
fdc.c2s(rpc_call(0x2102, READ, read_args(H2)))
fdc.s2c(d_rec)
fdc.s2c(read_reply(0x2101, DUP))
fdc.s2c(read_reply(0x2102, MARK_D))
fdc.c2s(canary_remove(0x2103))
fdc.close()
flows.append(fdc)

# Flow r-consecutive (sport 3110): two zero-count replies, to READ 0x2201
# (H1, 804 bytes) and 0x2202 (H2, 4004 bytes). The second starts mid-segment
# after the first one's tail, and its 3872-byte tail spans three segments,
# the last one also carrying the genuine reply to READ 0x2203 (H3,
# R9188MARK-E). Then a to-server REMOVE.
e1_head, e1_rec = zero_read_reply(0x2201)
e2_head, e2_rec = zero_read_reply(0x2202, frag_len=HUGE_REC)
e2_tail = e2_rec[len(e2_head):]
fe = Flow(3110, 10.0)
fe.handshake()
fe.c2s(rpc_call(0x2201, READ, read_args(H1)))
fe.c2s(rpc_call(0x2202, READ, read_args(H2)))
fe.c2s(rpc_call(0x2203, READ, read_args(H3)))
fe.s2c(e1_head)
fe.s2c(e1_rec[len(e1_head):] + e2_head)
fe.s2c(e2_tail[:1300])
fe.s2c(e2_tail[1300:2600])
fe.s2c(e2_tail[2600:] + read_reply(0x2203, MARK_E))
fe.c2s(canary_remove(0x2204))
fe.close()
flows.append(fe)

# Flow z-short (sport 3111): ordinary short zero-count records, complete on
# every build: a 76-byte WRITE with count 0, a 132-byte READ reply with
# count 0 and eof, then the genuine reply to a second READ (R9188MARK-Z)
# and a REMOVE. Unaffected by the fix.
fz = Flow(3111, 11.0)
fz.handshake()
fz.c2s(rpc_call(0x2300, NULL, b""))
fz.c2s(rpc_call(0x2301, WRITE, write_head(H1, 0, 0)))
fz.c2s(rpc_call(0x2302, READ, read_args(H1)))
fz.c2s(rpc_call(0x2303, READ, read_args(H2)))
fz.s2c(read_reply(0x2302, b"", eof=1, attr_follows=1))
fz.s2c(read_reply(0x2303, MARK_Z))
fz.c2s(canary_remove(0x2304))
fz.close()
flows.append(fz)

packets = []
for f in flows:
    packets.extend(f.pkts)

here = os.path.dirname(os.path.abspath(__file__))
wrpcap(os.path.join(here, "input.pcap"), packets)

print("records:")
print("  zero-count WRITE record =", REC, "header =", len(w_head),
      "tail =", REC - len(w_head), "embedded LOOKUP =", len(bait_ts))
print("  zero-count WRITE 4004 tail =", len(h_tail))
print("  zero-count READ reply record =", REC, "header =", len(r_head),
      "tail =", REC - len(r_head), "embedded reply =", len(bait_tc))
print("  zero-count READ reply 4004 tail =", len(e2_tail))
for name, m in (("MARK-R", MARK_R), ("MARK-D", MARK_D), ("MARK-E", MARK_E),
                ("MARK-Z", MARK_Z), ("BAIT-TC", BAIT_TC), ("DUPXID", DUP)):
    print("  %-8s %r len %d sha256 %s" % (name, m, len(m),
                                          hashlib.sha256(m).hexdigest()))
print("  packets =", len(packets))
