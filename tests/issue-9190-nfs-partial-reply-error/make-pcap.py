#!/usr/bin/env python3
"""Generate input.pcap for the Redmine #9190 partial-record reply/RPC/WRITE
content-error regression test.

See https://redmine.openinfosecfoundation.org/issues/9190.

Each flow uses a distinct client source port. The attack flows each exercise
one known-boundary content-error arm of the NFS TCP partial-record fast paths;
each attack flow has a control flow carrying an invalid record of the same
kind complete (un-split; byte-identical for b, c, e, f, g and h). Flow d is
a negative control whose record marker is undecodable (boundary unknown) and
must stay fatal. Flows f and g prove the skip lands exactly on the record
boundary: the unread tail of the malformed record starts with a complete,
well-formed embedded record that must never be parsed. Flow h proves that
skipping a malformed partial READ reply also ends its request, so a later
reply reusing its xid is ignored.

Deterministic: fixed IPs, ports, sequence numbers and timestamps. Regenerate
with ./make-pcap.py (writes input.pcap in this directory). scapy 2.8.
"""
import hashlib
import os
import struct

from scapy.all import Ether, IP, TCP, Raw, wrpcap

NULL, LOOKUP, READ, WRITE = 0, 3, 6, 7
COMPOUND4 = 1              # NFSv4 COMPOUND procedure
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


# ---- RPC record builders -------------------------------------------------
def rpc_call_body(xid, proc, prog, creds_flavor=0, creds=b"", verf_flavor=0,
                  verf=b""):
    return (
        u32(xid) + u32(0)          # msgtype CALL
        + u32(2) + u32(NFS_PROGRAM) + u32(3) + u32(proc)
        + u32(creds_flavor) + xdr_opaque(creds)
        + u32(verf_flavor) + xdr_opaque(verf)
        + prog
    )


def rpc_call(xid, proc, prog, frag_len=None, **kw):
    body = rpc_call_body(xid, proc, prog, **kw)
    if frag_len is None:
        frag_len = len(body)
    return frag_hdr(frag_len) + body


def rpc_reply_body(xid, prog, reply_state=0):
    return (
        u32(xid) + u32(1)          # msgtype REPLY
        + u32(reply_state)         # reply_state (MSG_ACCEPTED=0)
        + u32(0) + u32(0)          # verifier flavor + length 0
        + u32(0)                   # accept_state SUCCESS
        + prog
    )


def rpc_reply(xid, prog, frag_len=None, reply_state=0):
    body = rpc_reply_body(xid, prog, reply_state)
    if frag_len is None:
        frag_len = len(body)
    return frag_hdr(frag_len) + body


# ---- NFSv3 program bodies ------------------------------------------------
def read_args(fh, offset=0, count=512):
    return xdr_opaque(fh) + u64(offset) + u32(count)


def lookup_args(fh, name):
    return xdr_opaque(fh) + xdr_opaque(name)


def read_reply_prog(data, count, eof, attr_follows=0, data_len=None):
    """NFSv3 READ reply body (status OK)."""
    if data_len is None:
        data_len = len(data)
    b = u32(0)                      # status NFS3_OK
    b += u32(attr_follows)
    if attr_follows == 1:
        b += b"\x00" * 84
    b += u32(count) + u32(eof) + u32(data_len)
    pad = (4 - len(data) % 4) % 4
    b += data + b"\x00" * pad
    return b


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

    def s2c(self, payload):
        self._p(False, "PA", payload); self.sseq += len(payload)
        self._p(True, "A")

    def close(self):
        self._p(True, "FA"); self.cseq += 1
        self._p(False, "FA"); self.sseq += 1
        self._p(True, "A")


H1 = b"R9190FH1"           # file handle 1 (8 bytes)
H2 = b"R9190FH2"           # file handle 2
H3 = b"R9190FH3"
MARKER_A = b"R9190MARK-A-" + b"0123456789" * 2 + b"ABCD"   # 36 bytes
MARKER_B = b"R9190MARK-B-" + b"0123456789" * 2 + b"ABCD"   # 36 bytes
BIG_REC = 800              # claimed fragment length -> 804-byte record


def read_reply_record(xid, data, count=512, eof=1, attr_follows=0,
                      data_len=None, frag_len=None, reply_state=0):
    prog = read_reply_prog(data, count, eof, attr_follows, data_len)
    return rpc_reply(xid, prog, frag_len=frag_len, reply_state=reply_state)


def padded(prefix, total=BIG_REC + 4):
    """Pad a record prefix out to the full claimed record size with opaque
    filler. The invalid field sits near the front (inside the first delivered
    segment); the parser rejects it before reading the filler."""
    assert len(prefix) <= total, (len(prefix), total)
    return prefix + b"\x00" * (total - len(prefix))


flows = []

# --- Flow a-attack (sport 3001): to-client partial READ reply whose content
#     is invalid (eof = 2). Record >= 512, first delivery >= 128 bytes. The
#     remainder of the record plus a complete good reply (different handle,
#     data carries R9190MARK) arrives in the next segment. ---
# RPC reply header (28 bytes) + READ reply fields; eof field lands at offset 40.
bad_a_prefix = (
    frag_hdr(BIG_REC) + u32(0xA1) + u32(1)            # marker, xid, REPLY
    + u32(0) + u32(0) + u32(0) + u32(0)               # reply_state, vflav, vlen, accept
    + u32(0) + u32(0) + u32(512) + u32(2)             # status, attr_follows, count, eof=2
)
bad_a = padded(bad_a_prefix)                          # full 804-byte record
seg1 = bad_a[:140]                                    # >=128, < rec, includes eof
tail = bad_a[140:]                                    # rest of A1 record
good_a = read_reply_record(0xA2, MARKER_A, count=len(MARKER_A), eof=1)
fa = Flow(3001, 1.0)
fa.handshake()
fa.c2s(rpc_call(0xA1, READ, read_args(H1, 0, 512)))   # READ req, xid A1
fa.c2s(rpc_call(0xA2, READ, read_args(H2, 0, 512)))   # READ req, xid A2
fa.s2c(seg1)
fa.s2c(tail + good_a)
fa.close()
flows.append(fa)

# --- Flow a-control (sport 3002): a short COMPLETE READ reply with the same
#     invalid eof = 2 (below 512 bytes, so never on the partial path), then a
#     complete good reply. The complete record is only marked malformed, so
#     the marker already alerts on the vulnerable baseline. ---
fac = Flow(3002, 2.0)
fac.handshake()
fac.c2s(rpc_call(0xB1, READ, read_args(H1, 0, 512)))
fac.c2s(rpc_call(0xB2, READ, read_args(H2, 0, 512)))
fac.s2c(read_reply_record(0xB1, b"", count=512, eof=2, data_len=0))  # complete
fac.s2c(read_reply_record(0xB2, MARKER_A, count=len(MARKER_A), eof=1))
fac.close()
flows.append(fac)

# --- Flow b-attack (sport 3003): to-client partial reply whose RPC reply
#     header itself is invalid (reply_state = 2) with a valid record marker
#     for a known READ xid. Remainder + a later good reply follow. ---
# reply_state field lands at offset 12 (right after the 12-byte RPC header).
bad_b_prefix = (
    frag_hdr(BIG_REC) + u32(0xC1) + u32(1)            # marker, xid, REPLY
    + u32(2)                                          # reply_state=2 (invalid)
)
bad_b = padded(bad_b_prefix)                          # full 804-byte record
seg1b = bad_b[:72]                                    # < rec, includes reply_state
tailb = bad_b[72:]
good_b = read_reply_record(0xC2, MARKER_B, count=len(MARKER_B), eof=1)
fb = Flow(3003, 3.0)
fb.handshake()
fb.c2s(rpc_call(0xC1, READ, read_args(H1, 0, 512)))
fb.c2s(rpc_call(0xC2, READ, read_args(H2, 0, 512)))
fb.s2c(seg1b)
fb.s2c(tailb + good_b)
fb.close()
flows.append(fb)

# --- Flow c-attack (sport 3004): to-server partial WRITE whose RPC call header
#     is invalid at the RPC level (AUTH_UNIX credential with an absurd length)
#     while the record marker / xid / msgtype / procedure are all valid.
#     Remainder + a complete LOOKUP follow in later segments. ---
# Build a WRITE call whose creds_len is absurd (0x2000 >= RPC_MAX_CREDS_SIZE).
# Lay out the header by hand so the credential length field (offset 32) is the
# failure. The record marker / xid / msgtype / procedure are all valid.
write_prefix = (
    frag_hdr(BIG_REC)
    + u32(0xD1) + u32(0)                               # xid, CALL
    + u32(2) + u32(NFS_PROGRAM) + u32(3) + u32(WRITE)  # rpc/prog/ver/proc=WRITE
    + u32(1)                                           # creds_flavor AUTH_UNIX
    + u32(0x2000)                                      # creds_len: absurd
)
write_rec = padded(write_prefix)                       # full 804-byte record
seg1c = write_rec[:72]                                 # >= 44, < rec, includes creds_len
tailc = write_rec[72:]                                 # rest of WRITE record
lookup_c = rpc_call(0xD2, LOOKUP, lookup_args(H3, b"R9190LOOKUPC"))
fc = Flow(3004, 4.0)
fc.handshake()
fc.c2s(rpc_call(0xD0, NULL, b""))                      # establish NFS
fc.c2s(seg1c)
fc.c2s(tailc + lookup_c)
fc.close()
flows.append(fc)

# --- Flow d-negative (sport 3005): record marker is undecodable (fragment
#     length 16 < 24), so the boundary is unknown and the error must stay
#     fatal even after R9190. A following LOOKUP must NOT alert; the flow
#     raises exactly one NFS parser error. The raw LOOKUP name bytes still
#     reach the sensor. ---
fd = Flow(3005, 5.0)
fd.handshake()
fd.c2s(rpc_call(0xE0, NULL, b""))                      # good NULL, NFS detected
bad_marker = frag_hdr(16) + u32(0xE1) + u32(0) + b"\x00" * 12  # frag_len < 24
fd.c2s(bad_marker)
fd.c2s(rpc_call(0xE2, LOOKUP, lookup_args(H3, b"R9190LOOKUPD")))
fd.close()
flows.append(fd)

# --- Flow b-control (sport 3006): the identical 804-byte reply_state = 2
#     record of flow b, delivered complete (un-split), then the same good
#     reply in the next segment. The complete-record path only marks it
#     malformed, so the marker already alerts on the vulnerable baseline. ---
fbc = Flow(3006, 6.0)
fbc.handshake()
fbc.c2s(rpc_call(0xC1, READ, read_args(H1, 0, 512)))
fbc.c2s(rpc_call(0xC2, READ, read_args(H2, 0, 512)))
fbc.s2c(bad_b)                                         # complete 804-byte record
fbc.s2c(good_b)
fbc.close()
flows.append(fbc)

# --- Flow c-control (sport 3007): the identical 804-byte WRITE record of
#     flow c (creds_len 0x2000), delivered complete (un-split), then the same
#     LOOKUP in the next segment. Already non-fatal on the vulnerable
#     baseline. ---
fcc = Flow(3007, 7.0)
fcc.handshake()
fcc.c2s(rpc_call(0xD0, NULL, b""))
fcc.c2s(write_rec)                                     # complete 804-byte record
fcc.c2s(lookup_c)
fcc.close()
flows.append(fcc)

# --- Flow e-attack (sport 3008): to-server partial NFSv4 COMPOUND call whose
#     RPC call header is invalid at the RPC level (AUTH_UNIX creds_len 0x2000)
#     while marker / xid / msgtype / program / version 4 / COMPOUND are valid.
#     This takes the NFSv4 partial-WRITE scan of parse_tcp_partial_data_ts
#     (active with the default non-zero max-write-size), not the NFSv3 WRITE
#     fast path of flow c. Remainder + a complete NFSv3 LOOKUP follow. ---
v4_prefix = (
    frag_hdr(BIG_REC)
    + u32(0xF1) + u32(0)                               # xid, CALL
    + u32(2) + u32(NFS_PROGRAM) + u32(4) + u32(COMPOUND4)  # rpc/prog/v4/COMPOUND
    + u32(1)                                           # creds_flavor AUTH_UNIX
    + u32(0x2000)                                      # creds_len: absurd
)
v4_rec = padded(v4_prefix)                             # full 804-byte record
seg1e = v4_rec[:72]                                    # >= 44, < rec, includes creds_len
taile = v4_rec[72:]                                    # rest of the COMPOUND record
lookup_e = rpc_call(0xF2, LOOKUP, lookup_args(H3, b"R9190LOOKUPE"))
fe = Flow(3008, 8.0)
fe.handshake()
fe.c2s(rpc_call(0xF0, NULL, b""))                      # establish NFS
fe.c2s(seg1e)
fe.c2s(taile + lookup_e)
fe.close()
flows.append(fe)

# --- Flow e-control (sport 3009): the identical 804-byte NFSv4 record of
#     flow e, delivered complete (un-split), then the same LOOKUP. Already
#     non-fatal on the vulnerable baseline. ---
fec = Flow(3009, 9.0)
fec.handshake()
fec.c2s(rpc_call(0xF0, NULL, b""))
fec.c2s(v4_rec)                                        # complete 804-byte record
fec.c2s(lookup_e)
fec.close()
flows.append(fec)

# ---- Exact-boundary flows (f, g) -----------------------------------------
# These flows prove that the skip lands EXACTLY on the record boundary given
# by the record marker, rather than resynchronising by scanning the stream for
# something that looks like an RPC record (as the post-GAP nfs_probe catch-up
# does). The unread tail of each malformed partial record starts with a
# complete, well-formed embedded record (built with the same helpers as the
# genuine records, so it parses if it is ever treated as a record) followed by
# zero filler to the record end. The genuine record follows the true record
# boundary in the same segment. A parser that skips exactly never parses the
# embedded record; one that scans, or that just resumes after the buffered
# bytes, parses it (and then trips over the zero filler).
EMBED_NAME_F = b"R9190EMBEDTS"     # embedded LOOKUP name (must never parse)
REAL_NAME_F = b"R9190LOOKUPF"      # genuine LOOKUP name after the boundary
MARKER_EMB = b"R9190EMBEDTC-" + b"0123456789" * 2 + b"XYZ"  # 36 bytes
MARKER_G = b"R9190MARK-G-" + b"0123456789" * 2 + b"ABCD"     # 36 bytes

# Flow f: an 804-byte NFSv3 WRITE call. Its 76-byte header (first delivery)
# is self-consistent except for stable = 3: count = data length = 728, the
# data running exactly to the record end. The 728-byte data area, i.e. the
# whole unread tail, starts with the embedded LOOKUP call record.
embed_f = rpc_call(0x1F2, LOOKUP, lookup_args(H2, EMBED_NAME_F))   # 72 bytes
wf_data_len = BIG_REC + 4 - 76
write_f_head = rpc_call(0x1F1, WRITE,
                        xdr_opaque(H1) + u64(0) + u32(wf_data_len)
                        + u32(3)                       # stable = 3 (invalid)
                        + u32(wf_data_len),            # data length
                        frag_len=BIG_REC)
assert len(write_f_head) == 76, len(write_f_head)
write_f = padded(write_f_head + embed_f)               # full 804-byte record
seg1f = write_f[:len(write_f_head)]                    # >= 44, ends after stable
tailf = write_f[len(seg1f):]                           # embedded LOOKUP + zeros
lookup_f = rpc_call(0x1F3, LOOKUP, lookup_args(H3, REAL_NAME_F))
assert tailf.startswith(embed_f) and len(seg1f) + len(tailf) == BIG_REC + 4

# Flow g: an 804-byte NFSv3 READ reply with the attributes present. Its
# 132-byte header (first delivery, at least 128) is self-consistent except for
# eof = 2: count = data length = 672, the data running exactly to the record
# end. The 672-byte data area, i.e. the whole unread tail, starts with an
# embedded READ reply record for READ xid 0x1C2, which is outstanding
# (requested on handle H2, never answered).
embed_g = read_reply_record(0x1C2, MARKER_EMB, count=len(MARKER_EMB), eof=1)
rg_data_len = BIG_REC + 4 - 132
bad_g_head = rpc_reply(0x1C1,
                       read_reply_prog(b"", count=rg_data_len, eof=2,
                                       attr_follows=1, data_len=rg_data_len),
                       frag_len=BIG_REC)
assert len(bad_g_head) == 132, len(bad_g_head)
bad_g = padded(bad_g_head + embed_g)                   # full 804-byte record
seg1g = bad_g[:len(bad_g_head)]                        # >= 128, ends after eof
tailg = bad_g[len(seg1g):]                             # embedded reply + zeros
good_g = read_reply_record(0x1C3, MARKER_G, count=len(MARKER_G), eof=1)
assert tailg.startswith(embed_g) and len(seg1g) + len(tailg) == BIG_REC + 4

# --- Flow f-attack (sport 3010): to-server. NULL, then the first 76 bytes of
#     the malformed WRITE (ending after stable = 3 and the data length), then
#     the 728-byte unread tail (embedded LOOKUP R9190EMBEDTS + zeros) and the
#     genuine LOOKUP R9190LOOKUPF in one segment. ---
ff = Flow(3010, 10.0)
ff.handshake()
ff.c2s(rpc_call(0x1F0, NULL, b""))                     # establish NFS
ff.c2s(seg1f)
ff.c2s(tailf + lookup_f)
ff.close()
flows.append(ff)

# --- Flow f-control (sport 3011): the identical 804-byte WRITE record of flow
#     f delivered complete (un-split), with the genuine LOOKUP in the same
#     segment. The complete-record path skips the record by its marker on
#     every build: the reference behavior for flow f. ---
ffc = Flow(3011, 11.0)
ffc.handshake()
ffc.c2s(rpc_call(0x1F0, NULL, b""))
ffc.c2s(write_f + lookup_f)                            # complete record + LOOKUP
ffc.close()
flows.append(ffc)

# --- Flow g-attack (sport 3012): to-client. READ requests 0x1C1 (H1, the
#     malformed reply), 0x1C2 (H2, matched only by the embedded reply) and
#     0x1C3 (H3, the genuine reply). Then the first 132 bytes of the malformed
#     reply, then the 672-byte unread tail (embedded reply R9190EMBEDTC +
#     zeros) and the genuine reply R9190MARK-G in one segment. ---
fg = Flow(3012, 12.0)
fg.handshake()
fg.c2s(rpc_call(0x1C1, READ, read_args(H1, 0, rg_data_len)))
fg.c2s(rpc_call(0x1C2, READ, read_args(H2, 0, len(MARKER_EMB))))
fg.c2s(rpc_call(0x1C3, READ, read_args(H3, 0, len(MARKER_G))))
fg.s2c(seg1g)
fg.s2c(tailg + good_g)
fg.close()
flows.append(fg)

# --- Flow g-control (sport 3013): the identical 804-byte READ reply of flow g
#     delivered complete (un-split), with the genuine reply in the same
#     segment: the reference behavior for flow g. ---
fgc = Flow(3013, 13.0)
fgc.handshake()
fgc.c2s(rpc_call(0x1C1, READ, read_args(H1, 0, rg_data_len)))
fgc.c2s(rpc_call(0x1C2, READ, read_args(H2, 0, len(MARKER_EMB))))
fgc.c2s(rpc_call(0x1C3, READ, read_args(H3, 0, len(MARKER_G))))
fgc.s2c(bad_g + good_g)                                # complete record + reply
fgc.close()
flows.append(fgc)

# ---- Duplicate-xid flows (h) ---------------------------------------------
# A malformed READ reply ends its request: the complete-record path removes
# the xid from the request map before it parses the reply body, so a later
# reply reusing that xid matches no request and is ignored. Skipping a
# malformed partial READ reply must remove the request as well, else a later
# valid reply reusing the xid is taken as the data of the skipped READ and
# logged as a file. A sentinel reply to a second READ follows the duplicate,
# showing the to-client direction still parses records after it (the
# duplicate is ignored, not lost), and a final LOOKUP shows the to-server
# direction is still parsed.
MARKER_DUP = b"R9190DUPXID-" + b"0123456789" * 2 + b"WXYZ"  # 36 bytes
MARKER_H = b"R9190MARK-H-" + b"0123456789" * 2 + b"ABCD"     # 36 bytes
REAL_NAME_H = b"R9190LOOKUPH"      # LOOKUP name after the duplicate

# Flow h: an 804-byte NFSv3 READ reply to xid 0x1D1 without attributes. Its
# 48-byte header is self-consistent except for eof = 2: count = data length =
# 756, the zero-filled data running exactly to the record end.
rh_data_len = BIG_REC + 4 - 48
bad_h_head = rpc_reply(0x1D1,
                       read_reply_prog(b"", count=rh_data_len, eof=2,
                                       data_len=rh_data_len),
                       frag_len=BIG_REC)
assert len(bad_h_head) == 48, len(bad_h_head)
bad_h = padded(bad_h_head)                             # full 804-byte record
seg1h = bad_h[:140]                                    # >= 128, includes eof
tailh = bad_h[len(seg1h):]                             # rest of the record
dup_h = read_reply_record(0x1D1, MARKER_DUP, count=len(MARKER_DUP), eof=1)
good_h = read_reply_record(0x1D2, MARKER_H, count=len(MARKER_H), eof=1)
lookup_h = rpc_call(0x1D3, LOOKUP, lookup_args(H3, REAL_NAME_H))
assert len(seg1h) + len(tailh) == BIG_REC + 4

# --- Flow h-attack (sport 3014): to-client. READ requests 0x1D1 (H1, the
#     malformed reply) and 0x1D2 (H2, the sentinel). Then the first 140 bytes
#     of the malformed reply (ending inside the zero-filled data), the 664-byte
#     record tail, a valid reply reusing xid 0x1D1 (data R9190DUPXID), the
#     sentinel reply to 0x1D2 (data R9190MARK-H) and a LOOKUP for
#     R9190LOOKUPH, each in its own segment. ---
fh = Flow(3014, 14.0)
fh.handshake()
fh.c2s(rpc_call(0x1D1, READ, read_args(H1, 0, rh_data_len)))
fh.c2s(rpc_call(0x1D2, READ, read_args(H2, 0, len(MARKER_H))))
fh.s2c(seg1h)
fh.s2c(tailh)
fh.s2c(dup_h)
fh.s2c(good_h)
fh.c2s(lookup_h)
fh.close()
flows.append(fh)

# --- Flow h-control (sport 3015): the identical 804-byte reply of flow h
#     delivered complete (un-split), then the same duplicate reply, sentinel
#     reply and LOOKUP. The complete-record path removes xid 0x1D1 from the
#     request map on every build, so the duplicate is ignored: the reference
#     behavior for flow h. ---
fhc = Flow(3015, 15.0)
fhc.handshake()
fhc.c2s(rpc_call(0x1D1, READ, read_args(H1, 0, rh_data_len)))
fhc.c2s(rpc_call(0x1D2, READ, read_args(H2, 0, len(MARKER_H))))
fhc.s2c(bad_h)                                         # complete 804-byte record
fhc.s2c(dup_h)
fhc.s2c(good_h)
fhc.c2s(lookup_h)
fhc.close()
flows.append(fhc)

packets = []
for f in flows:
    packets.extend(f.pkts)

here = os.path.dirname(os.path.abspath(__file__))
wrpcap(os.path.join(here, "input.pcap"), packets)

print("records:")
print("  a good reply data_len =", len(MARKER_A),
      "sha256 =", hashlib.sha256(MARKER_A).hexdigest())
print("  b good reply data_len =", len(MARKER_B),
      "sha256 =", hashlib.sha256(MARKER_B).hexdigest())
print("  a bad reply rec_size =", BIG_REC + 4, "seg1 =", len(seg1),
      "tail =", len(tail))
print("  b bad reply rec_size =", BIG_REC + 4, "seg1 =", len(seg1b),
      "tail =", len(tailb))
print("  c write rec_size    =", BIG_REC + 4, "seg1 =", len(seg1c),
      "tail =", len(tailc), "lookup =", len(lookup_c))
print("  e v4 call rec_size  =", BIG_REC + 4, "seg1 =", len(seg1e),
      "tail =", len(taile), "lookup =", len(lookup_e))
print("  seg1 a bytes =", len(seg1), " seg1 b bytes =", len(seg1b))
print("  f write rec_size    =", BIG_REC + 4, "seg1 =", len(seg1f),
      "tail =", len(tailf), "embedded lookup =", len(embed_f),
      "lookup =", len(lookup_f))
print("  g bad reply rec_size =", BIG_REC + 4, "seg1 =", len(seg1g),
      "tail =", len(tailg), "embedded reply =", len(embed_g),
      "good reply =", len(good_g))
print("  g good reply data_len =", len(MARKER_G),
      "sha256 =", hashlib.sha256(MARKER_G).hexdigest())
print("  g embedded data_len =", len(MARKER_EMB),
      "sha256 =", hashlib.sha256(MARKER_EMB).hexdigest())
print("  h bad reply rec_size =", BIG_REC + 4, "seg1 =", len(seg1h),
      "tail =", len(tailh), "duplicate reply =", len(dup_h),
      "sentinel reply =", len(good_h), "lookup =", len(lookup_h))
print("  h sentinel data_len =", len(MARKER_H),
      "sha256 =", hashlib.sha256(MARKER_H).hexdigest())
print("  h duplicate data_len =", len(MARKER_DUP),
      "sha256 =", hashlib.sha256(MARKER_DUP).hexdigest())
print("  packets =", len(packets))
