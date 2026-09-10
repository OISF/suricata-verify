#!/usr/bin/env python3
"""Generate pcaps for the nfs4-malformed-compound-{request,response},
nfs-size-limit-zero, nfs4-gss-integrity-{write,read} and
nfs4-createsession-partial-write suricata-verify tests.

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


# ---------------------------------------------------------------- GSS helpers

def gss_creds():
    # RPCSEC_GSS credential: version procedure seqnum service ctx.
    # procedure=0, service=2 = integrity: the analyzer unwraps the
    # (length, seqnum, data) envelope around the compound for this
    # combination (full record path and partial scan).
    return be32(1) + be32(0) + be32(1) + be32(2) + be32(0)


def req_record_gss(xid, progver, proc, prog_data, frag_len=None):
    body = (be32(xid) + be32(0) + be32(2) + be32(NFS_PROG) +
            be32(progver) + be32(proc) + be32(6) + be32(len(gss_creds())) +
            gss_creds() + be32(0) + be32(0) + prog_data)
    return marker(frag_len if frag_len is not None else len(body)) + body


def gss_envelope(compound, seq=1):
    # the integrity wrapper the analyzer expects inside prog_data
    return be32(len(compound)) + be32(seq) + compound


WRITE_CLAIM = 17 * 1024 * 1024 + 4  # above the 16 MiB default


def v4_write_compound(write_len=WRITE_CLAIM):
    # PUTFH + WRITE: the WRITE claims write_len but the compound carries
    # no data (claim vs data desync, cf. Redmine #8791)
    putfh = be32(22) + fh3()
    write = (be32(38) + be32(1) + b"\x00" * 12 +   # stateid
             be64(0) + be32(2) + be32(write_len))  # offset stable write_len
    return be32(0) + be32(0) + be32(2) + putfh + write


def v4_read_req_compound(count=4096):
    # PUTFH + READ request op (stateid, offset, count)
    putfh = be32(22) + fh3()
    read = be32(25) + be32(1) + b"\x00" * 12 + be64(0) + be32(count)
    return be32(0) + be32(0) + be32(2) + putfh + read


def v4_read_reply_compound(read_len=WRITE_CLAIM):
    # compound status, tag, ops_cnt, READ op (status 0, eof 1, read_len)
    return (be32(0) + be32(0) + be32(1) +
            be32(25) + be32(0) + be32(1) + be32(read_len))


def v4_sequence_read_req_compound(count=8192):
    # NFSv4.1 request: SEQUENCE (32-byte args), PUTFH, READ. Establishes the
    # file (PUTFH) and requests a `count`-byte read.
    sequence = (be32(53) + b"\x22" * 16 + be32(1) + be32(1) +
                be32(1) + be32(0))  # ssn_id(16) + seqid/slot/high/cache
    putfh = be32(22) + fh3()
    read = be32(25) + be32(1) + b"\x00" * 12 + be64(0) + be32(count)
    return be32(0) + be32(0) + be32(3) + sequence + putfh + read


def v4_sequence_read_reply_compound(read_len=8192):
    # NFSv4.1 reply: SEQUENCE (status 0 + 36-byte sequence_ok result),
    # PUTFH (status 0, no result), READ (status 0, eof 0, read_len, data).
    # The response scanner must skip the 36-byte SEQUENCE result to reach
    # the READ; without that the compound is rejected as malformed.
    sequence = be32(53) + be32(0) + b"\x11" * 36
    putfh = be32(22) + be32(0)
    read = be32(25) + be32(0) + be32(0) + be32(read_len) + b"\x77" * read_len
    return be32(0) + be32(0) + be32(3) + sequence + putfh + read


def v4_createsession_op(machine_name=b"nfsclient", variant="auth_none"):
    # A valid-looking CREATE_SESSION op: clientid4, seqid, flags,
    # fore/back channel_attributes4, cb program/version, g flavor/stamp,
    # machine name. The channel attributes carry realistic values (the
    # 0x33333333 RDMA counts in the original fixture were invalid); the
    # "rdma" variant carries a non-empty channel netid, so the op is
    # variable-length. The scanner rejects the op tag (not reliably
    # skippable) regardless of these args.
    clientid = bytes(range(0xa0, 0xa8))
    seqid = be32(1)
    flags = be32(0)
    # channel_attributes4: high_tls, session_cached_lb, slot_table_size,
    # xdr_minsize, xdr_maxsize, hauth_maxreqs, sc_first, sc_backchannel
    chan = (be32(0) + be32(0) + be32(128) + be32(64) +
            be32(1 << 20) + be32(256) + be32(0) + be32(0))
    cb_program = be32(0)
    cb_version = be32(0)
    g_flavor = be32(0)
    if variant == "auth_sys":
        cb_program = be32(NFS_PROG)
        cb_version = be32(3)
        g_flavor = be32(1)
    elif variant == "rdma":
        # a non-empty channel netid makes the attributes variable-length
        chan += be32(4) + b"rdma"
        cb_program = be32(NFS_PROG)
        cb_version = be32(4)
        g_flavor = be32(1)
    g_stamp = be32(0x5f3c0000)
    name = be32(len(machine_name)) + machine_name
    pad = (4 - (len(machine_name) % 4)) % 4
    return (be32(43) + clientid + seqid + flags + chan + chan +
            cb_program + cb_version + g_flavor + g_stamp +
            name + b"\x00" * pad)


def v4_createsession_write_compound(write_len=WRITE_CLAIM, variant="auth_none"):
    # CREATE_SESSION (a valid variable-length op) followed by an oversized
    # WRITE. The scanner must not advance past the CREATE_SESSION op: it
    # rejects the compound (bounded, Malformed) instead of Incomplete.
    write = (be32(38) + be32(1) + b"\x00" * 12 +
             be64(0) + be32(2) + be32(write_len))
    return (be32(0) + be32(0) + be32(2) +
            v4_createsession_op(variant=variant) + write)


def v4_open_write_compound(write_len=WRITE_CLAIM):
    # OPEN (with a CLAIM4_DELEGATE_CUR claim) followed by an oversized
    # WRITE. The scanner must not advance past the OPEN's open_claim4
    # union (a CLAIM4_DELEGATE_CUR stateid seqid would be misread as a
    # filename length by a non-union-aware parser): bounded rejection
    # (Malformed), never Incomplete.
    seqid = be32(1)
    share_access = be32(0)
    share_deny = be32(0)
    clientid = bytes(range(0xb0, 0xb8))
    owner = be32(0)    # OPEN4_NONGROUP (no clientid in the union arm)
    how = be32(0)      # OPEN4_CURRENT
    claim_type = be32(3)  # CLAIM4_DELEGATE_CUR
    # the claim carries a stateid4; its seqid would be misread as a
    # filename length by a non-union-aware parser
    claim = be32(0x01000000) + b"\x00" * 12  # stateid4
    filename = be32(5) + b"nfsfile"
    open_op = (be32(18) + seqid + share_access + share_deny + clientid +
               owner + how + claim_type + claim + filename)
    write = (be32(38) + be32(1) + b"\x00" * 12 +
             be64(0) + be32(2) + be32(write_len))
    return be32(0) + be32(0) + be32(2) + open_op + write


def v4_read_write_req_compound(write_len=8192):
    # PUTFH + READ (stateid, offset, count) + WRITE (stateid, offset,
    # stable, write_len, data). The READ (request) is a valid op the
    # scanner must skip to reach the following within-limit WRITE.
    putfh = be32(22) + fh3()
    read = be32(25) + be32(1) + b"\x00" * 12 + be64(0) + be32(write_len)
    write = (be32(38) + be32(1) + b"\x00" * 12 +
             be64(0) + be32(2) + be32(write_len) + b"\x99" * write_len)
    return be32(0) + be32(0) + be32(3) + putfh + read + write


def v4_open_getfh_read_reply_compound(read_len=8192):
    # status, tag, ops_cnt, OPEN (status 0 + open_ok4: stateid, change_info,
    # result_flags, fattr4 attr_cnt(0) + mask1 -- the parser always reads
    # mask1 -- delegate NONE), GETFH (status 0 + 32-byte fh, 4-aligned:
    # no XDR pad), READ (status 0, eof 0, read_len, data). The OPEN
    # (response) is a valid op the scanner must skip to reach the
    # within-limit READ; the GETFH result mirrors the request's PUTFH
    # handle, so the tx file state stays intact.
    open_op = (be32(18) + be32(0) + b"\x00" * 16 + b"\x00" * 20 +
               be32(0) + be32(0) + be32(0) + be32(0))
    getfh = be32(10) + be32(0) + fh3()
    read = be32(25) + be32(0) + be32(0) + be32(read_len) + b"\x77" * read_len
    return be32(0) + be32(0) + be32(3) + open_op + getfh + read


def v4_write_reply(xid, count):
    # compound status, tag, ops_cnt=1, WRITE res (status 0 + count +
    # committed + verifier)
    prog_data = (be32(0) + be32(0) + be32(1) +
                 be32(38) + be32(0) + be32(count) + be32(0) + be64(0))
    return reply_record(xid, prog_data)


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


def v3_write_req(xid, offset, count, data, stable=0, fh=None):
    # fh offset count stable file_len data. stable=0 (UNSTABLE): the file
    # tx stays open, so the in-progress chunk is fed by later stream data;
    # stable=2 closes the tx and the remaining chunk bytes are dropped.
    if fh is None:
        fh = fh3()
    prog_data = (fh + be64(offset) + be32(count) + be32(stable) +
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
        # SYN/SYN-ACK consume one sequence number, data packets consume
        # their payload length, pure ACKs consume nothing
        if d == "c":
            p = (IP(src=CLIENT, dst=SERVER) /
                 TCP(sport=self.cport, dport=NFS_PORT, seq=self.cseq,
                     ack=self.ack_c, flags=flags, window=self.window) /
                 Raw(load=payload))
            if payload:
                self.cseq += len(payload)
            elif flags in ("S", "SA"):
                self.cseq += 1
            # the server will ack up to the client's new position
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

# ---------------------------------------------------------------- test D
# RPCSEC_GSS integrity-wrapped oversized WRITE (request side). The partial
# scan must unwrap the envelope before scanning: scanning the raw envelope
# would read its length as the compound tag length and buffer toward the
# 8 KiB claim (Redmine #8791) instead of rejecting the 17 MiB claim.
flow = Flow(883)
flow.handshake()
flow.data("c", v4_getattr_req(0x11111111))
flow.data("s", v4_getattr_reply(0x11111111))
comp = v4_write_compound()
env = gss_envelope(comp)
hdr = (be32(0x22222222) + be32(0) + be32(2) + be32(NFS_PROG) +
       be32(4) + be32(1) + be32(6) + be32(len(gss_creds())) +
       gss_creds() + be32(0) + be32(0))
p1 = marker(8188) + hdr + env + b"\xaa" * (4096 - 4 - len(hdr) - len(env))
p2 = b"\xaa" * 4096
flow.data("c", p1, seg=4096)
flow.tcp("s", "A")
flow.data("c", p2, seg=4096)
flow.close()
wrpcap("tests/nfs4-gss-integrity-write/input.pcap", flow.pkts)
print("test D:", len(flow.pkts), "pkts, envelope", len(env))

# ---------------------------------------------------------------- test E
# RPCSEC_GSS integrity-wrapped oversized READ (response side). The request
# (complete, small) records the (0, 2) GSS combination in the xidmap; the
# partial reply scan must unwrap via that and reject the 17 MiB claim
# instead of buffering toward the 8 KiB record claim.
flow = Flow(884)
flow.handshake()
flow.data("c", v4_getattr_req(0x11111111))
flow.data("s", v4_getattr_reply(0x11111111))
rcomp = v4_read_req_compound()
renv = gss_envelope(rcomp)
rhdr = (be32(0x88888888) + be32(0) + be32(2) + be32(NFS_PROG) +
       be32(4) + be32(1) + be32(6) + be32(len(gss_creds())) +
       gss_creds() + be32(0) + be32(0))
flow.data("c", marker(len(rhdr) + len(renv)) + rhdr + renv)
flow.tcp("s", "A")
wcomp = v4_read_reply_compound()
wenv = gss_envelope(wcomp, seq=2)
whdr = (be32(0x88888888) + be32(1) + be32(0) + be32(0) +
        be32(0) + be32(0))               # ..verf_len accept_state
p1 = marker(8188) + whdr + wenv + b"\xbb" * (4096 - 4 - len(whdr) - len(wenv))
p2 = b"\xbb" * 4096
flow.data("s", p1, seg=4096)
flow.tcp("c", "A")
flow.data("s", p2, seg=4096)
flow.close()
wrpcap("tests/nfs4-gss-integrity-read/input.pcap", flow.pkts)
print("test E:", len(flow.pkts), "pkts")

# ---------------------------------------------------------------- test F
# CREATE_SESSION (a valid variable-length op) leading an oversized WRITE.
# The scanner must not advance past the CREATE_SESSION op: it rejects the
# compound (bounded, Malformed) instead of returning Incomplete and
# buffering toward the claim (Redmine #8791). Three channel variants
# (AUTH_NONE, AUTH_SYS, non-empty RDMA) are covered.
flow = Flow(885)
flow.handshake()
flow.data("c", v4_getattr_req(0x11111111))
flow.data("s", v4_getattr_reply(0x11111111))
for i, variant in enumerate(("auth_none", "auth_sys", "rdma")):
    comp = v4_createsession_write_compound(variant=variant)
    xid = 0x99990001 + i
    hdr = (be32(xid) + be32(0) + be32(2) + be32(NFS_PROG) +
           be32(4) + be32(1) + be32(0) + be32(0) + be32(0) + be32(0))
    p1 = marker(8188) + hdr + comp + b"\xcc" * (4096 - 4 - len(hdr) - len(comp))
    p2 = b"\xcc" * 4096
    flow.data("c", p1, seg=4096)
    flow.tcp("s", "A")
    flow.data("c", p2, seg=4096)
flow.close()
wrpcap("tests/nfs4-createsession-partial-write/input.pcap", flow.pkts)
print("test F:", len(flow.pkts), "pkts")

# ---------------------------------------------------------------- test G
# OPEN (CLAIM4_DELEGATE_CUR) leading an oversized WRITE. The scanner must
# not advance past the OPEN's open_claim4 union (a CLAIM4_DELEGATE_CUR
# stateid seqid would be misread as a filename length by a non-union-aware
# parser): bounded rejection (Malformed), never Incomplete and never
# buffering toward the claim (Redmine #8791).
flow = Flow(886)
flow.handshake()
flow.data("c", v4_getattr_req(0x11111111))
flow.data("s", v4_getattr_reply(0x11111111))
comp = v4_open_write_compound()
hdr = (be32(0x88880001) + be32(0) + be32(2) + be32(NFS_PROG) +
       be32(4) + be32(1) + be32(0) + be32(0) + be32(0) + be32(0))
p1 = marker(8188) + hdr + comp + b"\xcc" * (4096 - 4 - len(hdr) - len(comp))
p2 = b"\xcc" * 4096
flow.data("c", p1, seg=4096)
flow.tcp("s", "A")
flow.data("c", p2, seg=4096)
flow.close()
wrpcap("tests/nfs4-open-partial-write/input.pcap", flow.pkts)
print("test G:", len(flow.pkts), "pkts")

# ---------------------------------------------------------------- test H
# A fragmented NFSv4.1 SEQUENCE; PUTFH; READ reply. The response scanner
# must skip the 36-byte successful SEQUENCE result (and the PUTFH status)
# to reach the READ; without that the compound is rejected as malformed and
# the read data is never inspected. The read is within the limit, so the
# record completes and the file is logged (size 8192); the check asserts
# the fileinfo event and no malformed_data.
flow = Flow(887)
flow.handshake()
flow.data("c", v4_getattr_req(0x11111111))
flow.data("s", v4_getattr_reply(0x11111111))
# the read request (SEQUENCE; PUTFH; READ): establishes the file
rcomp = v4_sequence_read_req_compound(8192)
rhdr = (be32(0x77777777) + be32(0) + be32(2) + be32(NFS_PROG) +
        be32(4) + be32(1) + be32(0) + be32(0) + be32(0) + be32(0))
flow.data("c", marker(len(rhdr) + len(rcomp)) + rhdr + rcomp)
flow.tcp("s", "A")
# the fragmented SEQUENCE; PUTFH; READ reply (within-limit 8192-byte read)
wcomp = v4_sequence_read_reply_compound(8192)
whdr = (be32(0x77777777) + be32(1) + be32(0) + be32(0) +
        be32(0) + be32(0))
body = whdr + wcomp
p1 = marker(len(body)) + body[:4092]
p2 = body[4092:]
flow.data("s", p1, seg=4096)
flow.tcp("c", "A")
flow.data("s", p2, seg=4096)
flow.close()
wrpcap("tests/nfs4-sequence-read-partial/input.pcap", flow.pkts)
print("test H:", len(flow.pkts), "pkts")

# ---------------------------------------------------------------- test I
# A fragmented PUTFH; READ; WRITE request (within-limit 8192-byte write).
# The request scanner must skip the READ (a valid op the full parser
# supports) to reach the WRITE; without that the compound is rejected as
# malformed and the write data is never inspected. The write is within the
# limit, so the record completes and the file is logged (size 8192).
flow = Flow(888)
flow.handshake()
flow.data("c", v4_getattr_req(0x11111111))
flow.data("s", v4_getattr_reply(0x11111111))
comp = v4_read_write_req_compound(8192)
hdr = (be32(0x77777777) + be32(0) + be32(2) + be32(NFS_PROG) +
       be32(4) + be32(1) + be32(0) + be32(0) + be32(0) + be32(0))
body = hdr + comp
full = marker(len(body)) + body
# first packet: marker + hdr + compound header + PUTFH + READ cmd tag
p1 = full[:100]
p2 = full[100:]
flow.data("c", p1, seg=4096)
flow.tcp("s", "A")
flow.data("c", p2, seg=4096)
flow.tcp("s", "A")
flow.data("s", v4_write_reply(0x77777777, 8192))
flow.close()
wrpcap("tests/nfs4-partial-request-read-write/input.pcap", flow.pkts)
print("test I:", len(flow.pkts), "pkts")

# ---------------------------------------------------------------- test J
# A fragmented OPEN; GETFH; READ reply (within-limit 8192-byte read). The
# response scanner must skip the OPEN (a valid op the full parser supports)
# to reach the READ; without that the compound is rejected as malformed and
# the read data is never inspected. The read is within the limit, so the
# record completes and the file is logged (size 8192).
flow = Flow(889)
flow.handshake()
flow.data("c", v4_getattr_req(0x11111111))
flow.data("s", v4_getattr_reply(0x11111111))
rcomp = v4_read_req_compound(8192)
rhdr = (be32(0x88888888) + be32(0) + be32(2) + be32(NFS_PROG) +
        be32(4) + be32(1) + be32(0) + be32(0) + be32(0) + be32(0))
flow.data("c", marker(len(rhdr) + len(rcomp)) + rhdr + rcomp)
flow.tcp("s", "A")
comp = v4_open_getfh_read_reply_compound(8192)
whdr = (be32(0x88888888) + be32(1) + be32(0) + be32(0) +
        be32(0) + be32(0))
body = whdr + comp
p1 = marker(len(body)) + body[:4092]
p2 = body[4092:]
flow.data("s", p1, seg=4096)
flow.tcp("c", "A")
flow.data("s", p2, seg=4096)
flow.close()
wrpcap("tests/nfs4-partial-response-open-read/input.pcap", flow.pkts)
print("test J:", len(flow.pkts), "pkts")

# ---------------------------------------------------------------- test K
# A fragmented PUTFH; OPEN; GETFH request compound (record >= 512 bytes):
# the OPEN (request) is a valid op the full parser supports but had no
# scanner skip entry, so the record was rejected malformed and the OPEN's
# filename association was lost. The OPEN (open_type 0, CLAIM_NULL) is
# padded via the owner name to push the record past 512 bytes; the split
# lands mid-OPEN, right after the OPEN tag. The following PUTFH; READ
# reuses the GETFH handle: the fileinfo must carry the OPEN's filename
# (association via the namemap), proving the record was inspected.
def v4_open_getfh_req_compound(name=b"opengetfhfile", owner_len=512):
    putfh = be32(22) + fh3()
    # owner (len + bytes, no XDR pad: 4-aligned) pads the record past 512
    owner = be32(owner_len) + b"\x0f" * owner_len
    # seq_id share_access share_deny client_id owner open_type claim_type name
    open_op = (be32(18) + be32(8192) + be32(2) + be32(0) + be32(123) +
               be32(12345) + owner + be32(0) + be32(0) +
               be32(len(name)) + name + b"\x00" * (-len(name) % 4))
    getfh = be32(10)
    return be32(0) + be32(0) + be32(3) + putfh + open_op + getfh


def v4_open_getfh_reply_compound():
    # OPEN res (status 0 + open_ok4: stateid, change_info, result_flags,
    # delegate NONE) + GETFH res (status 0 + 32-byte fh, 4-aligned).
    open_op = (be32(18) + be32(0) + b"\x00" * 16 + b"\x00" * 20 +
               be32(0) + be32(0) + be32(0) + be32(0))
    getfh = be32(10) + be32(0) + fh3()
    return be32(0) + be32(0) + be32(2) + open_op + getfh


def v4_read_data_reply_compound(read_len=8192):
    read = be32(25) + be32(0) + be32(0) + be32(read_len) + b"\x77" * read_len
    return be32(0) + be32(0) + be32(1) + read


flow = Flow(890)
flow.handshake()
flow.data("c", v4_getattr_req(0x11111111))
flow.data("s", v4_getattr_reply(0x11111111))
comp = v4_open_getfh_req_compound()
hdr = (be32(0x77777777) + be32(0) + be32(2) + be32(NFS_PROG) +
       be32(4) + be32(1) + be32(0) + be32(0) + be32(0) + be32(0))
body = hdr + comp
full = marker(len(body)) + body
assert len(full) >= 512
# first packet ends right after the OPEN tag
p1 = full[:100]
p2 = full[100:]
flow.data("c", p1, seg=4096)
flow.tcp("s", "A")
flow.data("c", p2, seg=4096)
flow.tcp("s", "A")
flow.data("s", reply_record(0x77777777, v4_open_getfh_reply_compound()))
flow.tcp("c", "A")
# the read reuses the GETFH handle (putfh fh3): the filename association
flow.data("c", req_record(0x99999999, 4, 1, v4_read_req_compound(8192)))
flow.tcp("s", "A")
flow.data("s", reply_record(0x99999999, v4_read_data_reply_compound(8192)))
flow.close()
wrpcap("tests/nfs4-partial-request-open-getfh/input.pcap", flow.pkts)
print("test K:", len(flow.pkts), "pkts")

# ---------------------------------------------------------------- test L
# A v3 WRITE with count (4096) > file_len (2048): the chunk promise is
# count-based but the record tail is file_len-based. The continuation
# crosses max-write-queue-size (2048) and the chunk path rejects it; the
# stream must land exactly at the following RPC (a 1000-byte WRITE on a
# second handle), whose file must still be logged. The count-based
# accounting consumed/skipped past the record tail into the following RPC
# and lost the file.
flow = Flow(891)
flow.handshake()
# in-order 100-byte WRITE on fh3: establishes the file tx, stays open
flow.data("c", v3_write_req(0x11111111, 0, 100, b"\x33" * 100))
flow.tcp("s", "A")
flow.data("s", v3_write_reply(0x11111111, 0, 100))
flow.tcp("c", "A")
# the partial WRITE: offset 8192 (OOO), count 4096, file_len 2048.
# Only the header + 512 data bytes ride in the first packet; the record
# claims the full args (1536 bytes of data remain unbuffered).
wcount = 4096
wlen = 2048
prog_data = (fh3() + be64(8192) + be32(wcount) + be32(0) +
             be32(wlen) + b"\x55" * wlen)
body = (be32(0x22222222) + be32(0) + be32(2) + be32(NFS_PROG) +
        be32(3) + be32(7) + be32(0) + be32(0) + be32(0) + be32(0) +
        prog_data)
full = marker(len(body)) + body
first = 4 + 40 + 36 + 8 + 4 + 4 + 4 + 512  # marker hdr fh off cnt stb flen 512
assert first < len(full)
flow.data("c", full[:first], seg=4096)
flow.tcp("s", "A")
# the rest of the record (1536 bytes of file data) followed by a complete
# 1000-byte in-order WRITE on the second handle: the rejection must leave
# this record in the stream, not consume/skip it.
follow = v3_write_req(0x44444444, 0, 1000, b"\x44" * 1000, fh=fh3b())
flow.data("c", full[first:] + follow, seg=64240)
flow.tcp("s", "A")
flow.data("s", v3_write_reply(0x44444444, 0, 1000))
flow.tcp("c", "A")
flow.close()
wrpcap("tests/nfs3-write-count-data-continuation-overflow/input.pcap", flow.pkts)
print("test L:", len(flow.pkts), "pkts")

# ---------------------------------------------------------------- test M
# A short v3 READ reply (data_len < count, complete record) must not arm a
# count-based chunk promise: the promise would outlive the record and eat
# the following reply's bytes as (consume-only) chunk data, losing the
# next read's file. The tracker and the chunk state must follow the data
# actually present in the reply (data_len-based), so the following read's
# new data is stored and the file closes complete.
flow = Flow(892)
flow.handshake()
# T1: full read, 512 bytes at offset 0 (the file is established)
flow.data("c", v3_read_req(0x10000001, 0, 512))
flow.tcp("s", "A")
flow.data("s", v3_read_reply(0x10000001, 512, b"A" * 512, eof=0))
flow.tcp("c", "A")
# T2: SHORT read: count 1000, only 100 bytes of data (all inside the
# tracked region: a covered retransmission, discarded)
flow.data("c", v3_read_req(0x10000002, 0, 1000))
flow.tcp("s", "A")
flow.data("s", v3_read_reply(0x10000002, 1000, b"B" * 100, eof=0))
flow.tcp("c", "A")
# T3: a new in-order read at offset 512: its reply must be parsed as a
# record, not consumed as T2's chunk continuation
flow.data("c", v3_read_req(0x10000003, 512, 512))
flow.tcp("s", "A")
flow.data("s", v3_read_reply(0x10000003, 512, b"C" * 512, eof=1))
flow.close()
wrpcap("tests/nfs3-short-read-continuation/input.pcap", flow.pkts)
print("test M:", len(flow.pkts), "pkts")

# ---------------------------------------------------------------- test N
# Partial v4 COMPOUND request [OPEN, WRITE]: the record claims 4196 bytes,
# only the ~90-byte compound is present. The scanner must skip the OPEN
# with the layout the full parser actually reads (seq_id + share_access +
# share_deny + client_id = 20 bytes before the owner string). The 12-byte
# owner below is crafted so the old 4-byte-off skip misreads it: the
# misaligned compound desyncs and the record is rejected as malformed
# instead of the oversized WRITE (17 MiB claim) being rejected.
def v4_open_oversized_write_compound():
    seqid = be32(1)
    share_access = be32(0)
    share_deny = be32(0)
    clientid = bytes(range(0xb0, 0xb8))
    # owner: first 8 bytes zero, last 4 bytes decode to 65536 -- what the
    # old (4-byte-off) OPEN skip walks over as the misaligned layout
    owner = be32(12) + bytes(8) + be32(65536)
    open_type = be32(0)    # OPEN4_NONE (no open_data)
    claim_type = be32(0)   # CLAIM4_NONE (no claim payload)
    filename = be32(4) + b"file"
    open_op = (be32(18) + seqid + share_access + share_deny + clientid +
               owner + open_type + claim_type + filename)
    write = (be32(38) + be32(1) + b"\x00" * 12 +
             be64(0) + be32(2) + be32(WRITE_CLAIM))
    return be32(0) + be32(0) + be32(2) + open_op + write

flow = Flow(893)
flow.handshake()
# small, complete v4 exchange first: the app layer attaches on the first
# fully parsed record in each direction
flow.data("c", v4_getattr_req(0x11111111))
flow.tcp("s", "A")
flow.data("s", v4_getattr_reply(0x11111111))
flow.tcp("c", "A")
comp = v4_open_oversized_write_compound()
flow.data("c", req_record(0x55555555, 4, 1, comp, frag_len=4196))
flow.close()
wrpcap("tests/nfs4-open-oversized-write-skip/input.pcap", flow.pkts)
print("test N:", len(flow.pkts), "pkts")
