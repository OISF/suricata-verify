#!/usr/bin/env python3
"""Generate input.pcap for the Redmine #9194 NFSv3 WRITE XDR-padding test.

Redmine #9194: a partial NFSv3 WRITE record whose file data ends on a TCP
segment boundary (so the 1-3 XDR pad bytes arrive in a later segment) loses
the pad from the outer continuation accounting. The parser then reads the pad
as the start of the next RPC record marker, raises nfs malformed_data, returns
a fatal error, and NFS inspection stops for the rest of the flow.

Each case is an independent NFSv3/TCP flow (one client source port). A flow
writes a file at offset 0 (WRITE record >= 512 bytes so the partial fast-path
is used), then COMMITs it (closing the UNSTABLE file), then does a LOOKUP that
must alert. The FILE_SYNC case (shape e) needs no COMMIT: the file closes when
its data ends while the pad is still owed.

Shapes control and a-g write a SINGLE-chunk file: this deliberately avoids
the unrelated complete-WRITE stale-fill-bytes defect (which only bites the
NEXT chunk of a multi-chunk file). The chunk2 shapes h-k write a SECOND chunk:
the first WRITE (414 bytes, 2 pad bytes, partial) is followed, right after its
pad, by a complete WRITE of an aligned 512-byte chunk at offset 414 of the
same handle. That chunk is only stored if the late pad bytes reached the file
tracker and cleared its fill state; a fix that only skipped them in the
stream leaves the fill state set, and the second chunk truncates the file.
No chunk2 flow has a first delivery ending inside the pad: the parser
consumes those pad bytes without telling the tracker, which is the same
out-of-scope stale-fill-bytes defect. Distinct handle and distinct file
content per flow.

New flows are only ever appended to CASES, so earlier flows stay
byte-identical.

Deterministic: fixed MACs, fixed seqs, fixed timestamps. Regenerate with:
    ./make-pcap.py
It writes input.pcap in this directory and prints the per-flow table whose
sizes and sha256 values are pinned in test.yaml.
"""
import hashlib
import os
import struct
from scapy.all import Ether, IP, TCP, Raw, wrpcap


def u32(v):
    return struct.pack(">I", v)


def u64(v):
    return struct.pack(">Q", v)


def xdr_opaque(b):
    pad = (4 - len(b) % 4) % 4
    return u32(len(b)) + b + b"\x00" * pad


def rpc_call(xid, proc, prog, vers=3):
    # AUTH_NULL creds and verifier (flavor 0, len 0 each).
    body = (
        u32(xid) + u32(0) + u32(2) + u32(100003) + u32(vers) + u32(proc)
        + u32(0) + u32(0) + u32(0) + u32(0) + prog
    )
    return u32(0x80000000 | len(body)) + body


def write_args(fh, offset, data, stable):
    # NFSv3 WRITE: handle, offset, count, stable, file_len, data, XDR pad.
    pad = (4 - len(data) % 4) % 4
    return (
        xdr_opaque(fh) + u64(offset) + u32(len(data)) + u32(stable)
        + u32(len(data)) + data + b"\x00" * pad
    )


def commit_args(fh):
    return xdr_opaque(fh) + u64(0) + u32(0)


def lookup_args(dh, name):
    return xdr_opaque(dh) + xdr_opaque(name)


CMAC, SMAC = "02:00:00:00:00:01", "02:00:00:00:00:02"
CIP, SIP = "10.0.0.1", "10.0.0.2"


class Flow:
    def __init__(self, cport, t0):
        self.cp = cport
        self.cseq, self.sseq = 1000, 5000
        self.t = float(t0)
        self.pkts = []

    def _p(self, to_server, flags, payload=b""):
        if to_server:
            p = (Ether(src=CMAC, dst=SMAC) / IP(src=CIP, dst=SIP)
                 / TCP(sport=self.cp, dport=2049, flags=flags,
                       seq=self.cseq, ack=self.sseq))
        else:
            p = (Ether(src=SMAC, dst=CMAC) / IP(src=SIP, dst=CIP)
                 / TCP(sport=2049, dport=self.cp, flags=flags,
                       seq=self.sseq, ack=self.cseq))
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
        # Client segment, then the server ACK that makes Suricata deliver it
        # to the parser as its own chunk.
        self._p(True, "PA", payload); self.cseq += len(payload)
        self._p(False, "A")

    def close(self):
        self._p(True, "FA"); self.cseq += 1
        self._p(False, "FA"); self.sseq += 1
        self._p(True, "A")


def segments(shape, write_rec, pad, data_off, file_len, commit_rec, lookup_rec,
             write2_rec=None):
    hdr = write_rec[:data_off]
    data = write_rec[data_off:data_off + file_len]
    pad_bytes = write_rec[data_off + file_len:]
    assert len(pad_bytes) == pad
    tail = (commit_rec + lookup_rec) if commit_rec is not None else lookup_rec
    if write2_rec is not None:
        # chunk2 shapes: the second WRITE directly follows the first's pad.
        tail = write2_rec + tail
    k = file_len // 2
    if shape == "control":
        return [hdr + data + pad_bytes + tail]
    if shape == "a":
        # seg1 ends on the last file byte; pad + next records follow.
        return [hdr + data, pad_bytes + tail]
    if shape == "b":
        # seg1 ends INSIDE the pad (exactly one pad byte present).
        return [hdr + data + pad_bytes[:1], pad_bytes[1:] + tail]
    if shape == "c":
        # continuation: header+part data | rest of data ending on last byte | pad+next.
        return [hdr + data[:k], data[k:], pad_bytes + tail]
    if shape == "d":
        # like c, but the pad itself is split (1 byte with the data, rest later).
        return [hdr + data[:k], data[k:] + pad_bytes[:1], pad_bytes[1:] + tail]
    if shape == "e":
        # FILE_SYNC shape c, no COMMIT: file closes when data ends, pad still owed.
        return [hdr + data[:k], data[k:], pad_bytes + tail]
    if shape == "f":
        # seg1 ends on the last file byte, then every pad byte but the last
        # arrives alone (each of those deliveries ends inside the pad), then
        # the last pad byte + next records.
        return ([hdr + data] + [pad_bytes[i:i + 1] for i in range(pad - 1)]
                + [pad_bytes[-1:] + tail])
    if shape == "g":
        # continuation, pad alone: header+part data | rest of data ending on
        # last byte | all pad bytes alone | next records.
        return [hdr + data[:k], data[k:], pad_bytes, tail]
    if shape == "h":
        # chunk2 control: split only inside the data; the pad travels with
        # the rest of the data, the second WRITE and the next records.
        return [hdr + data[:k], data[k:] + pad_bytes + tail]
    if shape == "i":
        # chunk2, shape c: header+part data | rest of data ending on last
        # byte | pad + second WRITE + next records.
        return [hdr + data[:k], data[k:], pad_bytes + tail]
    if shape == "j":
        # chunk2, shape d: the pad is split across the 2nd and 3rd deliveries.
        return [hdr + data[:k], data[k:] + pad_bytes[:1], pad_bytes[1:] + tail]
    if shape == "k":
        # chunk2, shape a: header + all file data but no pad byte | pad +
        # second WRITE + next records.
        return [hdr + data, pad_bytes + tail]
    raise ValueError(shape)


# (label, shape, pad_len, sport). pad_len -> file_len: 1->415, 2->414, 3->413.
# Only ever append: earlier flows must stay byte-identical.
PAD_TO_LEN = {1: 415, 2: 414, 3: 413}
CASES = [
    ("control-pad1", "control", 1, 41001),
    ("control-pad2", "control", 2, 41002),
    ("control-pad3", "control", 3, 41003),
    ("split-a-pad1", "a", 1, 42001),
    ("split-a-pad2", "a", 2, 42002),
    ("split-a-pad3", "a", 3, 42003),
    ("split-b-pad2", "b", 2, 43002),
    ("split-b-pad3", "b", 3, 43003),
    ("cont-c-pad1", "c", 1, 44001),
    ("cont-c-pad2", "c", 2, 44002),
    ("cont-c-pad3", "c", 3, 44003),
    ("cont-d-pad2", "d", 2, 45002),
    ("cont-d-pad3", "d", 3, 45003),
    ("filesync-e-pad3", "e", 3, 46003),
    ("split-f-pad3", "f", 3, 47003),
    ("cont-g-pad1", "g", 1, 48001),
    ("cont-g-pad2", "g", 2, 48002),
    ("cont-g-pad3", "g", 3, 48003),
    ("chunk2-h-pad2", "h", 2, 49002),
    ("chunk2-i-pad2", "i", 2, 50002),
    ("chunk2-j-pad2", "j", 2, 51002),
    ("chunk2-k-pad2", "k", 2, 52002),
]

# Shapes whose file gets a second chunk: a complete WRITE record of
# CHUNK2_LEN (4-byte aligned, so no pad of its own) bytes at offset file_len.
CHUNK2_SHAPES = ("h", "i", "j", "k")
CHUNK2_LEN = 512


def main():
    all_pkts = []
    rows = []
    for idx, (label, shape, padlen, sport) in enumerate(CASES):
        file_len = PAD_TO_LEN[padlen]
        # Distinct 32-byte handle and distinct file content per flow.
        fh = bytes([0x10 + idx]) * 32
        seed = ("%s|" % label).encode()
        data = (seed * (file_len // len(seed) + 1))[:file_len]
        stable = 2 if shape == "e" else 0
        xid = 0x9194_0000 + idx
        write_rec = rpc_call(xid, 7, write_args(fh, 0, data, stable))
        pad = (4 - file_len % 4) % 4
        assert pad == padlen, (label, pad, padlen)
        assert len(write_rec) >= 512, (label, len(write_rec))
        data_off = len(write_rec) - file_len - pad
        commit_rec = None if shape == "e" else rpc_call(xid + 0x100, 21, commit_args(fh))
        lookup_rec = rpc_call(xid + 0x200, 3, lookup_args(fh, b"LOOKUPME"))

        write2_rec = None
        file_data = data
        if shape in CHUNK2_SHAPES:
            # Second chunk: same handle, next offset, UNSTABLE, own content.
            seed2 = ("%s|2|" % label).encode()
            data2 = (seed2 * (CHUNK2_LEN // len(seed2) + 1))[:CHUNK2_LEN]
            assert len(data2) % 4 == 0
            write2_rec = rpc_call(xid + 0x300, 7, write_args(fh, file_len, data2, 0))
            file_data = data + data2
        sha = hashlib.sha256(file_data).hexdigest()

        segs = segments(shape, write_rec, pad, data_off, file_len,
                        commit_rec, lookup_rec, write2_rec)
        # Every split shape's first delivery is an incomplete WRITE record
        # large enough for the partial-record fast path.
        if shape != "control":
            assert 44 <= len(segs[0]) < len(write_rec), (label, len(segs[0]))
        assert b"".join(segs) == (write_rec + (write2_rec or b"")
                                  + (commit_rec or b"") + lookup_rec), label
        f = Flow(sport, t0=1.0 + idx)
        f.handshake()
        for s in segs:
            f.c2s(s)
        f.close()
        all_pkts.extend(f.pkts)
        rows.append((label, sport, file_len, pad, len(write_rec),
                     len(file_data), [len(s) for s in segs], sha))

    wrpcap(os.path.join(os.path.dirname(os.path.abspath(__file__)), "input.pcap"),
           all_pkts)
    w = max(len(r[0]) for r in rows)
    print("%-*s  sport  flen pad wrec  size  segments            sha256" % (w, "flow"))
    for label, sport, flen, pad, wl, size, slens, sha in rows:
        print("%-*s  %5d  %4d  %d  %4d  %4d  %-18s  %s"
              % (w, label, sport, flen, pad, wl, size, ",".join(map(str, slens)), sha))


if __name__ == "__main__":
    main()
