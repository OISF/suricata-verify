#!/usr/bin/env python3
#
# Generate input.pcap for Redmine #9196: NFSv3 FILE_SYNC WRITE records that
# arrive split across TCP segments. Each flow ends with a REMOVE that must
# alert. Addresses, sequence numbers and timestamps are fixed, so the output
# is deterministic. Writes input.pcap next to this script.
#
#   40001: UNSTABLE WRITE 512 bytes at offset 0, then FILE_SYNC WRITE 1024
#          bytes at offset 512 split into 2 segments (existing open file)
#   40002: as 40001, FILE_SYNC WRITE in one segment (control)
#   40003: FILE_SYNC WRITE 1024 bytes as the only chunk, split into 3
#          segments (new file, two continuation segments)
#   40004: as 40003, FILE_SYNC WRITE in one segment (control)
#   40005: as 40003, split into 2 segments, the REMOVE shares the segment
#          with the end of the continuation
#   40006: UNSTABLE WRITE 512 bytes at offset 0, then FILE_SYNC WRITE 1024
#          bytes at offset 1024 split into 2 segments (the hole before it
#          truncates the file), then FILE_SYNC WRITE 128 bytes at offset 0
#          starting with MARKER (a new file)
#   40007: as 40006, FILE_SYNC WRITE after the hole in one segment (control)
#
# All file data lengths are multiples of 4, so there is no XDR padding.

import hashlib
import os
import struct

from scapy.all import Ether, IP, TCP, Raw, wrpcap

NFSPROC3_WRITE = 7
NFSPROC3_REMOVE = 12
UNSTABLE = 0
FILE_SYNC = 2

CLIENT, SERVER = "10.0.0.1", "10.0.0.2"
CLIENT_MAC, SERVER_MAC = "02:00:00:00:00:01", "02:00:00:00:00:02"
NFS_PORT = 2049
T0 = 1767225600.0


def u32(value):
    return struct.pack("!I", value)


def u64(value):
    return struct.pack("!Q", value)


def opaque(data):
    return u32(len(data)) + data + b"\0" * (-len(data) % 4)


def rpc_call(xid, procedure, args):
    body = (
        u32(xid)
        + u32(0)  # CALL
        + u32(2)  # RPC version
        + u32(100003)  # NFS
        + u32(3)  # NFSv3
        + u32(procedure)
        + u32(0) + u32(0)  # AUTH_NONE credentials
        + u32(0) + u32(0)  # AUTH_NONE verifier
        + args
    )
    return u32(0x80000000 | len(body)) + body


def write_call(xid, fh, offset, data, stable):
    assert len(data) % 4 == 0
    args = opaque(fh) + u64(offset) + u32(len(data)) + u32(stable) + opaque(data)
    return rpc_call(xid, NFSPROC3_WRITE, args)


def remove_call(xid, dir_fh, name):
    return rpc_call(xid, NFSPROC3_REMOVE, opaque(dir_fh) + opaque(name))


def pattern(tag, size):
    # Text data: if a continuation is parsed as an RPC header, its message
    # type is not CALL or REPLY.
    data = b"".join(b"%s %04d\n" % (tag, i) for i in range(size))
    return data[:size]


def handle(name):
    return hashlib.sha256(name).digest()


class Flow:
    def __init__(self, cport, t):
        self.cport = cport
        self.cseq = 1000
        self.sseq = 5000
        self.t = t
        self.pkts = []

    def _pkt(self, to_server, flags, payload=b""):
        if to_server:
            ack = 0 if flags == "S" else self.sseq
            p = (Ether(src=CLIENT_MAC, dst=SERVER_MAC)
                 / IP(src=CLIENT, dst=SERVER)
                 / TCP(sport=self.cport, dport=NFS_PORT, flags=flags,
                       seq=self.cseq, ack=ack))
        else:
            p = (Ether(src=SERVER_MAC, dst=CLIENT_MAC)
                 / IP(src=SERVER, dst=CLIENT)
                 / TCP(sport=NFS_PORT, dport=self.cport, flags=flags,
                       seq=self.sseq, ack=self.cseq))
        if payload:
            p = p / Raw(payload)
        p.time = self.t
        self.t += 0.001
        self.pkts.append(p)

    def handshake(self):
        self._pkt(True, "S")
        self.cseq += 1
        self._pkt(False, "SA")
        self.sseq += 1
        self._pkt(True, "A")

    def send(self, payload):
        # The server ACK hands each client segment to the parser on its own.
        self._pkt(True, "PA", payload)
        self.cseq += len(payload)
        self._pkt(False, "A")

    def close(self):
        self._pkt(True, "FA")
        self.cseq += 1
        self._pkt(False, "FA")
        self.sseq += 1
        self._pkt(True, "A")


FIRST = pattern(b"9196 first chunk", 512)
SECOND = pattern(b"9196 second chunk", 1024)
ONLY = pattern(b"9196 only chunk", 1024)
HOLE = pattern(b"9196 after hole", 1024)
MARKER = b"9196-TRUNCATED-FILE-MARKER\n"
MARKED = MARKER + pattern(b"9196 marked file", 128 - len(MARKER))
DIR_FH = handle(b"9196 directory")

# Bytes of a WRITE record before its file data: record marker, RPC call
# header, 32-byte handle, offset, count, stable and data length.
DATA_AT = len(write_call(0, DIR_FH, 0, b"", FILE_SYNC))


def append_flow(cport, t, split):
    fh = handle(b"9196 file %d" % cport)
    xid = 0x91960000 + (cport % 100) * 0x100
    f = Flow(cport, t)
    f.handshake()
    f.send(write_call(xid + 1, fh, 0, FIRST, UNSTABLE))
    write = write_call(xid + 2, fh, len(FIRST), SECOND, FILE_SYNC)
    if split:
        f.send(write[:DATA_AT + 200])
        f.send(write[DATA_AT + 200:])
    else:
        f.send(write)
    f.send(remove_call(xid + 3, DIR_FH, b"9196-remove-%d" % cport))
    f.close()
    return f.pkts


def only_chunk_flow(cport, t, cuts, remove_with_tail=False):
    fh = handle(b"9196 file %d" % cport)
    xid = 0x91960000 + (cport % 100) * 0x100
    f = Flow(cport, t)
    f.handshake()
    write = write_call(xid + 1, fh, 0, ONLY, FILE_SYNC)
    remove = remove_call(xid + 2, DIR_FH, b"9196-remove-%d" % cport)
    bounds = [0] + [DATA_AT + c for c in cuts] + [len(write)]
    segments = [write[a:b] for a, b in zip(bounds, bounds[1:])]
    if remove_with_tail:
        segments[-1] += remove
    for segment in segments:
        f.send(segment)
    if not remove_with_tail:
        f.send(remove)
    f.close()
    return f.pkts


def truncated_flow(cport, t, split):
    fh = handle(b"9196 file %d" % cport)
    xid = 0x91960000 + (cport % 100) * 0x100
    f = Flow(cport, t)
    f.handshake()
    f.send(write_call(xid + 1, fh, 0, FIRST, UNSTABLE))
    # The last chunk does not follow the tracked data, so the file tracker
    # truncates the file.
    write = write_call(xid + 2, fh, 2 * len(FIRST), HOLE, FILE_SYNC)
    if split:
        f.send(write[:DATA_AT + 200])
        f.send(write[DATA_AT + 200:])
    else:
        f.send(write)
    # Rewrites the file from offset 0: a new file once the truncated one is
    # closed.
    f.send(write_call(xid + 3, fh, 0, MARKED, FILE_SYNC))
    f.send(remove_call(xid + 4, DIR_FH, b"9196-remove-%d" % cport))
    f.close()
    return f.pkts


packets = []
packets += append_flow(40001, T0 + 1, split=True)
packets += append_flow(40002, T0 + 2, split=False)
packets += only_chunk_flow(40003, T0 + 3, cuts=[200, 600])
packets += only_chunk_flow(40004, T0 + 4, cuts=[])
packets += only_chunk_flow(40005, T0 + 5, cuts=[200], remove_with_tail=True)
packets += truncated_flow(40006, T0 + 6, split=True)
packets += truncated_flow(40007, T0 + 7, split=False)

wrpcap(os.path.join(os.path.dirname(os.path.abspath(__file__)), "input.pcap"),
       packets)

print("40001/40002: size %d sha256 %s" % (
    len(FIRST + SECOND), hashlib.sha256(FIRST + SECOND).hexdigest()))
print("40003/40004/40005: size %d sha256 %s" % (
    len(ONLY), hashlib.sha256(ONLY).hexdigest()))
print("40006/40007: truncated size %d, marker file size %d sha256 %s" % (
    len(FIRST), len(MARKED), hashlib.sha256(MARKED).hexdigest()))
