#!/usr/bin/env python3
"""Generate input.pcap for tests/nfs3-write-commit-order.

An UNSTABLE WRITE split into two chunks is closed by a COMMIT. Whether the
record carries the writes' status depends on the order Suricata sees them in:

- flow A (port 951): both write calls, then the COMMIT, then the replies - the
  first reply is NFS3ERR_IO. The COMMIT closes the transaction, so the reply
  that follows it lands too late and the record is logged with no status.
- flow B (port 952): the same calls with each reply before the next call, so the
  error is in hand when the COMMIT arrives and the record reports ERR_IO.

Regenerate: python3 gen.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nfs_sv_common import Pcap, be32, be64, v3_call, v3_fh, v3_reply  # noqa: E402

PROC_WRITE = 7
PROC_COMMIT = 21
UNSTABLE = 0
NFS3_OK = 0
NFS3ERR_IO = 5
CHUNK = b"A" * 64
VERF = b"\x11" * 8

CLIENT = "192.168.0.10"
SERVER = "192.168.0.20"


def write_call(xid, fh, off, data):
    return v3_call(
        xid,
        PROC_WRITE,
        fh
        + be64(off)
        + be32(len(data))
        + be32(UNSTABLE)
        + be32(len(data))
        + data,
    )


def wcc():
    # wcc_data with no attributes before or after the call
    return be32(0) + be32(0)


def write_reply(xid, status):
    # WRITE3resok: status, wcc_data, count, committed, writeverf. The failure
    # form is status and wcc_data only; leaving wcc_data out of either reads
    # as malformed to tshark even though the status still decodes.
    if status == NFS3_OK:
        body = be32(status) + wcc() + be32(len(CHUNK)) + be32(UNSTABLE) + VERF
    else:
        body = be32(status) + wcc()
    return v3_reply(xid, body)


def commit_call(xid, fh):
    # COMMIT3args: file, offset64, count
    return v3_call(xid, PROC_COMMIT, fh + be64(0) + be32(0))


def commit_reply(xid):
    # COMMIT3resok: status, wcc_data, write verifier. tshark wants all three;
    # status and the verifier alone decode as a malformed reply.
    return v3_reply(xid, be32(NFS3_OK) + wcc() + VERF)


p = Pcap(os.path.join(os.path.dirname(os.path.abspath(__file__)), "input.pcap"))

fha = v3_fh(0xA1)
a = (CLIENT, 951), (SERVER, 2049)
p.tcp(*a, syn=True)
p.tcp(a[1], a[0], synack=True)
p.tcp(a[0], a[1], payload=write_call(0x5C000001, fha, 0, CHUNK))
p.tcp(a[0], a[1], payload=write_call(0x5C000002, fha, 64, CHUNK))
p.tcp(a[0], a[1], payload=commit_call(0x5C000003, fha))
p.tcp(a[1], a[0], payload=write_reply(0x5C000001, NFS3ERR_IO))
p.tcp(a[1], a[0], payload=write_reply(0x5C000002, NFS3_OK))
p.tcp(a[1], a[0], payload=commit_reply(0x5C000003))

fhb = v3_fh(0xB2)
b = (CLIENT, 952), (SERVER, 2049)
p.tcp(*b, syn=True)
p.tcp(b[1], b[0], synack=True)
p.tcp(b[0], b[1], payload=write_call(0x5C000101, fhb, 0, CHUNK))
p.tcp(b[1], b[0], payload=write_reply(0x5C000101, NFS3ERR_IO))
p.tcp(b[0], b[1], payload=write_call(0x5C000102, fhb, 64, CHUNK))
p.tcp(b[1], b[0], payload=write_reply(0x5C000102, NFS3_OK))
p.tcp(b[0], b[1], payload=commit_call(0x5C000103, fhb))
p.tcp(b[1], b[0], payload=commit_reply(0x5C000103))

p.close()
