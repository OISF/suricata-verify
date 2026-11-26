"""Generate input.pcap: NFSv3 flows carrying an RPC MSG_DENIED reply.

RFC 5531 9: a denied reply is 20 bytes (xid, msgtype, reply_stat,
reject_stat, auth_stat) and carries no verifier, no accept_stat, no program
body and no program number. It must not be read as a malformed reply, and it
must not hide or drop the status of the other replies to the same request.

The client ACKs every server segment so the to-client data reaches the parser
one segment at a time, as on a live link.
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nfs_sv_common import Pcap, be32, be64, rpc_record, v3_call, v3_fh, v3_reply

PROC_WRITE, PROC_READ = 7, 6
UNSTABLE = 0
SRC, SRV = "192.168.1.10", "192.168.1.20"
DATA = b"A" * 64
FH3 = v3_fh(0x42)


def w3(xid, off):
    return v3_call(xid, PROC_WRITE,
                   FH3 + be64(off) + be32(len(DATA)) + be32(UNSTABLE) + be32(len(DATA)) + DATA)


def w3_ok(xid):
    body = be32(0) + be32(0) + be32(0) + be32(len(DATA)) + be32(UNSTABLE) + be64(0)
    return v3_reply(xid, body)


def read_call(xid):
    return v3_call(xid, PROC_READ, FH3 + be64(0) + be32(512))


def denied_body(xid):
    return be32(xid) + be32(1) + be32(1) + be32(1) + be32(1)


def denied(xid):
    return rpc_record(denied_body(xid))


def flow(p, cli_port, steps):
    cli, srv = (SRC, cli_port), (SRV, 2049)
    p.tcp(cli, srv, syn=True)
    p.tcp(srv, cli, synack=True)
    for d, payload in steps:
        if d == "c":
            p.tcp(cli, srv, payload=payload)
        else:
            p.tcp(srv, cli, payload=payload)
            p.tcp(cli, srv, pure_ack=True)


def main():
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "input.pcap")
    p = Pcap(out)

    # flow A: the denial answers the first chunk, the second chunk's status holds
    flow(p, 941, [("c", w3(1, 0)), ("c", w3(2, 64)),
                  ("s", denied(1)), ("s", w3_ok(2))])
    # flow B: the reverse order, the held OK must survive the denial
    flow(p, 942, [("c", w3(3, 0)), ("c", w3(4, 64)),
                  ("s", w3_ok(3)), ("s", denied(4))])
    # flow C: a READ answered by a denial only
    flow(p, 943, [("c", read_call(5)), ("s", denied(5))])
    # flow D: not RFC traffic: a denied record claiming a READ reply body
    big = DATA * 8
    rbody = denied_body(6) + be32(0) + be32(0) + be32(len(big)) + be32(1) + be32(len(big)) + big
    rec = rpc_record(rbody)
    flow(p, 944, [("c", read_call(6)), ("s", rec[:200]), ("s", rec[200:])])
    p.close()


if __name__ == "__main__":
    main()
