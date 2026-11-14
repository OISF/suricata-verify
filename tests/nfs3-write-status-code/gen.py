"""Fixture for nfs3-write-status-code.

A v3 WRITE with stable_how FILE_SYNC completes from the request, so its
transaction is closed before the reply arrives. Its record must then carry
neither a status nor a numeric status code: status_code 0 reads as NFS3_OK, and
a server that rejected the write (the reply here says NFS3ERR_IO) must not look
successful. The fileinfo written at file close follows mainline and
names the status OK, so it must leave status_code out.

The UNSTABLE leg is the other half: its request settles nothing, so the reply
is parsed while the transaction is still open and the status has to reach the
record. The reply path finds a write's file transaction by the xid of its last
chunk, which used to be recorded only for a FILE_SYNC write - so an UNSTABLE
write the server rejected was logged as though it had never been answered.

  xid 1  WRITE FILE_SYNC   fhA 64 bytes  reply status 5 (NFS3ERR_IO)
  xid 2  WRITE UNSTABLE    fhB 64 bytes  reply status 5 (NFS3ERR_IO)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nfs_sv_common import Pcap, be32, be64, v3_call, v3_fh, v3_reply

PROC_WRITE = 7
NFS3ERR_IO = 5
SRC, SRV = "192.168.1.10", "192.168.1.20"
DATA = b"A" * 64
FHA = v3_fh(0x41)
FHB = v3_fh(0x42)


def write_call(xid, fh, stable, data):
    return v3_call(
        xid, PROC_WRITE,
        fh + be64(0) + be32(len(data)) + be32(stable) + be32(len(data)) + data,
    )


p = Pcap(os.path.join(os.path.dirname(os.path.abspath(__file__)), "input.pcap"))
cli, srv = (SRC, 941), (SRV, 2049)
p.tcp(cli, srv, syn=True)
p.tcp(srv, cli, synack=True)
p.tcp(cli, srv, payload=write_call(1, FHA, 2, DATA))
p.tcp(srv, cli, payload=v3_reply(1, be32(NFS3ERR_IO)))
p.tcp(cli, srv, payload=write_call(2, FHB, 0, DATA))
p.tcp(srv, cli, payload=v3_reply(2, be32(NFS3ERR_IO)))


p.close()
