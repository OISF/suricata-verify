"""Generate input.pcap: NFSv2 LOOKUP reply resolving a handle to a name.

RFC 1094 keeps the object's name in the request and returns its handle in the
diropres, so the handle->name mapping can only be built from that reply.
Without it, a later handle-only operation on the object logs no file name.

Flow: LOOKUP "cfile" -> reply with the object handle, then a READLINK on that
handle in a separate datagram.
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nfs_sv_common import Pcap, be32

CLIENT = ("192.168.1.6", 941)
CLIENT2 = ("192.168.1.6", 942)
CLIENT3 = ("192.168.1.6", 943)
SERVER = ("192.168.1.2", 2049)
DIR_FH = b"\x11" * 32
OBJ_FH = b"\x42" * 32
NAME = b"cfile"
DATA = b"\x43" * 64


def call_raw(xid, proc, prog_data):
    # unmarked v2 call: AUTH_NULL (type 0, zero length)
    return (
        be32(xid) + be32(0) + be32(2) + be32(100003) + be32(2) + be32(proc)
        + be32(0) + be32(0) + be32(0) + be32(0) + prog_data
    )


def reply_raw(xid, prog_data):
    return be32(xid) + be32(1) + be32(0) + be32(0) + be32(0) + be32(0) + prog_data


def xdr_string(s):
    pad = (4 - (len(s) % 4)) % 4
    return be32(len(s)) + s + b"\x00" * pad


fattr2 = (
    be32(1) + be32(0x81A4) + be32(1) + be32(1000) + be32(1000)
    + be32(0) + be32(0) + be32(0) + be32(0) + be32(0)
    + be32(0) + be32(0) + be32(0) + be32(0) + be32(0) + be32(0)
)
fattr2 = fattr2 + b"\x00" * (68 - len(fattr2))

# LOOKUP args: dir handle + name
lookup_args = DIR_FH + xdr_string(NAME)
# LOOKUP reply (diropres): status OK, object handle, attributes. RFC 1094
# keeps the name in the request, so the reply supplies the handle only.
lookup_reply = be32(0) + OBJ_FH + fattr2

# READLINK on the object: the request carries only the handle, so the record's
# name can only come from the LOOKUP reply's handle to name mapping

# readlinkres (RFC 1094): status and the link data, no attributes
readlink_args = OBJ_FH
readlink_reply = be32(0) + xdr_string(b"target")

# SETATTR args (sattrargs): handle + sattr2 (8 words; zeros are legal)
SATTR = b"\x00" * 32
setattr_args = OBJ_FH + SATTR


def garbage_reply(xid):
    # MSG_ACCEPTED, accept_stat GARBAGE_ARGS: no program body
    return be32(xid) + be32(1) + be32(0) + be32(0) + be32(0) + be32(4)


def main():
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "input.pcap")
    p = Pcap(out)
    p.udp(CLIENT, SERVER, payload=call_raw(1, 4, lookup_args))
    p.udp(SERVER, CLIENT, payload=reply_raw(1, lookup_reply))
    p.udp(CLIENT, SERVER, payload=call_raw(2, 5, readlink_args))
    p.udp(SERVER, CLIENT, payload=reply_raw(2, readlink_reply))
    # a SETATTR on the same handle: the name in its record comes only from the map
    p.udp(CLIENT, SERVER, payload=call_raw(6, 2, setattr_args))
    p.udp(SERVER, CLIENT, payload=reply_raw(6, be32(0) + fattr2))

    # flow B: a message-level rejected reply carries no diropres; a status is
    # all that is missing, so it must not be flagged as malformed
    p.udp(CLIENT2, SERVER, payload=call_raw(3, 4, DIR_FH + xdr_string(b"dfile")))
    p.udp(SERVER, CLIENT2, payload=garbage_reply(3))

    # flow C: a name over the RFC 1094 bound is flagged on the request that
    # carried it, and not again on the handle-only op that resolves it
    long_name = b"L" * 300
    p.udp(CLIENT3, SERVER, payload=call_raw(4, 4, DIR_FH + xdr_string(long_name)))
    p.udp(SERVER, CLIENT3, payload=reply_raw(4, be32(0) + OBJ_FH + fattr2))
    p.udp(CLIENT3, SERVER, payload=call_raw(5, 2, setattr_args))
    p.udp(SERVER, CLIENT3, payload=reply_raw(5, be32(0) + fattr2))
    p.close()


if __name__ == "__main__":
    main()
