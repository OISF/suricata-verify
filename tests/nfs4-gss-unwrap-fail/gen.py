#!/usr/bin/env python3
"""Generate input.pcap for tests/nfs4-gss-unwrap-fail.

RPCSEC_GSS integrity (creds procedure 0, service 2) wraps the compound in an
envelope (RFC 2203 5.3.2.2): length of the wrapped body (sequence number and
arguments), sequence number, arguments, checksum. When that envelope cannot be
unwrapped the record never reaches the compound parser, so no transaction is
created for it - and an event that does not land on a transaction does not
exist: the reject was a state event only, which marks the newest transaction
and is dropped when there is none.

Four flows, each a different face of that:

  939 the very first RPC of the flow is an integrity CALL whose envelope
      length fails the credentials bound (>= 4096): before the fix the flow
      logged nothing for it. A good compound follows, so a correct reject also
      has to leave the stream at the record boundary.
  940 as 939 but the length is inside the bound and past the end of the
      record: the unwrap is incomplete, which took the other arm.
  941 two integrity calls (A then B), both opening a transaction, then A's
      reply with a broken envelope while B is still open, then B's reply. B is
      the newest transaction at the failure, so the event was stamped on it and
      A stayed open; the event belongs on A (tx_id 0), and the flow must have
      exactly one.
  944 an integrity call of a compound that opens no transaction at all
      (PUTFH+GETATTR: no main-opcode result), then its reply with a broken
      envelope. The reject needs a transaction of its own, and that one has to
      carry the procedure the request map recorded - EVE reads the 0 it was
      left with as NULL.

Regenerate: python3 gen.py (deterministic, no dependencies).
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nfs_sv_common import Pcap, be32, be64, null_verf, unix_cred, gss_cred  # noqa: E402

CLIENT_IP, SERVER_IP = "10.0.0.1", "10.0.0.2"
PORT = 2049
FH = b"\x01" * 16
NAME = b"gssfail"

putfh = be32(22) + be32(len(FH)) + FH
getattr_ = be32(9) + be32(2) + be32(0x10) + be32(0)
remove = be32(28) + be32(4) + b"newf"
resp_ops = [
    be32(22) + be32(0),                                       # PUTFH: OK
    be32(28) + be32(0) + be32(2) + be32(0) + be32(0) + be64(0),  # REMOVE: OK, change info
]


def rec(body):
    return struct.pack(">I", (1 << 31) | len(body)) + body


def call(xid, cred, prog):
    return rec(be32(xid) + be32(0) + be32(2) + be32(100003) + be32(4) + be32(1)
               + cred + null_verf() + prog)


def reply(xid, prog):
    return rec(be32(xid) + be32(1) + be32(0) + null_verf() + be32(0) + prog)


def compound(ops):
    """COMPOUND4args: tag, minor version, op count, ops."""
    return be32(0) + be32(0) + be32(len(ops)) + b"".join(ops)


# A REMOVE answer marks its transaction done; a GETATTR one opens none, which
# is what flow 944 needs.
CALL_C = compound([putfh, remove])
GETATTR_C = compound([putfh, getattr_])


def res_compound(ops, status=0):
    """COMPOUND4res: compound status, tag, op count, results."""
    return be32(status) + be32(0) + be32(len(ops)) + b"".join(ops)


RESP_C = res_compound(resp_ops)
RESP_ATTR = res_compound([be32(22) + be32(0), be32(9) + be32(0) + be32(2)
                          + be32(0x10) + be32(0) + be32(8) + be64(4096)])


def envelope(claimed, data):
    """Integrity envelope: wrapped body length, sequence number, then args."""
    return be32(claimed) + be32(1) + data


def flow(cport):
    c, s = (CLIENT_IP, cport), (SERVER_IP, PORT)
    p.tcp(c, s, syn=True)
    p.tcp(s, c, synack=True)
    p.tcp(c, s, pure_ack=True)
    return c, s


p = Pcap(os.path.join(os.path.dirname(os.path.abspath(__file__)), "input.pcap"))

# 939: envelope over the credentials bound, as the first RPC of the flow
c, s = flow(939)
p.tcp(c, s, payload=call(0x9391, gss_cred(0, 2), envelope(4096, CALL_C)))
p.tcp(s, c, pure_ack=True)
p.tcp(c, s, payload=call(0x9392, unix_cred(), CALL_C))
p.tcp(s, c, payload=reply(0x9392, RESP_C))
p.tcp(c, s, pure_ack=True)

# 940: envelope length inside the bound but past the end of the record
c, s = flow(940)
p.tcp(c, s, payload=call(0x9401, gss_cred(0, 2), envelope(3000, CALL_C)))
p.tcp(s, c, pure_ack=True)
p.tcp(c, s, payload=call(0x9402, unix_cred(), CALL_C))
p.tcp(s, c, payload=reply(0x9402, RESP_C))
p.tcp(c, s, pure_ack=True)

# 941: broken reply envelope on an async mount; the event belongs on call A
c, s = flow(941)
p.tcp(c, s, payload=call(0xA001, gss_cred(0, 2), envelope(len(CALL_C), CALL_C)))
p.tcp(c, s, payload=call(0xA002, gss_cred(0, 2), envelope(len(CALL_C), CALL_C)))
p.tcp(s, c, pure_ack=True)
p.tcp(s, c, payload=reply(0xA001, envelope(5000, RESP_C)))
p.tcp(c, s, pure_ack=True)
p.tcp(s, c, payload=reply(0xA002, envelope(len(RESP_C), RESP_C)))
p.tcp(c, s, pure_ack=True)

# 944: a compound that opens no transaction at all (PUTFH+GETATTR: no
# main-opcode result), so its failing reply takes the fallback branch. The
# reject tx must carry the procedure the xidmap recorded, not the 0 that
# EVE reads as NULL.
c, s = flow(944)
p.tcp(c, s, payload=call(0xB101, gss_cred(0, 2), envelope(len(GETATTR_C), GETATTR_C)))
p.tcp(s, c, pure_ack=True)
p.tcp(s, c, payload=reply(0xB101, envelope(5000, RESP_ATTR)))
p.tcp(c, s, pure_ack=True)

p.close()
print("wrote input.pcap")
