#!/usr/bin/env python3
"""Generate the nfs3-lookup-overclaim-skip fixture.

A v3 LOOKUP request, a LOOKUP reply whose record marker claims
1 MiB + 64 KiB (above the test's max-read-size of 1 MiB + 64), a
stream of filler bytes sized exactly to the claim minus the
delivered prefix, then a follow-up ACCESS on the reply's filehandle.

The segmented-metadata gate must refuse to buffer toward the crafted
claim: the record is skipped to its claimed boundary (the filler is
eaten) and the reply never reaches the namemap. The follow-up ACCESS
then carries no filename. If the gate admitted the record, the filler
would complete the claim, the lenient v3 parser would consume the
garbage and feed the namemap, and the ACCESS would carry the filename.

The filler also pins the skip's boundary arithmetic: an off-by-N skip
would eat into (or desync) the follow-up record.
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nfs_sv_common import Pcap, be32, fh3, null_verf, v3_call, v3_fh, v3_reply

CLIENT = ("192.168.1.6", 939)
SERVER = ("192.168.1.2", 2049)
XID1 = 0x41000001
XID2 = 0x41000002
NAME = b"segfile"
FH = v3_fh(0x20)
CLAIM = 1048576 + 65536  # 1 MiB + 64 KiB > max-read-size (1 MiB) + 64
FILL = 1448              # filler segment size

# LOOKUP request: dir fh + filename
lookup_req = v3_call(XID1, 3, v3_fh(0x10) + be32(len(NAME)) + NAME + b"\x00")

# LOOKUP reply: canonical framing (null verifier) + status + fh. The
# fh must be the real one: if the gate regressed and admitted the
# reply, the parser would feed the namemap with it and the follow-up
# ACCESS would carry the filename (the count-0 check would fail).
reply_body = (
    be32(XID1) + be32(1) + be32(0) + null_verf() + be32(0)
    + be32(0) + FH
)
overclaim_reply = struct.pack(">I", (1 << 31) | (CLAIM - 4)) + reply_body

# filler: exactly the claim minus the delivered prefix, so the skip
# lands on the record boundary; sized to the claim so the buggy
# admit path would complete the record over the filler
filler = b"\x5a" * (CLAIM - len(overclaim_reply))

# ACCESS request on the reply's fh + a status-only reply
access_req = v3_call(XID2, 4, FH + be32(0x01))
access_reply = v3_reply(XID2, be32(0))

p = Pcap(os.path.join(os.path.dirname(os.path.abspath(__file__)), "nfs3-lookup-overclaim-skip.pcap"))
p.tcp(CLIENT, SERVER, syn=True)
p.tcp(SERVER, CLIENT, synack=True)
p.tcp(CLIENT, SERVER, pure_ack=True)
p.tcp(CLIENT, SERVER, payload=lookup_req)
p.tcp(SERVER, CLIENT, payload=overclaim_reply)
p.tcp(CLIENT, SERVER, pure_ack=True)
for off in range(0, len(filler), FILL):
    p.tcp(SERVER, CLIENT, payload=filler[off:off + FILL])
    p.tcp(CLIENT, SERVER, pure_ack=True)
p.tcp(CLIENT, SERVER, payload=access_req)
p.tcp(SERVER, CLIENT, payload=access_reply)
p.tcp(CLIENT, SERVER, pure_ack=True)
p.close()
print("lookup_req", len(lookup_req), "overclaim_reply", len(overclaim_reply),
      "filler", len(filler), "claim", CLAIM)
