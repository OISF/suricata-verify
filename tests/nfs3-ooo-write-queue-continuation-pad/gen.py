#!/usr/bin/env python3
"""Generate input.pcap for tests/nfs3-ooo-write-queue-continuation-pad.

Three v3 WRITE calls, client to server, no replies:

- WRITE 1 (xid 1, handle A): 4000 x 0x44 at offset 0, in one segment, so
  its record is complete on delivery.
- WRITE 2 (xid 2, handle B): 8190 x 0x45 at offset 12192, so out of order.
  Its record is split across two segments: the args plus 2924 data bytes,
  then the remaining 5266 data bytes and the 2-byte XDR pad that aligns the
  opaque. The 8264 byte claim covers the pad, as RFC 5661 requires.
- WRITE 3 (xid 3, handle C): 100 x 0x45 at offset 0, in the segment that
  carries WRITE 2's continuation.

With max-write-queue-size=4096, queueing WRITE 2's continuation crosses the
limit, so the chunk path rejects it. The skip must cover the rest of the file
data *and* the XDR pad inside the record claim, or the parser chews on the pad
and WRITE 3 desyncs.

Regenerate: python3 gen.py (deterministic: the timestamps are synthetic).
"""
from scapy.all import IP, TCP, Raw, wrpcap

CLIENT = "10.0.2.1"
SERVER = "10.0.0.9"
CLIENT_PORT = 42000
NFS_PORT = 2049
NFS_PROG = 100003
WINDOW = 64240

# the first delivery of WRITE 2's record, in stream bytes
SPLIT = 3000


def be32(v):
    return v.to_bytes(4, "big")


def be64(v):
    return v.to_bytes(8, "big")


def marker(frag_len):
    return (0x80000000 | (frag_len & 0x7FFFFFFF)).to_bytes(4, "big")


def claim(rec):
    return int.from_bytes(rec[:4], "big") & 0x7FFFFFFF


def fh8(value):
    return be32(8) + be64(value)


def v3_write_req(xid, handle, offset, data, pad=b""):
    """One WRITE call record. The XDR pad stays inside the record claim."""
    body = (be32(xid) + be32(0) + be32(2) + be32(NFS_PROG) + be32(3) + be32(7) +
            be32(0) + be32(0) + be32(0) + be32(0) +
            fh8(handle) + be64(offset) + be32(len(data)) + be32(0) +
            be32(len(data)) + data)
    assert len(body) == 72 + len(data)
    return marker(len(body) + len(pad)) + body + pad


class Flow:
    """Client data segments, each ACKed by the server so that Suricata hands
    every one of them to the parser on its own."""

    def __init__(self):
        self.cseq = 1000
        self.sseq = 9000
        self.pkts = []

    def client(self, payload=b"", flags="A", ack=None):
        if ack is None:
            ack = self.sseq
        p = (IP(src=CLIENT, dst=SERVER, id=4096, flags="DF", chksum=0) /
             TCP(sport=CLIENT_PORT, dport=NFS_PORT, seq=self.cseq,
                 ack=ack, flags=flags, window=WINDOW, chksum=0))
        self.pkts.append(p / Raw(load=payload) if payload else p)
        self.cseq += len(payload) + (1 if "S" in flags else 0)

    def server(self, flags="A"):
        self.pkts.append(
            IP(src=SERVER, dst=CLIENT, id=4096, flags="DF", chksum=0) /
            TCP(sport=NFS_PORT, dport=CLIENT_PORT, seq=self.sseq,
                ack=self.cseq, flags=flags, window=WINDOW, chksum=0))
        self.sseq += 1 if "S" in flags else 0

    def handshake(self):
        self.client(flags="S", ack=0)
        self.server(flags="SA")
        self.client()

    def segment(self, payload):
        self.client(payload)
        self.server()


flow = Flow()
flow.handshake()

write1 = v3_write_req(1, 0x68C93758, 0, b"\x44" * 4000)
assert claim(write1) == 4072 and len(write1) == 4076
flow.segment(write1)

write2 = v3_write_req(2, 0x69D04159, 12192, b"\x45" * 8190, b"\x00" * 2)
assert claim(write2) == 8264 and claim(write2) % 4 == 0
assert len(write2) == 8268
flow.segment(write2[:SPLIT])
# the continuation ends the record, and WRITE 3 follows it in the same segment
write3 = v3_write_req(3, 0x70000001, 0, b"\x45" * 100)
assert claim(write3) == 172 and len(write3) == 176
flow.segment(write2[SPLIT:] + write3)

# synthetic timestamps, so regenerating does not rewrite the whole file
for i, p in enumerate(flow.pkts, 1):
    p.time = 0.0002 * i
wrpcap("input.pcap", flow.pkts)
print(len(flow.pkts), "pkts, WRITE 2 claim", claim(write2))
