#!/usr/bin/env python3
"""
Redmine #8863 -- CopyIn accounting must survive a malformed CopyInResponse.

Two flows, identical except for the CopyInResponse column count:

  47820  malformed 'G'  length=7, columns=65535  -> length != 7 + 2*columns
  47821  well-formed 'G' length=7, columns=0     -> control

Both are followed by the same CopyData/CopyDone/CommandComplete exchange, so
the accounting (msg_count, data_size) must come out identical; only 47820
should raise malformed pgsql.response.copy_in_response

Baseline handshake/messages modelled on tests/pgsql/pgsql-bug-8863.
"""
import struct
from scapy.all import IP, TCP, wrpcap

SERVER = "10.16.1.10"
CLIENT = "10.16.1.11"
PORT = 5432


def be32(n):
    return struct.pack(">I", n)


def be16(n):
    return struct.pack(">H", n)


def cstr(s):
    return s.encode() + b"\x00"


def msg(ident, body):
    """A regular pgsql message: identifier, length (covers itself + body), body."""
    return ident + be32(4 + len(body)) + body


# ---------------------------------------------------------------- pgsql pieces

STARTUP = be32(23) + be32(0x00030000) + cstr("user") + cstr("postgres") + b"\x00"
assert len(STARTUP) == 23

AUTH_OK = msg(b"R", be32(0))
READY = msg(b"Z", b"I")
COPY_DONE = msg(b"c", b"")
QUERY = msg(b"Q", cstr("COPY t FROM STDIN"))

# Two CopyData messages with deliberately different body sizes, so a mistake in
# summing them is visible rather than masked by symmetry.
ROW_1 = b"1\talpha\n"        # 8 bytes
ROW_2 = b"2\tbeta\n"         # 7 bytes
COPY_DATA_1 = msg(b"d", ROW_1)
COPY_DATA_2 = msg(b"d", ROW_2)
# data_size is (length - 4) per CopyData, i.e. the body byte count
EXPECTED_MSG_COUNT = 2
EXPECTED_DATA_SIZE = len(ROW_1) + len(ROW_2)
assert EXPECTED_DATA_SIZE == 15

COMMAND_COMPLETE = msg(b"C", cstr(f"COPY {EXPECTED_MSG_COUNT}"))


def copy_in_response(columns):
    """
    CopyInResponse with a 3-byte body: overall format + column count.

    length is always 7, which is the minimum a Copy response can declare
    (4 for the length field + 1 format + 2 columns) and is well-formed only
    when columns == 0. Passing a non-zero count makes length disagree with
    7 + 2*columns while leaving the framing itself valid, so the message
    still ends at offset 8 for a length-bounded parser.
    """
    length = 7
    pdu = b"\x47" + be32(length) + b"\x00" + be16(columns)
    assert len(pdu) == 1 + length == 8
    return pdu


MALFORMED_G = copy_in_response(0xFFFF)
WELLFORMED_G = copy_in_response(0)
# The two differ in exactly the two column bytes -- nothing else varies.
assert len(MALFORMED_G) == len(WELLFORMED_G)
assert sum(a != b for a, b in zip(MALFORMED_G, WELLFORMED_G)) == 2
assert MALFORMED_G[:6] == WELLFORMED_G[:6]


# ------------------------------------------------------------------ TCP plumbing


class Flow:
    """A single TCP flow with correct seq/ack bookkeeping."""

    def __init__(self, sport):
        self.sport = sport
        self.cseq = 1
        self.sseq = 1
        self.pkts = []

    def _c(self, flags, payload=b""):
        p = IP(src=CLIENT, dst=SERVER) / TCP(
            sport=self.sport, dport=PORT, flags=flags,
            seq=self.cseq, ack=self.sseq, window=64240,
        )
        if payload:
            p = p / payload
        self.pkts.append(p)
        self.cseq += len(payload) + (1 if "S" in flags or "F" in flags else 0)

    def _s(self, flags, payload=b""):
        p = IP(src=SERVER, dst=CLIENT) / TCP(
            sport=PORT, dport=self.sport, flags=flags,
            seq=self.sseq, ack=self.cseq, window=64240,
        )
        if payload:
            p = p / payload
        self.pkts.append(p)
        self.sseq += len(payload) + (1 if "S" in flags or "F" in flags else 0)

    def handshake(self):
        self._c("S")
        self._s("SA")
        self._c("A")

    def to_server(self, payload):
        self._c("PA", payload)
        self._s("A")

    def to_client(self, payload):
        self._s("PA", payload)
        self._c("A")

    def teardown(self):
        self._c("FA")
        self._s("A")
        self._s("FA")
        self._c("A")

    def startup(self):
        self.handshake()
        self.to_server(STARTUP)
        self.to_client(AUTH_OK + READY)


def copy_in_exchange(sport, copy_in_resp):
    """query -> CopyInResponse -> two CopyData -> CopyDone -> CommandComplete."""
    f = Flow(sport)
    f.startup()
    f.to_server(QUERY)
    f.to_client(copy_in_resp)
    # Separate segments, so the parser crosses FirstCopyDataInReceived ->
    # ConsolidatingCopyDataIn across calls rather than within one buffer.
    f.to_server(COPY_DATA_1)
    f.to_server(COPY_DATA_2)
    f.to_server(COPY_DONE)
    f.to_client(COMMAND_COMPLETE + READY)
    f.teardown()
    return f


f_malformed = copy_in_exchange(47820, MALFORMED_G)
f_control = copy_in_exchange(47821, WELLFORMED_G)

pkts = f_malformed.pkts + f_control.pkts
wrpcap("input.pcap", pkts)

print(f"wrote input.pcap: {len(pkts)} packets, 2 flows")
print(f"  47820 malformed 'G': {MALFORMED_G.hex()}  (length=7, columns=65535)")
print(f"  47821 control   'G': {WELLFORMED_G.hex()}  (length=7, columns=0)")
print(f"  both: {EXPECTED_MSG_COUNT} CopyData, data_size {EXPECTED_DATA_SIZE}, "
      f"CommandComplete 'COPY {EXPECTED_MSG_COUNT}'")
