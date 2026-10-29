#!/usr/bin/env python3
"""
pgsql RowDescription ('T') / DataRow ('D') messages whose declared field count
disagrees with the body their length field delimits.

Five flows. Each sends a query, then the crafted (or well-formed) message, then
the messages that follow in a separate segment. Those trailing messages are on
the wire and acknowledged, so a flow that does not log them was unable to get
past the crafted message.

  47830  'D', body too short for the declared count   44 00000007 0001 00
  47831  'T', no field-name terminator in the body    54 00000008 0001 4142
  47832  'T', declares 65535 fields in a 4-byte body  54 0000000a ffff 41 00 ..
  47833  'T', body is only a terminator               54 00000007 0001 00
  47834  control, all well-formed

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
AUTH_OK = msg(b"R", be32(0))
READY = msg(b"Z", b"I")
QUERY = msg(b"Q", cstr("SELECT id FROM t"))
COMMAND_COMPLETE = msg(b"C", cstr("SELECT 1"))


def row_field(name, table_oid=16393, column_index=1, data_type_oid=23,
              data_type_size=4, type_modifier=-1, format_code=0):
    return (cstr(name) + be32(table_oid) + be16(column_index) + be32(data_type_oid)
            + struct.pack(">h", data_type_size) + struct.pack(">i", type_modifier)
            + be16(format_code))


def row_description(fields):
    return msg(b"T", be16(len(fields)) + b"".join(fields))


def data_row(values):
    body = be16(len(values))
    for v in values:
        body += be32(len(v)) + v
    return msg(b"D", body)


GOOD_ROW_DESC = row_description([row_field("id")])
GOOD_DATA_ROW = data_row([b"42"])
# the declared count must account for the body exactly
assert len(GOOD_ROW_DESC) == 1 + 4 + 2 + 21
assert len(GOOD_DATA_ROW) == 1 + 4 + 2 + 6

# --------------------------------------------------------------- crafted cases

# 'D': the length leaves 1 byte after the field count, but a value needs >= 4
D_SHORT = b"\x44" + be32(7) + be16(1) + b"\x00"
assert len(D_SHORT) == 8

# 'T': the length leaves 2 bytes, and neither terminates the field name
T_NO_NUL = b"\x54" + be32(8) + be16(1) + b"\x41\x42"
assert len(T_NO_NUL) == 9

# 'T': a plausible-looking field count against a 4-byte body.
T_BIG_COUNT = b"\x54" + be32(10) + be16(0xFFFF) + b"\x41\x00\x42\x43"
assert len(T_BIG_COUNT) == 11

# 'T': the length leaves 1 byte and it is the terminator, so the declared field
# has an empty name
T_LEADING_NUL = b"\x54" + be32(7) + be16(1) + b"\x00"
assert len(T_LEADING_NUL) == 8


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


def query_exchange(sport, crafted, trailing):
    """
    query -> crafted message (own segment) -> the messages that follow.

    The trailing messages go in a separate segment so that a stall is
    unambiguous: they are present on the wire and acknowledged, and only
    Suricata's inability to get past the crafted message can hide them.
    """
    f = Flow(sport)
    f.startup()
    f.to_server(QUERY)
    f.to_client(crafted)
    f.to_client(trailing)
    f.teardown()
    return f


flows = [
    query_exchange(47830, D_SHORT, COMMAND_COMPLETE + READY),
    query_exchange(47831, T_NO_NUL, GOOD_DATA_ROW + COMMAND_COMPLETE + READY),
    query_exchange(47832, T_BIG_COUNT, GOOD_DATA_ROW + COMMAND_COMPLETE + READY),
    query_exchange(47833, T_LEADING_NUL, GOOD_DATA_ROW + COMMAND_COMPLETE + READY),
    query_exchange(47834, GOOD_ROW_DESC, GOOD_DATA_ROW + COMMAND_COMPLETE + READY),
]

pkts = [p for f in flows for p in f.pkts]
wrpcap("input.pcap", pkts)

print(f"wrote input.pcap: {len(pkts)} packets, {len(flows)} flows")
for sport, label, crafted in [
    (47830, "'D' short body      ", D_SHORT),
    (47831, "'T' no NUL in body  ", T_NO_NUL),
    (47832, "'T' count=65535     ", T_BIG_COUNT),
    (47833, "'T' body starts NUL ", T_LEADING_NUL),
    (47834, "control (well-formed)", GOOD_ROW_DESC),
]:
    print(f"  {sport}  {label}  {crafted.hex()}")
