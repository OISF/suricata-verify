#!/usr/bin/env python3
"""
Redmine #8822 -- a simple query that arrives right after a gap in the
to-server stream.

One flow: startup, then two simple queries. Between them the client sends a
5-byte Terminate-shaped segment that is *not* in the capture, while the
server's next ACK covers it. The sensor is left with a fully acknowledged
5-byte hole ahead of the first query.

    C -> S  StartupMessage      user=postgres database=test
    S -> C  AuthenticationOk, ParameterStatus, ParameterStatus, ParameterStatus, BackendKeyData, ReadyForQuery
    C -> S  58 00 00 00 04      omitted from the capture -- the gap
    C -> S  Query               SELECT version();
    S -> C  ACK covering the omitted bytes and the query
    S -> C  RowDescription, DataRow, CommandComplete, ReadyForQuery
    C -> S  Query               SELECT * FROM secrets;
    S -> C  RowDescription, CommandComplete, ReadyForQuery   (no rows)
    teardown

Two pcaps are written, differing only in two length fields:

    input.pcap            lengths computed from the bodies
    described-lengths.pcap  lengths as written in the ticket -- the
                            StartupMessage claims 38 bytes for 37, and the
                            second Query claims 29 for 27

Sequence numbers are one lower than the ticket's throughout, since the
StartupMessage payload is 37 bytes on the wire in both pcaps.
"""
import struct
from scapy.all import IP, TCP, wrpcap

SERVER = "10.16.1.10"
CLIENT = "10.16.1.11"
PORT = 5432
SPORT = 47824

TEXT_OID = 25
INT4_OID = 23


def be32(n):
    return struct.pack(">I", n)


def be16(n):
    return struct.pack(">H", n)


def cstr(s):
    return s.encode() + b"\x00"


def msg(ident, body, declared_len=None):
    """A regular pgsql message: identifier, length (covers itself + body), body."""
    return ident + be32(4 + len(body) if declared_len is None else declared_len) + body


# ---------------------------------------------------------------- pgsql pieces


def startup(declared_len=None):
    """StartupMessage: length, protocol 3.0, then null-terminated key/value pairs."""
    body = be32(0x00030000)
    for kv in ("user", "postgres", "database", "test"):
        body += cstr(kv)
    body += b"\x00"
    return be32(4 + len(body) if declared_len is None else declared_len) + body


SERVER_PARAMS = [
    ("application_name", "psql"),
    ("client_encoding", "UTF8"),
    ("DateStyle", "ISO, MDY"),
]

def parameter_status(name, value):
    """ParameterStatus: name and value, both null-terminated."""
    return msg(b"S", cstr(name) + cstr(value))

def backend_key_data(pid, secret_key):
    """BackendKeyData: process id and cancellation secret. Length is always 12."""
    return msg(b"K", be32(pid) + be32(secret_key))

def query(sql, declared_len=None):
    return msg(b"Q", cstr(sql), declared_len)


AUTH_OK = msg(b"R", be32(0))
PARAM_STATUS = b"".join(parameter_status(name, value) for name, value in SERVER_PARAMS[:3])
BACKEND_KEY = backend_key_data(40720, 0x4D2)
READY = msg(b"Z", b"I")
TERMINATE = msg(b"X", b"")


def row_description(columns):
    """RowDescription: field count, then one descriptor per column."""
    body = be16(len(columns))
    for idx, (name, oid, size) in enumerate(columns):
        body += (
            cstr(name)
            + be32(0)                # table_oid: not a real table column
            + be16(idx)              # column_index
            + be32(oid)              # data_type_oid
            + struct.pack(">h", size)
            + struct.pack(">i", -1)  # type_modifier
            + be16(0)                # format_code: text
        )
    return msg(b"T", body)


def data_row(values):
    """DataRow: column count, then length-prefixed text values."""
    body = be16(len(values))
    for v in values:
        body += struct.pack(">i", len(v)) + v.encode()
    return msg(b"D", body)


def command_complete(tag):
    return msg(b"C", cstr(tag))


VERSION_STRING = (
    "PostgreSQL 16.2 on x86_64-pc-linux-gnu, compiled by "
    "gcc (Debian 12.2.0-14) 12.2.0, 64-bit"
)

VERSION_REPLY = (
    row_description([("version", TEXT_OID, -1)])
    + data_row([VERSION_STRING])
    + command_complete("SELECT 1")
    + READY
)

# secrets is empty, so the backend describes the columns and reports no rows.
SECRETS_REPLY = (
    row_description(
        [("id", INT4_OID, 4), ("name", TEXT_OID, -1), ("value", TEXT_OID, -1)]
    )
    + command_complete("SELECT 0")
    + READY
)


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

    def missing(self, payload):
        """The client sent this, but the capture does not contain it."""
        self.cseq += len(payload)

    def teardown(self):
        self._c("FA")
        self._s("A")
        self._s("FA")
        self._c("A")


def session(startup_len=None, secrets_query_len=None):
    f = Flow(SPORT)
    f.handshake()

    f.to_server(startup(startup_len))
    f.to_client(AUTH_OK + PARAM_STATUS + BACKEND_KEY + READY)

    f.missing(TERMINATE)

    # The ACK that closes this exchange also covers the omitted bytes.
    f.to_server(query("SELECT version();"))
    f.to_client(VERSION_REPLY)

    f.to_server(query("SELECT * FROM secrets;", secrets_query_len))
    f.to_client(SECRETS_REPLY)

    f.teardown()
    return f


assert len(startup()) == 37
assert len(TERMINATE) == 5
assert len(query("SELECT version();")) == 23
assert len(query("SELECT * FROM secrets;")) == 28

for name, kwargs in (
    ("input.pcap", {}),
    ("described-lengths.pcap", {"startup_len": 0x26, "secrets_query_len": 0x1D}),
):
    pkts = session(**kwargs).pkts
    wrpcap(name, pkts)
    print(f"wrote {name}: {len(pkts)} packets, 1 flow, {len(TERMINATE)}-byte gap")
