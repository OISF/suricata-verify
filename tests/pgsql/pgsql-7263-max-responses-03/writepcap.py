#!/usr/bin/env python3
"""
Redmine #7263 -- capping a transaction's responses, for the two response kinds
that are summarised rather than logged one by one: the rows of a SELECT, and
the data of a COPY TO STDOUT.

Companion to pgsql-7263-max-responses-01, which reaches the cap during the
startup sequence. A result set cannot get a transaction there: however many
rows come back, DataRow and CopyData are summarised into a single response, so
a SELECT reply is four responses deep and a COPY reply five. Reaching the cap
inside a query transaction therefore needs other messages to arrive alongside
the result.

ParameterStatus is what fills it here. The protocol allows it at any point --
the backend reports a parameter whenever its value changes, and a SET run by a
function the query calls, or a configuration reload landing mid-query, does
exactly that. Names outside the set Suricata knows are reported the same way, as
servers already do for custom GUCs.

Two flows, both a trust/no-auth startup reporting the parameters a real server
sends, followed by one query whose reply carries a batch of parameter reports:

  47830  SELECT age FROM census;  three rows, then 19 parameter reports
  47831  COPY census TO STDOUT;   three rows of COPY output, then 19 reports

By the time each reply's closing message arrives, the transaction has no room
for a summarised response and the message that closes it, so 47830 keeps only
its field_count and 47831 only its copy_out_response. What survives, and how
many events are raised, is asserted in test.yaml.

TCP plumbing modelled on tests/pgsql/pgsql-bug-8863-copy-in.
"""
import struct
from scapy.all import IP, TCP, wrpcap

SERVER = "10.16.1.10"
CLIENT = "10.16.1.11"
PORT = 5432

# Must match app-layer.protocols.pgsql.max-responses in suricata.yaml
MAX_RESPONSES = 21


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

INT4_OID = 23

# What a real server reports at startup, in the order PostgreSQL sends it.
STARTUP_PARAMS = [
    ("application_name", "psql"),
    ("client_encoding", "UTF8"),
    ("DateStyle", "ISO, MDY"),
    ("integer_datetimes", "on"),
    ("IntervalStyle", "postgres"),
    ("is_superuser", "on"),
    ("server_encoding", "UTF8"),
    ("server_version", "13.19"),
    ("session_authorization", "postgres"),
    ("standard_conforming_strings", "on"),
    ("TimeZone", "Etc/UTC"),
]

# Reported mid-query: settings the statement itself changed. A mix of session
# parameters and custom GUCs, which servers report by the same mechanism.
QUERY_PARAMS = [
    ("application_name", "census_report"),
    ("search_path", "census, public"),
    ("statement_timeout", "30s"),
    ("lock_timeout", "5s"),
    ("idle_in_transaction_session_timeout", "60s"),
    ("DateStyle", "ISO, DMY"),
    ("IntervalStyle", "iso_8601"),
    ("TimeZone", "Europe/Lisbon"),
    ("client_min_messages", "warning"),
    ("default_transaction_read_only", "on"),
    ("row_security", "on"),
    ("custom.tenant_id", "42"),
    ("custom.audit_level", "verbose"),
    ("custom.report_window", "2025Q2"),
    ("custom.locale_override", "pt_PT"),
    ("custom.cache_hint", "cold"),
    ("custom.trace_id", "9f2c1b7e"),
    ("custom.export_format", "parquet"),
    ("custom.batch_size", "5000"),
]

# MAX - 2: the run leaves the transaction one slot short of the two a
# summarised response and the message closing it need together, so the run
# itself still fits entirely while everything after it is refused.
assert len(QUERY_PARAMS) == MAX_RESPONSES - 2


def parameter_status(name, value):
    """ParameterStatus: name and value, both null-terminated."""
    return msg(b"S", cstr(name) + cstr(value))


def parameter_run(params):
    return b"".join(parameter_status(name, value) for name, value in params)


def backend_key_data(pid, secret_key):
    """BackendKeyData: process id and cancellation secret. Length is always 12."""
    return msg(b"K", be32(pid) + be32(secret_key))


def row_description(columns):
    """RowDescription: field_count, then one 18-byte descriptor per column."""
    body = be16(len(columns))
    for idx, name in enumerate(columns):
        body += (
            cstr(name)
            + be32(0)                # table_oid: not a real table column
            + be16(idx)              # column_index
            + be32(INT4_OID)         # data_type_oid
            + be16(4)                # data_type_size
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


def copy_out_response(columns):
    """CopyOutResponse: overall format, column count, then a format per column."""
    body = b"\x00" + be16(columns) + b"".join(be16(0) for _ in range(columns))
    return msg(b"H", body)


def copy_data(payload):
    """CopyData carrying one row of text-format COPY output."""
    return msg(b"d", payload.encode())


COPY_DONE = msg(b"c", b"")


def command_complete(tag):
    return msg(b"C", cstr(tag))


# --------------------------------------------------------------- the two queries

# Values of differing length, so a mistake in summing them could not hide
# behind symmetry.
SELECT_AGES = ["20", "7", "113"]
SELECT_SQL = "SELECT age FROM census;"
SELECT_REPLY = (
    row_description(["age"])
    + b"".join(data_row([age]) for age in SELECT_AGES)
    + parameter_run(QUERY_PARAMS)
    + command_complete(f"SELECT {len(SELECT_AGES)}")
    + READY
)

COPY_ROWS = ["1\talpha\n", "2\tbeta\n", "3\tgamma\n"]
COPY_SQL = "COPY census TO STDOUT;"
COPY_REPLY = (
    copy_out_response(1)
    + b"".join(copy_data(row) for row in COPY_ROWS)
    + parameter_run(QUERY_PARAMS)
    + COPY_DONE
    + command_complete(f"COPY {len(COPY_ROWS)}")
    + READY
)


class Accounting:
    """
    Predict what the cap keeps, so the expectations above are checked here
    rather than asserted by hand. Anything refused is dropped whole and raises
    one event.
    """

    def __init__(self):
        self.used = 0
        self.events = 0
        self.logged = []

    def one(self, tag):
        if self.used < MAX_RESPONSES:
            self.used += 1
            self.logged.append(tag)
        else:
            self.events += 1

    def pair(self, summary_tag, tag):
        if self.used + 2 <= MAX_RESPONSES:
            self.used += 2
            self.logged += [summary_tag, tag]
        else:
            self.events += 1

    def run(self, params, tag):
        for name, _ in params:
            self.one(f"{tag}:{name}")


def startup_tx():
    a = Accounting()
    a.one("authentication_ok")
    a.run(STARTUP_PARAMS, "param")
    a.one("backend_key_data")
    a.one("ready_for_query")       # stored or not, never logged
    return a


def select_tx():
    a = Accounting()
    a.one("field_count")           # RowDescription
    # The rows are summarised, so they take no room until the statement ends.
    a.run(QUERY_PARAMS, "param")
    a.pair("data_rows", "command_completed")
    a.one("ready_for_query")
    return a


def copy_tx():
    a = Accounting()
    a.one("copy_out_response")
    a.run(QUERY_PARAMS, "param")
    a.pair("copy_data_out", "copy_done")
    # With the rows still outstanding, the CommandComplete behind it is treated
    # the same way. Refused either way at this depth.
    a.pair("data_rows", "command_completed")
    a.one("ready_for_query")
    return a


STARTUP_TX = startup_tx()
SELECT_TX = select_tx()
COPY_TX = copy_tx()

# The startup sequence fits with room to spare, so nothing there is refused.
assert STARTUP_TX.events == 0
assert "backend_key_data" in STARTUP_TX.logged
# SELECT: every parameter report fits, the summarised row and its
# CommandComplete do not.
assert SELECT_TX.events == 1
assert SELECT_TX.logged[0] == "field_count"
assert "data_rows" not in SELECT_TX.logged
assert "command_completed" not in SELECT_TX.logged
assert len([t for t in SELECT_TX.logged if t.startswith("param:")]) == len(QUERY_PARAMS)
# COPY: both summarised responses are refused.
assert COPY_TX.events == 2
assert COPY_TX.logged[0] == "copy_out_response"
assert "copy_data_out" not in COPY_TX.logged
assert "command_completed" not in COPY_TX.logged

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


def session(sport, pid, sql, reply):
    """
    A trust/no-auth startup, then one query. Each reply travels in one segment,
    so the transaction reaches the detection engine at a single point.
    """
    f = Flow(sport)
    f.handshake()
    f.to_server(STARTUP)
    f.to_client(
        AUTH_OK
        + parameter_run(STARTUP_PARAMS)
        + backend_key_data(pid, 0x4D2)
        + READY
    )
    f.to_server(msg(b"Q", cstr(sql)))
    f.to_client(reply)
    f.teardown()
    return f


SELECT_PID = 20301
COPY_PID = 20302

flows = [
    session(47830, SELECT_PID, SELECT_SQL, SELECT_REPLY),
    session(47831, COPY_PID, COPY_SQL, COPY_REPLY),
]

pkts = [p for f in flows for p in f.pkts]
wrpcap("input.pcap", pkts)

print(f"wrote input.pcap: {len(pkts)} packets, {len(flows)} flows, "
      f"max-responses {MAX_RESPONSES}")
print(f"  startup (both flows): {len(STARTUP_PARAMS)} parameters, "
      f"{STARTUP_TX.used} stored, {STARTUP_TX.events} event(s)")
print(f"  47830 {SELECT_SQL:<24} {SELECT_TX.used} stored, "
      f"{SELECT_TX.events} event(s)")
print(f"  47831 {COPY_SQL:<24} {COPY_TX.used} stored, "
      f"{COPY_TX.events} event(s)")
