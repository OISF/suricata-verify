#!/usr/bin/env python3
"""
Redmine #7263 -- a backend can send an unbounded number of responses, so
tx.responses must be capped.

A big result set is *not* the way to grow tx.responses: DataRow messages are
folded into a single ConsolidatedDataRow when CommandComplete arrives, so
`SELECT * FROM huge_table` costs two entries no matter how many rows come
back. What grows the vector is the number of separate backend *messages* in
one transaction, and the startup sequence is where the protocol itself invites
a long run of them:

    AuthenticationOk -> ParameterStatus * N -> BackendKeyData -> ReadyForQuery

A real PostgreSQL server reports a dozen or so GUCs there. Nothing bounds N,
so a backend that reports hundreds is the ticket's case reached through an
entirely ordinary message flow -- no contrived ordering needed. (There is a limited pre-definided number of such Parameters, but it is already expected that this could grow or be configurable in the future, so the mechanism to accept that is there).

It also keeps the eve record valid. The logger writes one flat object per
transaction, so a transaction holding two of the same message type emits
duplicate JSON keys; a multi-statement simple query (`SELECT 1;SELECT 1;`)
does this with as few as two statements. ParameterStatus is the one response
logged as an array, each entry its own object, so a flood of them stays
schema-clean.

Four flows, differing only in how many parameters the backend reports
(max-responses is 21, set in suricata.yaml):

  47820  24 ParameterStatus -> the run overruns the cap partway, so the
                               parameters after it, BackendKeyData and
                               ReadyForQuery are all refused.
  47821  10 ParameterStatus -> the whole startup fits. Control.
  47822  20 ParameterStatus -> AuthenticationOk plus the run fill the vector
                               exactly, so BackendKeyData is the first thing
                               refused. Pins the boundary at MAX.
  47823  19 ParameterStatus -> the cap first bites at ReadyForQuery, so
                               BackendKeyData still lands.

47823 is the one alignment where the cap fires and the record still comes out
well-formed: the logger closes the parameter_status array only when a
non-ParameterStatus response follows the run, so every *other* overrunning
depth leaves that array open and the record a brace short. Without this flow,
a regression in that close would look identical to the cap misfiring.

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

# What a real server reports, in the order PostgreSQL sends it. The last two
# are custom GUCs, which is how a server legitimately exceeds the usual dozen.
SERVER_PARAMS = [
    ("application_name", "psql"),
    ("client_encoding", "UTF8"),
    ("DateStyle", "ISO, MDY"),
    ("default_transaction_read_only", "off"),
    ("in_hot_standby", "off"),
    ("integer_datetimes", "on"),
    ("IntervalStyle", "postgres"),
    ("is_superuser", "on"),
    ("server_encoding", "UTF8"),
    ("server_version", "16.2"),
    ("session_authorization", "postgres"),
    ("standard_conforming_strings", "on"),
    ("TimeZone", "Etc/UTC"),
    ("search_path", "census, public"),
    ("row_security", "off"),
    ("client_min_messages", "notice"),
    ("statement_timeout", "0"),
    ("lock_timeout", "0"),
    ("idle_in_transaction_session_timeout", "0"),
    ("scram_iterations", "4096"),
    ("custom.report_window", "2025Q2"),
    ("custom.trace_id", "9f2c1b7e"),
    ("custom.audit_level", "verbose"),
    ("custom.tenant_id", "42"),
]


def parameter_status(name, value):
    """ParameterStatus: name and value, both null-terminated."""
    return msg(b"S", cstr(name) + cstr(value))


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


def command_complete(rows):
    # The tag for a SELECT reports the *row* count, not the column count.
    return msg(b"C", cstr(f"SELECT {rows}"))


QUERY_SQL = "SELECT * from dummy_table;"
QUERY_REPLY = row_description(["a"]) + data_row(["1"]) + command_complete(1) + READY


def simulate(n_params):
    """
    Mirror the parser's accounting for the startup transaction, so the numbers
    claimed above are checked rather than asserted by hand.

    Every message in the startup sequence takes the single-push path, so the
    guard is `len < MAX` throughout. A refused push leaves the length alone and
    raises the event; it never truncates mid-message.
    """
    used, events, kept_params, key_data_logged = 0, 0, 0, False

    def push():
        nonlocal used, events
        if used < MAX_RESPONSES:
            used += 1
            return True
        events += 1
        return False

    push()                                  # AuthenticationOk
    for _ in range(n_params):
        if push():
            kept_params += 1
    key_data_logged = push()                # BackendKeyData
    push()                                  # ReadyForQuery, not logged either way
    return used, events, kept_params, key_data_logged


# MAX + 3: the run overruns by 3, and BackendKeyData and ReadyForQuery are
# refused on top of that.
FLOOD_PARAMS = MAX_RESPONSES + 3
CONTROL_PARAMS = 10
# MAX - 1: AuthenticationOk plus the run fill the vector exactly.
BOUNDARY_PARAMS = MAX_RESPONSES - 1
# MAX - 2: AuthenticationOk + the run + BackendKeyData fill the vector exactly,
# leaving ReadyForQuery as the only refusal.
EDGE_PARAMS = MAX_RESPONSES - 2

FLOOD = simulate(FLOOD_PARAMS)
CONTROL = simulate(CONTROL_PARAMS)
BOUNDARY = simulate(BOUNDARY_PARAMS)
EDGE = simulate(EDGE_PARAMS)

# 47820: the run itself is cut short, so nothing after it survives either.
assert FLOOD[0] == MAX_RESPONSES and FLOOD[1] == 6
assert FLOOD[2] == MAX_RESPONSES - 1 and not FLOOD[3]
# 47821: the whole startup fits.
assert CONTROL[1] == 0 and CONTROL[2] == CONTROL_PARAMS and CONTROL[3]
# 47822: exactly full after the run, so BackendKeyData is the first refusal.
assert BOUNDARY[0] == MAX_RESPONSES and BOUNDARY[1] == 2
assert BOUNDARY[2] == BOUNDARY_PARAMS and not BOUNDARY[3]
# 47823: one refusal, and BackendKeyData lands -- so the array gets closed and
# the record stays well-formed even though the cap fired.
assert EDGE[0] == MAX_RESPONSES and EDGE[1] == 1
assert EDGE[2] == EDGE_PARAMS and EDGE[3]

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


def session(sport, n_params, pid):
    """
    A trust/no-auth startup -- AuthenticationOk, the server's parameters,
    BackendKeyData, ReadyForQuery -- then one ordinary query.
    """
    f = Flow(sport)
    f.handshake()
    f.to_server(STARTUP)

    params = b"".join(
        parameter_status(name, value) for name, value in SERVER_PARAMS[:n_params]
    )
    # The whole startup reply travels in one segment, so the transaction reaches
    # the detection engine at a single point and the event count is not a
    # function of how the responses were segmented.
    f.to_client(AUTH_OK + params + backend_key_data(pid, 0x4D2) + READY)

    f.to_server(msg(b"Q", cstr(QUERY_SQL)))
    f.to_client(QUERY_REPLY)

    f.teardown()
    return f


# Distinct backend pids, so a filter can tell whether a flow's BackendKeyData
# was stored or refused.
FLOOD_PID = 20001
CONTROL_PID = 20002
BOUNDARY_PID = 20003
EDGE_PID = 20004

assert len(SERVER_PARAMS) >= FLOOD_PARAMS

flows = [
    session(47820, FLOOD_PARAMS, FLOOD_PID),
    session(47821, CONTROL_PARAMS, CONTROL_PID),
    session(47822, BOUNDARY_PARAMS, BOUNDARY_PID),
    session(47823, EDGE_PARAMS, EDGE_PID),
]

pkts = [p for f in flows for p in f.pkts]
wrpcap("input.pcap", pkts)

print(f"wrote input.pcap: {len(pkts)} packets, {len(flows)} flows, "
      f"max-responses {MAX_RESPONSES}")
for sport, n, pid, sim in (
    (47820, FLOOD_PARAMS, FLOOD_PID, FLOOD),
    (47821, CONTROL_PARAMS, CONTROL_PID, CONTROL),
    (47822, BOUNDARY_PARAMS, BOUNDARY_PID, BOUNDARY),
    (47823, EDGE_PARAMS, EDGE_PID, EDGE),
):
    used, events, kept, key_logged = sim
    print(f"  {sport}: {n:>2} ParameterStatus -> {used} stored, {events} event(s), "
          f"{kept} parameters logged, backend_key_data "
          f"{'logged' if key_logged else 'refused'} (pid {pid})")
