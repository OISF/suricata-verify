#!/usr/bin/env python3
"""
Redmine #7263 -- a backend can send an unbounded number of responses, so
tx.responses must be capped.

Simulating a Startup phase with several ParameterStatus, to force the default max.responses cap.

    AuthenticationOk -> ParameterStatus * N -> BackendKeyData -> ReadyForQuery

A real PostgreSQL server reports a dozen or so GUCs there. Nothing bounds N,
so a backend that reports hundreds is the ticket's case reached through an
entirely ordinary message flow -- no contrived ordering needed. (There is a limited pre-definided number of such Parameters, but it is already expected that this could grow or be configurable in the future, so the mechanism to accept that is there).

Reaching the cap takes a backend reporting
dozens of settings, which is why SERVER_PARAMS runs to an extension-heavy
70 entries rather than the usual dozen.

Four flows, differing only in how many parameters the backend reports:

  47820  67 ParameterStatus -> the run overruns the cap partway, so the
                               parameters after it, BackendKeyData and
                               ReadyForQuery are all refused.
  47821  10 ParameterStatus -> the whole startup fits. Control.
  47822  63 ParameterStatus -> AuthenticationOk plus the run fill the vector
                               exactly, so BackendKeyData is the first thing
                               refused. Pins the boundary at MAX.
  47823  62 ParameterStatus -> the cap first bites at ReadyForQuery, so
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

# PGSQL_CONFIG_DEFAULT_MAX_RESPONSES. suricata.yaml sets max-responses to 0,
# which is rejected as out of range, so this built-in default is what applies.
MAX_RESPONSES = 64


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

# What a real server reports, in the order PostgreSQL sends it: the stock
# GUC_REPORT settings first, then custom ones.
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
    ("pgaudit.log", "write, ddl"),
    ("pgaudit.log_catalog", "off"),
    ("pgaudit.log_client", "on"),
    ("pgaudit.log_level", "notice"),
    ("pgaudit.log_parameter", "on"),
    ("pgaudit.log_relation", "on"),
    ("pgaudit.log_statement_once", "off"),
    ("pgaudit.role", "auditor"),
    ("pg_stat_statements.track", "top"),
    ("pg_stat_statements.track_utility", "on"),
    ("pg_stat_statements.save", "on"),
    ("citus.node_conninfo", "sslmode=require"),
    ("citus.multi_shard_modify_mode", "parallel"),
    ("citus.propagate_set_commands", "local"),
    ("citus.shard_count", "32"),
    ("citus.task_executor_type", "adaptive"),
    ("timescaledb.telemetry_level", "off"),
    ("timescaledb.max_background_workers", "8"),
    ("timescaledb.license", "timescale"),
    ("postgis.gdal_enabled_drivers", "ENABLE_ALL"),
    ("postgis.backend", "geos"),
    ("plpgsql.check_asserts", "on"),
    ("plpgsql.extra_errors", "shadowed_variables"),
    ("plpgsql.variable_conflict", "error"),
    ("app.deployment", "census-eu-west"),
    ("app.release", "2025.06.3"),
    ("app.feature_flags", "sharding,async_audit"),
    ("app.request_id", "b91d4c02"),
    ("app.locale", "pt_BR"),
    ("app.currency", "BRL"),
    ("tenant.name", "acme"),
    ("tenant.region", "eu-west-1"),
    ("tenant.plan", "enterprise"),
    ("tenant.shard", "07"),
    ("audit.session_user", "reporting"),
    ("audit.client_host", "10.16.1.11"),
    ("audit.trace_sampling", "0.25"),
    ("audit.retention_days", "365"),
    ("custom.report_currency", "EUR"),
    ("custom.report_locale", "en_GB"),
    ("custom.report_format", "parquet"),
    ("custom.export_bucket", "s3://census-exports"),
    ("custom.pipeline_stage", "transform"),
    ("custom.batch_size", "5000"),
    ("custom.retry_budget", "3"),
    ("custom.correlation_id", "7c3e91aa"),
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
