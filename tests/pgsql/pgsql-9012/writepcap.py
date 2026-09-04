#!/usr/bin/env python3
"""
A PostgreSQL startup that never finishes.

The client sends a StartupMessage and the backend begins the usual reply --
AuthenticationOk, then the parameters it reports:

    AuthenticationOk -> ParameterStatus * 3

and then goes quiet. BackendKeyData and ReadyForQuery never arrive, and
neither side closes the connection: no FIN, no RST. The flow is left to time
out, which is what happens when a backend dies partway through greeting a
client, or when a capture starts after the connection did.

Three parameters is a short, unremarkable run -- nothing here is a flood.

TCP plumbing modelled on tests/pgsql/pgsql-7263-max-responses-01.
"""
import struct
from scapy.all import IP, TCP, wrpcap

SERVER = "10.16.1.10"
CLIENT = "10.16.1.11"
PORT = 5432
SPORT = 47840


def be32(n):
    return struct.pack(">I", n)


def cstr(s):
    return s.encode() + b"\x00"


def msg(ident, body):
    """A regular pgsql message: identifier, length (covers itself + body), body."""
    return ident + be32(4 + len(body)) + body


# ---------------------------------------------------------------- pgsql pieces

STARTUP = be32(23) + be32(0x00030000) + cstr("user") + cstr("postgres") + b"\x00"
assert len(STARTUP) == 23

AUTH_OK = msg(b"R", be32(0))

# The first three parameters a real server reports, in the order it sends them.
SERVER_PARAMS = [
    ("application_name", "psql"),
    ("client_encoding", "UTF8"),
    ("DateStyle", "ISO, MDY"),
]


def parameter_status(name, value):
    """ParameterStatus: name and value, both null-terminated."""
    return msg(b"S", cstr(name) + cstr(value))


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


f = Flow(SPORT)
f.handshake()
f.to_server(STARTUP)

params = b"".join(parameter_status(name, value) for name, value in SERVER_PARAMS)
f.to_client(AUTH_OK + params)

# No teardown on purpose: the startup is left hanging.

wrpcap("input.pcap", f.pkts)

print(f"wrote input.pcap: {len(f.pkts)} packets, 1 flow")
print(f"  {SPORT}: AuthenticationOk + {len(SERVER_PARAMS)} ParameterStatus, "
      "then silence (no BackendKeyData, no ReadyForQuery, no FIN)")
