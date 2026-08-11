#!/usr/bin/env python3
"""
Redmine #8863 -- pgsql CopyOutResponse/CopyInResponse ignore the wire `length`.

Three flows, one per case:

  47810  'H' over-read   length=8, columns big  -> Suricata SWALLOWS a following
                                                   ErrorResponse as format codes
  47811  'H' under-read  length big, columns=0  -> Suricata PARSES padding the
                                                   peer skips (fake msg injection)
  47812  'G' over-read   same as 47810, CopyInResponse sibling

Baseline handshake/messages modelled on tests/pgsql/pgsql-copy-data-out.
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


def error_response(severity, code, message, ident=b"E"):
    body = b"S" + cstr(severity) + b"C" + cstr(code) + b"M" + cstr(message) + b"\x00"
    return msg(ident, body)


# ---------------------------------------------------------------- pgsql pieces

# StartupMessage, protocol 3.0, user=postgres. No identifier byte; also moves the
# flow out of SSLRequestReceived so the Copy parsers are reachable.
STARTUP = be32(23) + be32(0x00030000) + cstr("user") + cstr("postgres") + b"\x00"
assert len(STARTUP) == 23

AUTH_OK = msg(b"R", be32(0))          # 52 00000008 00000000
READY = msg(b"Z", b"I")               # 5a 00000005 49
COPY_DONE = msg(b"c", b"")            # 63 00000004
assert AUTH_OK.hex() == "520000000800000000"
assert READY.hex() == "5a0000000549"


def craft_copy_response(ident, swallow_len):
    """
    Build a CopyOutResponse ('H') / CopyInResponse ('G') whose wire `length`
    frames a short body, but whose `columns` count makes a buggy parser
    consume `swallow_len` bytes past the wire message boundary.
    """
    pad = 1 if (pad1 := (1 + swallow_len) % 2) == 0 else 2
    del pad1
    length = 7 + pad                      # 4 (length field) + format + columns + pad
    swallowed = pad + swallow_len         # pad byte(s) + the message(s) to hide
    assert swallowed % 2 == 0, "buggy parser swallows 2 bytes per format code"
    columns = swallowed // 2
    hdr = ident + be32(length) + b"\x00" + be16(columns) + b"\x00" * pad
    assert len(hdr) == 1 + length         # message occupies offsets 0..length
    return hdr, columns, length


def craft_under_read(ident, injected):
    """
    Build a Copy response whose wire `length` covers `injected` inside its own
    body while `columns` is 0. A buggy parser stops after `columns` and then
    parses `injected` as if it were real backend messages; a length-framing
    peer skips it entirely. Both re-sync at the end of the declared body.
    """
    columns = 0
    length = 7 + len(injected)            # body = format + columns + injected
    hdr = ident + be32(length) + b"\x00" + be16(columns)
    pdu = hdr + injected
    assert len(pdu) == 1 + length
    # buggy parser resumes at offset 8, exactly where `injected` starts
    assert len(hdr) == 8
    return pdu, length


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
        """Handshake + StartupMessage + AuthenticationOk/ReadyForQuery."""
        self.handshake()
        self.to_server(STARTUP)
        self.to_client(AUTH_OK + READY)


def dump(title, payload, notes):
    print(f"\n=== {title} ===")
    print(f"  server->client payload: {len(payload)} bytes")
    for off, label in notes:
        window = payload[off:off + 8].hex()
        print(f"  offset {off:>3}  {window:<16}  {label}")


# ------------------------------------------------------------------ flow 47810
# 'H' over-read: hide a real ErrorResponse from Suricata.

hidden_a = error_response("ERROR", "42501", "permission denied for table secrets")
hdr_a, cols_a, len_a = craft_copy_response(b"\x48", len(hidden_a))
resp_a = hdr_a + hidden_a + READY

# Wire framing: 'H' occupies 0..len_a, so the peer's next message is at len_a+1.
assert len_a + 1 == len(hdr_a)
# Buggy Suricata: 8 bytes of header, then 2*cols_a bytes of "format codes".
assert 8 + 2 * cols_a == len(hdr_a) + len(hidden_a)
# ... which lands exactly on the ReadyForQuery, so nothing looks malformed.
assert resp_a[8 + 2 * cols_a:] == READY

f_a = Flow(47810)
f_a.startup()
f_a.to_server(msg(b"Q", cstr("COPY t TO STDOUT")))
f_a.to_client(resp_a)          # single segment: the swallowed bytes must be present
f_a.teardown()

dump(
    f"flow 47810  'H' over-read  length={len_a} columns={cols_a}",
    resp_a,
    [
        (0, f"'H' CopyOutResponse, length={len_a} (peer: next msg at {len_a + 1})"),
        (5, f"format=0, columns={cols_a} (a consistent length would be {7 + 2 * cols_a})"),
        (len(hdr_a), "'E' ErrorResponse -- SWALLOWED as format codes"),
        (8 + 2 * cols_a, "'Z' ReadyForQuery -- where Suricata resumes"),
    ],
)

# ------------------------------------------------------------------ flow 47811
# 'H' under-read: inject a message only Suricata sees.

injected_b = error_response("FATAL", "28000", "INJECTED - CLIENT NEVER SAW THIS")
pdu_b, len_b = craft_under_read(b"\x48", injected_b)
tail_b = msg(b"d", b"1\tsecret-row\n") + COPY_DONE + msg(b"C", cstr("COPY 1")) + READY
resp_b = pdu_b + tail_b

# Buggy Suricata resumes at offset 8 and reads `injected_b` as backend messages.
assert resp_b[8:8 + len(injected_b)] == injected_b
# Both views re-sync at the end of the declared body, so the desync is contained.
assert resp_b[len_b + 1:] == tail_b

f_b = Flow(47811)
f_b.startup()
f_b.to_server(msg(b"Q", cstr("COPY t TO STDOUT")))
f_b.to_client(resp_b)
f_b.teardown()

dump(
    f"flow 47811  'H' under-read  length={len_b} columns=0",
    resp_b,
    [
        (0, f"'H' CopyOutResponse, length={len_b} (peer: next msg at {len_b + 1})"),
        (5, "format=0, columns=0 -> buggy parser stops at offset 8"),
        (8, "'E' FATAL ErrorResponse -- INJECTED, peer skips it as body padding"),
        (len_b + 1, "'d' CopyData -- real next message, both views agree again"),
    ],
)

# ------------------------------------------------------------------ flow 47812
# 'G' over-read: the CopyInResponse sibling has the identical defect.

hidden_c = error_response("ERROR", "42501", "permission denied for table secrets")
hdr_c, cols_c, len_c = craft_copy_response(b"\x47", len(hidden_c))
resp_c = hdr_c + hidden_c + READY

assert 8 + 2 * cols_c == len(hdr_c) + len(hidden_c)
assert resp_c[8 + 2 * cols_c:] == READY

f_c = Flow(47812)
f_c.startup()
f_c.to_server(msg(b"Q", cstr("COPY t FROM STDIN")))
f_c.to_client(resp_c)
f_c.teardown()

dump(
    f"flow 47812  'G' over-read  length={len_c} columns={cols_c}",
    resp_c,
    [
        (0, f"'G' CopyInResponse, length={len_c} (peer: next msg at {len_c + 1})"),
        (5, f"format=0, columns={cols_c} (a consistent length would be {7 + 2 * cols_c})"),
        (len(hdr_c), "'E' ErrorResponse -- SWALLOWED as format codes"),
        (8 + 2 * cols_c, "'Z' ReadyForQuery -- where Suricata resumes"),
    ],
)

# ----------------------------------------------------------------------- output

pkts = f_a.pkts + f_b.pkts + f_c.pkts
wrpcap("input.pcap", pkts)
print(f"\nwrote input.pcap: {len(pkts)} packets, 3 flows")
