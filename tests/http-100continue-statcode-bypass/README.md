# http-100continue-statcode-bypass

NIDS-mode end-to-end reproducer for the 100-Continue stat_code
deviations (false negative on the final response + false positive
double alert on the 100 line) with a **standard, spec-compliant
exchange** - no crafted or oversized traffic.

## What this test reproduces

Flow A (baseline, `10.0.0.1`): normal `GET` -> `200 OK`. Rules on the
response `stat_code` fire normally.

Flow B (`10.0.0.3`): `POST` with `Expect: 100-continue` (RFC 7231);
the server answers with a bare `100 Continue` followed by the final
`200 OK`. On a pre-fix build the exact rule that fires on flow A's
final response silently never fires on flow B's final response, and
the interim 100 line alerts twice. The only difference between the
flows is the `Expect: 100-continue` handshake.

The test expects the **fixed** behaviour:

| observation                          | flow A | flow B (expected) | on a pre-fix build |
|--------------------------------------|--------|-------------------|--------------------|
| `alert ... http.stat_code; content:"200"` (mpm, sid 1001) on the final 200 | 1      | 1                 | **0 (bypassed)**   |
| same rule without MPM (pcre, sid 1003) | 1      | 1                 | **0 (bypassed)**   |
| `alert ... http.stat_code; content:"100"` (sid 1002) on the 100 line | 0      | 1                 | **2 (double alert)** |

So the test is RED against a pre-fix build on exactly those flow-B
checks, and GREEN once the fix (new response tx / progress reset on
100-continue) lands.

**Scope (pinned by sids 1004-1006, green even on a pre-fix build):**
response headers, response body and request-side detection are
unaffected by the deviation - the affected set is the response-line
buffer family (stat_code, stat_msg, response_line and the protocol
token; the sibling tests reproduce the same deviation for stat_msg
and response_line). Flow B's final 200 additionally carries a
distinctive response header (`X-Test: finalmarker`) and body
(`hello200`); the rules on `http.header` (1004) and
`http.response_body` (1005) fire on the final 200 as usual, and the
request-side rule on `http.host` (1006) fires on the request.
Mechanistically, the stale per-tx detect_progress bookkeeping (stored
as `min_progress + 1 = 2` by the stat_code engine's final run, whose
min progress is LINE) only skips engines with a min progress below 2
when the final 200 reaches COMPLETE; the response-header engine (min
progress HEADERS) and the body engines are not skipped, and the
rewind only touches the response tx, leaving request-side detection
unaffected.

## Real-world client and server behaviour (severity)

Both sides of flow B behave exactly like a standard, non-malicious
deployment:

- **Client:** textbook RFC 7231 Expect: 100-continue - sends the POST
  headers with `Expect: 100-continue` and waits for the `100` before
  sending the body. This is spec-legal (the client may also send the
  body early) and is the normal pattern for large uploads, where it
  avoids retransmitting a large body if the server rejects the request
  up front.
- **Server:** standard 100-continue handling - replies with a bare
  `100 Continue` status line (no headers; the shape Apache/nginx/Java
  and similar send) before the final response. No attacker-controlled
  or misconfigured server is involved.
- **Consequence:** the deviation is reachable with a **legitimate
  client and a legitimate server** (ordinary traffic), not the
  "evil client + evil server" class.

## Mechanism

1. `100 Continue` line (own packet, acked by the client): response tx
   at HEADERS (C > P). The prefilter's final run alerts on the "100"
   stat_code buffer and stores the per-tx `detect_progress`
   bookkeeping for the tx.
2. The empty line (own packet, acked): because the 100 has no
   `Transfer-Encoding`/`Content-Length`, the htp parser treats it as
   100-Continue and **rewinds the same tx**: headers are cleared,
   progress goes HEADERS -> LINE, but the status number stays `100`
   and the rewind resets neither the stale stat_code buffer nor the
   per-tx `detect_progress`. The non-terminal re-run at LINE matches
   the stale "100" buffer again - **second alert (FP double alert)**.
3. The final `200 OK` is parsed on the same tx and reaches COMPLETE
   (C > P) - but the tx-level prefilter bookkeeping sees
   `detect_progress > tx_min_progress` and skips the tx entirely: the
   final 200's stat_code buffer is never inspected - **FN bypass**.

**Parse-cycle requirement:** the deviation needs the 100 status line
to be committed in its own parse/detect cycle (HEADERS, C > P) before
the empty line rewinds the tx. In NIDS mode the stream engine
processes each direction when the opposing side acks it, so the
client's normal auto-ACKs of the 100 line and the empty line (carried
by the test pcap) provide the separate cycles. If the client never
acks the server data, the stream engine defers all toclient parsing to
flow teardown: the 100 line, the empty line and the final 200 are
then parsed in a single pass and the deviation is masked. (The
IPS-mode sibling test, `http-100continue-statcode-bypass-ips`,
reproduces the same deviation without any ACK dependency: inline mode
processes each packet's own direction immediately.)

## Notes

- Regular pcap, scapy-generated by `writepcap.py`, byte-identical to
  the script's output.
- tshark dissects both flows as HTTP overall; note that tshark (4.6.4)
  does not HTTP-dissect flow B's request and 100-line packets because
  the 100 response spans two packets (the 100 line and the empty line
  are separate) - a dissector quirk, verified against a control pcap
  with the 100 self-contained in one packet (which tshark dissects
  fully, request included). Suricata parses the pcap correctly, as the
  test results show.
