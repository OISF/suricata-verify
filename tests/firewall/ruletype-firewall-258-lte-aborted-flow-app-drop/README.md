# Fail-closed app-policy drop at flow end when the parser completes the tx on stream close

Fail-closed check for the firewall auto-accept-prior-states
(`accept:... proto:hook http1:<request_headers`) logic when a flow dies
with an in-progress request: on stream close the htp parser completes the
request transaction (progress advances to `request_complete`), so the no
match of the pending LTE rule becomes definitive (engine eof:
`progress > registered progress`) and the per-hook default app policy
must drop the flow - the flow may not end with the rule still pending and
no verdict.

The LTE rule (sid 100) accepts the prior states while it is pending and
waits for the marker header line `MARKERHDR` at `request_headers`:

* flow A (49380) completes the request with the marker header: the rule
  matches (`accept:flow`), no drops;
* flow B (49381) completes the request line plus two headers in the
  first segment (progress moves to `request_headers`), sends a truncated
  header line (`X-Pa`, no CRLF) in the second segment and then RSTs. The
  RST pass sees the completed tx (progress 5): the definitive no match
  applies the default app policy.

Expected: exactly 1 `firewall default app policy` drop (flow B, at the
RST packet). The complementary case - a parser that leaves the tx short at
flow end (dnp3) and the pending-state accept on the early packets - is
covered by test 257.
