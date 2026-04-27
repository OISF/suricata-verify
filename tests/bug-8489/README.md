# bug-8489

Tests for Redmine issue 8489 — FTP's `too_many_transactions` event
wasn't being raised when a flow exceeded
`app-layer.protocols.ftp.max-tx`.

pcaps are generated using flowsynt -- see the Makefile in each directory.

## Test cases

### bug-8489-01 — limit exceeded, event fires

Two `PWD` commands with `max-tx=1`. The second one pushes the live-tx
count past the limit and the event fires. Baseline positive case —
this is what the bug was actually about.

### bug-8489-02 — under the limit, no event

Six transactions with `max-tx=10`. The limit is never hit, so the
event never fires.

This one doesn't exercise the fix. With the bug fixed or unfixed the
result is the same: zero anomalies, zero alerts. It's here as a guard
against the *opposite* regression — someone accidentally broadens the
firing condition (`>` → `>=`, fires on every tx creation, etc.). In
those scenarios -01 and -03 would still pass but -02 would fail. If
you ever find yourself wanting to delete it, delete it deliberately,
not because it "doesn't seem to test anything."

### bug-8489-03 — flow keeps parsing after overflow

Bursts three `PWD`s past `max-tx=1`, then sends a `CWD` after a
server response. Checks that the event doesn't halt the flow — the
`CWD` after the burst must still be logged, and each excess `PWD`
creation reaps one stale tx with the event attached to it.

## Why the response rule?

Each test ships a `response_command_too_long` rule alongside the
`too_many_transactions` rule. The response rule looks irrelevant and
never fires in any of these pcaps — but it's not dead weight. Without
at least one `to_client` app-layer-event signature loaded, Suricata
skips to_client FTP parsing, responses don't complete transactions,
and the to_server-side limit check never fires at all. The response
rule is scaffolding, not an assertion.
