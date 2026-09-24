# ruletype-firewall-259-lte-failing-rule-later-accept

Regression test: a rule at an earlier state fails its content, but a later
`<hook` (auto-accept-prior-states) rule covers that state and matches on a
later one. The failing rule's state must not be dropped by the per-state
default policy while the later rule is pending.

## Scenario

`GET /api` with `Host: example.com`, request line and headers in separate
segments.

* sid:5 `accept:flow http1:<request_line (http.uri; content:"/nope")` fails
  at `request_line`.
* sid:6 `accept:flow http1:<request_headers (http.host;
  content:"example.com")` auto-accepts `request_line` while pending and
  matches once the Host header is parsed.

## Expected

* sid:6 alert on the headers packet (pkt 6); no sid:5 alert.
* 0 `firewall default app policy` drops and 0 `firewall rules` drops: the
  flow is accepted.

## Related

Redmine #8944 (auto-accept-prior-states / `<hook` handling).
