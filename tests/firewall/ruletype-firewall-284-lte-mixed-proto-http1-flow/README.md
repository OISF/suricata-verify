# ruletype-firewall-284-lte-mixed-proto-http1-flow

Cross-protocol LTE (`<hook`) isolation on an HTTP/1 flow: the mirror of
`ruletype-firewall-283-lte-mixed-proto-tls-flow`. A mixed ruleset where the
HTTP/1 rules and foreign-protocol rules (tls, smtp, http2) share one firewall
ruleset; the foreign rules must not contribute coverage to the HTTP/1
transaction.

## Scenario

`../lte-matrix-data/http1.pcap` (request `GET /index`).

HTTP/1 rules:

* sid:100 `accept:hook,alert http1:<request_line (http.uri; content:"/index")`
  matches the URI at `request_line` (pkt 6) and accepts the hook.
  `accept:hook` (not `accept:flow`) is used so the later state default can still
  fire.
* sid:101 `accept:flow,alert http1:<request_body (http.request_body;
  content:"NEVER-MARKER")` fails, so the HTTP1 `request_body` per-state default
  policy (`drop:flow,alert`) drops the flow at pkt 12.

Foreign LTE rules, each with a numeric hook that overlaps an HTTP/1 state and
raw content bytes present in the request (`/index`):

* sid:200 `tls:<client_hello` (hook 1 = `request_line`), raw content match.
* sid:201 `tls:<client_cert` (hook 2), out of scope (`198.51.100.0/24`).
* sid:202 `smtp:<request_data` (hook 1).
* sid:203 `http2:stream:<request_headers` (hook 1).

## Expected

The verdict sequence is exactly the HTTP/1 baseline, unchanged by the foreign
rules:

* sid:100 alert at pkt 6, `firewall.hook: http:request_line`,
  `firewall.policy: accept:hook,alert`, action `allowed`.
* default app policy drop at pkt 12, to_server, with the policy alert sid
  2201001, `firewall.hook: http:request_body`,
  `firewall.policy: drop:flow,alert`, action `blocked`.
* flow drop, `flow.alerted: true`.
* sid:101 stays silent; sids 200-203 emit no alert; no `firewall rules` drop;
  sid:9001 (scaffolding) stays silent.

## Baseline comparison

The foreign-free baseline is the same test with the sid:200-203 rules removed.
Both runs produce a byte-identical alert/drop/flow event sequence (same sids,
`pcap_cnt`, `firewall.hook`, `firewall.policy`, drop reasons). Verified with:

```
python3 run.py --testdir tests/firewall --exact ruletype-firewall-284-lte-mixed-proto-http1-flow
# then rerun with the foreign rules deleted and diff the two eve.json event
# sequences (alert, drop, flow); they match exactly.
```

## Related

Redmine #8944.
