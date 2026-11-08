# ruletype-firewall-283-lte-mixed-proto-tls-flow

Cross-protocol LTE (`<hook`) isolation on a TLS flow: a mixed ruleset where the
TLS rules and foreign-protocol rules (http1, smtp, http2) share one firewall
ruleset. The foreign rules must not contribute coverage to the TLS transaction.

## Scenario

`tests/tls/tls-client-hello-frag-01/dump_mtu300.pcap` (ClientHello SNI
`www.google.com`).

TLS rules:

* sid:100 `accept:hook,alert tls:<client_hello (tls.sni; content:"www.google.com")`
  matches the SNI at `client_hello` (pkt 6) and accepts the hook.
  `accept:hook` (not `accept:flow`) is used so the later state default can still
  fire; an `accept:flow` would carry the flow and mask it.
* sid:101 `accept:flow,alert tls:<client_cert (tls.version:1.3)` fails (the
  fixture is TLS 1.2), so the TLS `client_cert` per-state default policy
  (`drop:flow,alert`) drops the flow at pkt 22.

Foreign LTE rules, each with a numeric hook that overlaps a TLS state and raw
content bytes present in the ClientHello (`www.google.com`), so a
protocol-blind MPM would select them:

* sid:200 `http1:<request_line` (hook 1 = `client_hello`), raw content match.
* sid:201 `http1:<request_headers` (hook 2 = `client_cert`), out of scope
  (`198.51.100.0/24`).
* sid:202 `smtp:<request_data` (hook 1).
* sid:203 `http2:stream:<request_headers` (hook 1).

## Expected

The verdict sequence is exactly the TLS baseline, unchanged by the foreign
rules:

* sid:100 alert at pkt 6, `firewall.hook: tls:client_hello`,
  `firewall.policy: accept:hook,alert`, action `allowed`.
* default app policy drop at pkt 22, to_server, with the policy alert sid
  2201001, `firewall.hook: tls:client_cert`,
  `firewall.policy: drop:flow,alert`, action `blocked`.
* flow drop, `flow.alerted: true`.
* sid:101 stays silent; sids 200-203 emit no alert; no `firewall rules` drop;
  sid:9001 (scaffolding) stays silent.

## Baseline comparison

The foreign-free baseline is the same test with the sid:200-203 rules removed.
Both runs produce a byte-identical alert/drop/flow event sequence (same sids,
`pcap_cnt`, `firewall.hook`, `firewall.policy`, drop reasons). Verified with:

```
python3 run.py --testdir tests/firewall --exact ruletype-firewall-283-lte-mixed-proto-tls-flow
# then rerun with the foreign rules deleted and diff the two eve.json event
# sequences (alert, drop, flow); they match exactly.
```

## Related

The firewalls rules all share one ruleset. Isolation is enforced by the
per-alproto transaction prefilter engines: a foreign rule is never a candidate
for a TLS transaction (its engine is skipped because the flow alproto does not
match). See Redmine #8944.

The cross-protocol rules here use buffer matches: an `<hook` rule cannot match the raw
stream (see ruletype-firewall-615-lte-stream-match-rejected).
