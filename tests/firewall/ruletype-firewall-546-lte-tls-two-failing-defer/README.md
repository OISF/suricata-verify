# ruletype-firewall-546-lte-tls-two-failing-defer

Pins the `<hook` (LTE) deferral semantics when two rules at different states
both fail. This is a standalone test (not produced by
`../generate-lte-state-matrix.py`).

## Scenario

Two toserver `<` rules both fail on the fragmented TLS ClientHello in
`../../tls/tls-client-hello-frag-01/dump_mtu300.pcap`:

* sid:100 `accept:flow,alert tls:<client_hello (tls.version:1.3;)` fails.
* sid:101 `accept:flow,alert tls:<client_cert (tls.version:1.3;)` fails.

Per-state app default policies (`suricata.yaml`):

* `tls.client-hello`: `["drop:flow", "alert"]`
* `tls.client-cert`: `["accept:hook"]`
* `tls.default-policy`: `["accept:hook"]` (fallback for the unnamed states)

## Current semantics (pinned)

A failing `<` rule *defers* the per-state defaults of the states it promised to
cover; the last pending covering rule decides them. sid:101 is that last rule,
so its own hook default (`accept`) applies and its forward sweep covers the
states above its hook. Because sid:101 only sweeps forward from its own hook,
the lower state `tls:client_hello` gets no default: its `drop:flow` is never
applied.

Verdict pinned here: accept. No `firewall default app policy` drop, no
`tls:client_hello` policy alert (sid 2201001), no rule match alerts.

A future fix that back-fills the covered lower states would apply the
`tls:client_hello` drop and fail this test; that semantic change needs its own
decision (see the F item of the review).

## Related

Redmine #8944.
