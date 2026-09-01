# ruletype-firewall-230-lte-out-of-scope-address

Regression test: an auto-accept-prior-states (`<hook`) rule must not provide
pending-phase coverage when its header/packet predicates (address, port, proto,
...) do not match the flow.

## Scenario

Two to_server rules at `tls:client_hello` (hook 1):

* `accept:flow tls:client_hello ... (tls.sni; content:"www.google.com";)` —
  the head rule; matching address and keyword (the pcap SNI is
  www.google.com).
* `accept:flow tls:<client_hello 198.51.100.0/24 any -> 198.51.100.0/24 any
  (alert;)` — a `<hook` rule scoped to 198.51.100.0/24. The flow is
  10.16.1.11 -> 24.244.4.23, so this rule can never match and is not a valid
  covering rule for any prior state.

Since the `<` rule is out of scope, the prior state `client_started` is not
covered by any applicable pending rule, and the default app policy must drop it.
If the in-progress LTE candidate scan counted the out-of-scope rule before its
header predicates were checked, the head-gap default drop would be suppressed
and the matching `accept:flow` head rule would accept the flow before the
inapplicable LTE rule is inspected (per-state false accept).

## Expected

* 1 to_server `firewall default app policy` drop (client_started).

## Related

Redmine #8944 (auto-accept-prior-states / `<hook` handling).
