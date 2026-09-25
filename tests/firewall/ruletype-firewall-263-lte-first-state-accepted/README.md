# ruletype-firewall-263-lte-first-state-accepted

LTE (`<`) rule at the protocol's first state (progress 0): accepted, and
equivalent to the plain hook.

## Scenario

`accept:flow,alert http1:<request_started $HOME_NET any -> $EXTERNAL_NET any (sid:100;)`.

The first state has no prior states to auto-accept, so `<request_started`
behaves exactly like the plain `http1:request_started` hook: the rule accepts
the flow at the first request packet (pcap_cnt 4) with hook
`http:request_started`.

The opposite direction carries one scaffolding `accept:hook <last-state`
rule so its default policy does not drop the flow.

## Expected

0 `firewall default app policy` drops; the flow is accepted with
`flow.alerted: true`.

## Note

The rule is bare: no http1 keyword is registered at `request_started`. A
content keyword registered at a later state still fails the engine-progress
validation (`http.uri` is registered at `request_line`, so hook
`request_started` with `http.uri` is rejected independently of the
first-state handling).

## Related

Redmine #8944 (auto-accept-prior-states / `<hook` handling).
