# ruletype-firewall-275-lte-first-state-tls-accepted

LTE (`<`) rule at the protocol's first to-server state (progress 0): accepted,
and equivalent to the plain hook.

## Scenario

`accept:flow,alert tls:<client_started $HOME_NET any -> $EXTERNAL_NET any (sid:100;)`.

`tls:<client_started` is the auto-accept (`<hook`) form at the protocol's first
to-server state. There are no prior states to cover, so `<client_started`
behaves exactly like the plain `tls:client_started` hook: the rule accepts the
flow at the first client packet (pcap_cnt 4) with hook `tls:client_started`.

The opposite direction carries one scaffolding `accept:hook <last-state`
rule so its default policy does not drop the flow.

## Expected

0 `firewall default app policy` drops; the flow is accepted with
`flow.alerted: true`.

## Related

Redmine #8944 (auto-accept-prior-states / `<hook` handling); 263 covers the
same invariant for http1, 276 for smtp.
