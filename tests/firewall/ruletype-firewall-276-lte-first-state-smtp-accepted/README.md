# ruletype-firewall-276-lte-first-state-smtp-accepted

LTE (`<`) rule at the protocol's first to-server state (progress 0): accepted,
and equivalent to the plain hook.

## Scenario

`accept:flow,alert smtp:<request_started $HOME_NET any -> $EXTERNAL_NET any (sid:100;)`.

`smtp:<request_started` is the auto-accept (`<hook`) form at the protocol's
first to-server state. There are no prior states to cover, so
`<request_started` behaves exactly like the plain `smtp:request_started` hook.

smtp has separate to-server (`request_*`) and to-client (`response_*`) state
tables, so this also pins that the first state is resolved against the correct
axis.

The opposite direction carries one scaffolding `accept:hook <last-state`
rule so its default policy does not drop the flow.

## Expected

0 `firewall default app policy` drops; the flow is accepted with
`flow.alerted: true`.

## Related

Redmine #8944 (auto-accept-prior-states / `<hook` handling); 263 covers the
same invariant for http1, 275 for tls.
