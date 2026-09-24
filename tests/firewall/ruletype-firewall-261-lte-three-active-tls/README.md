# ruletype-firewall-261-lte-three-active-tls

More than two active LTE (`<hook`) rules in one direction (tls toserver),
all at the same hook.

## Scenario

Three LTE rules with hook `tls:<client_cert`:

* sid:100 `tls.version:1.3` (no match)
* sid:101 `tls.version:1.1` (no match)
* sid:102 `tls.version:1.2` (match)

All three are pending in the same pass. The accounting keeps the highest hook
with its owner, the highest hook among the others and a "more than one" flag;
the two failures must not apply the default policy for the hook (they count
each other as pending coverage), and sid:102 matches and accepts the flow.

The opposite direction gets one scaffolding `accept:hook <last-state` rule so
its default policy does not drop the flow first.

## Expected

sid:102 accepts the flow (alert at `tls:client_cert`); no default app policy
drop; neither sid:100 nor sid:101 alerts.

## Related

Redmine #8944 (auto-accept-prior-states / `<hook` handling);
sibling test 260 (http1).
