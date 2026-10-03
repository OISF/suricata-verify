# ruletype-firewall-396-lte-tls-ts-client-finished-single-bare

LTE (`<`) state matrix, tls ts `client_finished`, case `single-bare`.

Bare < rule: the prior states are auto-accepted and the rule accepts the flow at S.

The opposite direction carries one scaffolding `accept:hook <last-state`
rule so its default policy does not drop the flow before this direction
reaches S + 1, where a phase no match becomes final.
