# ruletype-firewall-433-lte-tls-ts-client-hello-multi-content-nomatch-next-match

LTE (`<`) state matrix, tls ts `client_hello`, case `multi-content-nomatch-next-match`.

A failing keyword rule for S and a matching non-LTE rule for S + 1: the rule for S resolves when the tx advances past it, so the default policy for S applies and the later match cannot rescue the flow.

The opposite direction carries one scaffolding `accept:hook <last-state`
rule so its default policy does not drop the flow before this direction
reaches S + 1, where a phase no match becomes final.
