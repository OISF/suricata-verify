# ruletype-firewall-331-lte-http1-ts-request-complete-single-ip-nomatch

LTE (`<`) state matrix, http1 ts `request_complete`, case `single-ip-nomatch`.

Out of scope < rule: it provides no pending coverage, so the default policy for S is applied.

The opposite direction carries one scaffolding `accept:hook <last-state`
rule so its default policy does not drop the flow before this direction
reaches S + 1, where a phase no match becomes final.
