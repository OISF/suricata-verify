# ruletype-firewall-325-lte-http1-ts-request-trailer-single-ip-nomatch

LTE (`<`) state matrix, http1 ts `request_trailer`, case `single-ip-nomatch`.

Out of scope < rule: it provides no pending coverage, so the default policy for S is applied.

The opposite direction carries one scaffolding `accept:hook <last-state`
rule so its default policy does not drop the flow before this direction
reaches S + 1, where a phase no match becomes final.
