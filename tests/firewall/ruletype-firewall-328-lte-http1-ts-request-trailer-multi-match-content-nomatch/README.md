# ruletype-firewall-328-lte-http1-ts-request-trailer-multi-match-content-nomatch

LTE (`<`) state matrix, http1 ts `request_trailer`, case `multi-match-content-nomatch`.

A matching rule for S and a failing keyword rule for another state: the match decides.

The opposite direction carries one scaffolding `accept:hook <last-state`
rule so its default policy does not drop the flow before this direction
reaches S + 1, where a phase no match becomes final.
