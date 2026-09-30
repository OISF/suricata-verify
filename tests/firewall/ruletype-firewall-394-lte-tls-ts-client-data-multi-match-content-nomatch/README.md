# ruletype-firewall-394-lte-tls-ts-client-data-multi-match-content-nomatch

LTE (`<`) state matrix, tls ts `client_data`, case `multi-match-content-nomatch`.

A matching rule for S and a failing keyword rule for another state: the match decides.

The opposite direction carries one scaffolding `accept:hook <last-state`
rule so its default policy does not drop the flow before this direction
reaches S + 1, where a phase no match becomes final.
