# ruletype-firewall-410-lte-tls-tc-server-hello-multi-match-content-nomatch

LTE (`<`) state matrix, tls tc `server_hello`, case `multi-match-content-nomatch`.

A matching rule for S and a failing keyword rule for another state: the match decides.

The opposite direction carries one scaffolding `accept:hook <last-state`
rule so its default policy does not drop the flow before this direction
reaches S + 1, where a phase no match becomes final.
