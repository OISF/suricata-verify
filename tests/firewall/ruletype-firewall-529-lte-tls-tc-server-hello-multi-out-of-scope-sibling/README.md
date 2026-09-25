# ruletype-firewall-529-lte-tls-tc-server-hello-multi-out-of-scope-sibling

LTE (`<`) state matrix, tls tc `server_hello`, case `multi-out-of-scope-sibling`.

A matching rule at S and an out of scope sibling last by sid: the trailing candidate must not disturb the accept and must not add pending coverage.

The opposite direction carries one scaffolding `accept:hook <last-state`
rule so its default policy does not drop the flow before this direction
reaches S + 1, where a phase no match becomes final.
