# ruletype-firewall-536-lte-tls-tc-server-hello-multi-out-of-scope-sibling-nomatch

LTE (`<`) state matrix, tls tc `server_hello`, case `multi-out-of-scope-sibling-nomatch`.

A failing keyword rule at S and an out of scope sibling last by sid: the sibling neither covers S nor hides the state default.

The opposite direction carries one scaffolding `accept:hook <last-state`
rule so its default policy does not drop the flow before this direction
reaches S + 1, where a phase no match becomes final.
