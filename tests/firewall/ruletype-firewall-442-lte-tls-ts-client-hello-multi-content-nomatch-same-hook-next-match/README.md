# ruletype-firewall-442-lte-tls-ts-client-hello-multi-content-nomatch-same-hook-next-match

LTE (`<`) state matrix, tls ts `client_hello`, case `multi-content-nomatch-same-hook-next-match`.

Two failing keyword rules for S and a matching non-LTE rule for S + 1: the first S rule resolves and retires from the coverage, the second applies the default policy for S, and the later match cannot rescue the flow.

The opposite direction carries one scaffolding `accept:hook <last-state`
rule so its default policy does not drop the flow before this direction
reaches S + 1, where a phase no match becomes final.
