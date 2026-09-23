# ruletype-firewall-400-lte-tls-ts-client-finished-multi-same-bare

LTE (`<`) state matrix, tls ts `client_finished`, case `multi-same-bare`.

Two bare < rules at S: the first one accepts.

The opposite direction carries one scaffolding `accept:hook <last-state`
rule so its default policy does not drop the flow before this direction
reaches S + 1, where a phase no match becomes final.
