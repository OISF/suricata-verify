# ruletype-firewall-420-lte-tls-tc-server-data-single-bare

LTE (`<`) state matrix, tls tc `server_data`, case `single-bare`.

Bare < rule: the prior states are auto-accepted and the rule accepts the flow at S.

The opposite direction carries one scaffolding `accept:hook <last-state`
rule so its default policy does not drop the flow before this direction
reaches S + 1, where a phase no match becomes final.
