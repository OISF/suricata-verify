# ruletype-firewall-336-lte-http1-tc-response-line-single-bare

LTE (`<`) state matrix, http1 tc `response_line`, case `single-bare`.

Bare < rule: the prior states are auto-accepted and the rule accepts the flow at S.

The opposite direction carries one scaffolding `accept:hook <last-state`
rule so its default policy does not drop the flow before this direction
reaches S + 1, where a phase no match becomes final.
