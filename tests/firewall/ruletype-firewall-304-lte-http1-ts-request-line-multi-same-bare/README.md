# ruletype-firewall-304-lte-http1-ts-request-line-multi-same-bare

LTE (`<`) state matrix, http1 ts `request_line`, case `multi-same-bare`.

Two bare < rules at S: the first one accepts.

The opposite direction carries one scaffolding `accept:hook <last-state`
rule so its default policy does not drop the flow before this direction
reaches S + 1, where a phase no match becomes final.
