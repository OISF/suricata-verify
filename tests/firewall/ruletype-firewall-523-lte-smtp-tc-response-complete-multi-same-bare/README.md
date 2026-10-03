# ruletype-firewall-523-lte-smtp-tc-response-complete-multi-same-bare

LTE (`<`) state matrix, smtp tc `response_complete`, case `multi-same-bare`.

Two bare < rules at S: the first one accepts.

The opposite direction carries one scaffolding `accept:hook <last-state`
rule so its default policy does not drop the flow before this direction
reaches S + 1, where a phase no match becomes final.
