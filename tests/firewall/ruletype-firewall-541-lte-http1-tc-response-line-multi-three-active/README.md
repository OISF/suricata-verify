# ruletype-firewall-541-lte-http1-tc-response-line-multi-three-active

LTE (`<`) state matrix, http1 tc `response_line`, case `multi-three-active`.

Three active keyword rules at S: the coverage accounting keeps the two failing siblings from applying the state default before the matching rule accepts.

The opposite direction carries one scaffolding `accept:hook <last-state`
rule so its default policy does not drop the flow before this direction
reaches S + 1, where a phase no match becomes final.
