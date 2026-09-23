# ruletype-firewall-520-lte-smtp-tc-response-data-multi-match-ip-nomatch

LTE (`<`) state matrix, smtp tc `response_data`, case `multi-match-ip-nomatch`.

An out of scope rule and a matching bare rule at S: the out of scope rule must not disturb the match.

The opposite direction carries one scaffolding `accept:hook <last-state`
rule so its default policy does not drop the flow before this direction
reaches S + 1, where a phase no match becomes final.
