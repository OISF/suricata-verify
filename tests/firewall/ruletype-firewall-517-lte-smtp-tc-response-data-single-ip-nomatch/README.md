# ruletype-firewall-517-lte-smtp-tc-response-data-single-ip-nomatch

LTE (`<`) state matrix, smtp tc `response_data`, case `single-ip-nomatch`.

Out of scope < rule: it provides no pending coverage, so the default policy for S is applied.

The opposite direction carries one scaffolding `accept:hook <last-state`
rule so its default policy does not drop the flow before this direction
reaches S + 1, where a phase no match becomes final.
