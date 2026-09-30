# ruletype-firewall-505-lte-smtp-ts-request-data-single-content-nomatch

LTE (`<`) state matrix, smtp ts `request_data`, case `single-content-nomatch`.

< rule with a non-matching email.from keyword: the no match becomes final at S + 1 and the per-state default policy drops the flow at S.

The opposite direction carries one scaffolding `accept:hook <last-state`
rule so its default policy does not drop the flow before this direction
reaches S + 1, where a phase no match becomes final.
