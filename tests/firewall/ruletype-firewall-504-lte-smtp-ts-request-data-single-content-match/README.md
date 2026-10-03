# ruletype-firewall-504-lte-smtp-ts-request-data-single-content-match

LTE (`<`) state matrix, smtp ts `request_data`, case `single-content-match`.

< rule with a matching email.from keyword: accepts at S.

The opposite direction carries one scaffolding `accept:hook <last-state`
rule so its default policy does not drop the flow before this direction
reaches S + 1, where a phase no match becomes final.
