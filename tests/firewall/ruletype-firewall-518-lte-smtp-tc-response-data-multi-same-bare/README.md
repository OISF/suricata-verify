# ruletype-firewall-518-lte-smtp-tc-response-data-multi-same-bare

LTE (`<`) state matrix, smtp tc `response_data`, case `multi-same-bare`.

Two bare < rules at S: the first one accepts.

The opposite direction carries one scaffolding `accept:hook <last-state`
rule so its default policy does not drop the flow before this direction
reaches S + 1, where a phase no match becomes final.
