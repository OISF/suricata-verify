# ruletype-firewall-519-lte-smtp-tc-response-data-multi-states

LTE (`<`) state matrix, smtp tc `response_data`, case `multi-states`.

Two bare < rules at different states: the rule for the earlier state accepts.

The opposite direction carries one scaffolding `accept:hook <last-state`
rule so its default policy does not drop the flow before this direction
reaches S + 1, where a phase no match becomes final.
