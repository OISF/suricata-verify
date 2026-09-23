# ruletype-firewall-333-lte-http1-ts-request-complete-multi-states

LTE (`<`) state matrix, http1 ts `request_complete`, case `multi-states`.

Two bare < rules at different states: the rule for the earlier state accepts.

The opposite direction carries one scaffolding `accept:hook <last-state`
rule so its default policy does not drop the flow before this direction
reaches S + 1, where a phase no match becomes final.
