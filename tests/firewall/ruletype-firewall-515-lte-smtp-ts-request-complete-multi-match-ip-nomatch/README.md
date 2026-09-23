# ruletype-firewall-515-lte-smtp-ts-request-complete-multi-match-ip-nomatch

LTE (`<`) state matrix, smtp ts `request_complete`, case `multi-match-ip-nomatch`.

An out of scope rule and a matching bare rule at S: the out of scope rule must not disturb the match.

The opposite direction carries one scaffolding `accept:hook <last-state`
rule so its default policy does not drop the flow before this direction
reaches S + 1, where a phase no match becomes final.
