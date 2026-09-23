# ruletype-firewall-307-lte-http1-ts-request-line-multi-match-ip-nomatch

LTE (`<`) state matrix, http1 ts `request_line`, case `multi-match-ip-nomatch`.

An out of scope rule and a matching bare rule at S: the out of scope rule must not disturb the match.

The opposite direction carries one scaffolding `accept:hook <last-state`
rule so its default policy does not drop the flow before this direction
reaches S + 1, where a phase no match becomes final.
