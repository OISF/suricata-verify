# ruletype-firewall-310-lte-http1-ts-request-headers-single-content-nomatch

LTE (`<`) state matrix, http1 ts `request_headers`, case `single-content-nomatch`.

< rule with a non-matching http.host keyword: the no match becomes final at S + 1 and the per-state default policy drops the flow at S.

The opposite direction carries one scaffolding `accept:hook <last-state`
rule so its default policy does not drop the flow before this direction
reaches S + 1, where a phase no match becomes final.
