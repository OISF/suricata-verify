# ruletype-firewall-302-lte-http1-ts-request-line-single-content-nomatch

LTE (`<`) state matrix, http1 ts `request_line`, case `single-content-nomatch`.

< rule with a non-matching http.uri keyword: the no match becomes final at S + 1 and the per-state default policy drops the flow at S.

The opposite direction carries one scaffolding `accept:hook <last-state`
rule so its default policy does not drop the flow before this direction
reaches S + 1, where a phase no match becomes final.
