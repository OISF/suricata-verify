# ruletype-firewall-571-lte-http1-tc-response-trailer-single-content-match

LTE (`<`) state matrix, http1 tc `response_trailer`, case `single-content-match`.

< rule with a matching http.trailer keyword: accepts at S.

The opposite direction carries one scaffolding `accept:hook <last-state`
rule so its default policy does not drop the flow before this direction
reaches S + 1, where a phase no match becomes final.
