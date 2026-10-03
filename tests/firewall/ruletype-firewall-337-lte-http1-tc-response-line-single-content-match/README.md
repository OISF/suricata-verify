# ruletype-firewall-337-lte-http1-tc-response-line-single-content-match

LTE (`<`) state matrix, http1 tc `response_line`, case `single-content-match`.

< rule with a matching http.stat_code keyword: accepts at S.

The opposite direction carries one scaffolding `accept:hook <last-state`
rule so its default policy does not drop the flow before this direction
reaches S + 1, where a phase no match becomes final.
