# ruletype-firewall-301-lte-http1-ts-request-line-single-content-match

LTE (`<`) state matrix, http1 ts `request_line`, case `single-content-match`.

< rule with a matching http.uri keyword: accepts at S.

The opposite direction carries one scaffolding `accept:hook <last-state`
rule so its default policy does not drop the flow before this direction
reaches S + 1, where a phase no match becomes final.
