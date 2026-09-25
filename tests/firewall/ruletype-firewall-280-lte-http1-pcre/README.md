# ruletype-firewall-280-lte-http1-pcre

LTE (`<`) pcre coverage cell for http1 to-server `request_headers`: the same
geometry as the single-content-match cell, but the predicate is a `pcre` on
`http.host` instead of a `content` match.

The matching `<` rule accepts the flow at packet 10, where the request
headers are inspected and the host buffer is available.

The opposite direction carries one scaffolding `accept:hook <last-state`
rule so its default policy does not drop the flow before this direction
reaches S + 1, where a phase no match becomes final.
