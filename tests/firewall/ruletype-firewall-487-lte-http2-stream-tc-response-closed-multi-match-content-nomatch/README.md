# ruletype-firewall-487-lte-http2-stream-tc-response-closed-multi-match-content-nomatch

LTE (`<`) state matrix, http2:stream tc `response_closed`, case `multi-match-content-nomatch`.

A matching rule for S and a failing keyword rule for another state: the match decides.

The opposite direction and the untested http2 tx type carry
scaffolding `accept:hook <last-state` rules so their default policies
do not drop the flow before the tested state is reached.
