# ruletype-firewall-482-lte-http2-stream-tc-response-data-multi-match-ip-nomatch

LTE (`<`) state matrix, http2:stream tc `response_data`, case `multi-match-ip-nomatch`.

An out of scope rule and a matching bare rule at S: the out of scope rule must not disturb the match.

The opposite direction and the untested http2 tx type carry
scaffolding `accept:hook <last-state` rules so their default policies
do not drop the flow before the tested state is reached.
