# ruletype-firewall-531-lte-http2-stream-tc-response-headers-multi-out-of-scope-sibling

LTE (`<`) state matrix, http2:stream tc `response_headers`, case `multi-out-of-scope-sibling`.

A matching rule at S and an out of scope sibling last by sid: the trailing candidate must not disturb the accept and must not add pending coverage.

The opposite direction and the untested http2 tx type carry
scaffolding `accept:hook <last-state` rules so their default policies
do not drop the flow before the tested state is reached.
