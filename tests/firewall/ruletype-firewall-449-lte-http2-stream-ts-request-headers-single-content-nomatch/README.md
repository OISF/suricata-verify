# ruletype-firewall-449-lte-http2-stream-ts-request-headers-single-content-nomatch

LTE (`<`) state matrix, http2:stream ts `request_headers`, case `single-content-nomatch`.

< rule with a non-matching http2.header_name keyword: the no match becomes final at S + 1 and the per-state default policy drops the flow at S.

The opposite direction and the untested http2 tx type carry
scaffolding `accept:hook <last-state` rules so their default policies
do not drop the flow before the tested state is reached.
