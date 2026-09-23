# ruletype-firewall-471-lte-http2-stream-tc-response-headers-single-content-match

LTE (`<`) state matrix, http2:stream tc `response_headers`, case `single-content-match`.

< rule with a matching http2.header_name keyword: accepts at S.

The opposite direction and the untested http2 tx type carry
scaffolding `accept:hook <last-state` rules so their default policies
do not drop the flow before the tested state is reached.
