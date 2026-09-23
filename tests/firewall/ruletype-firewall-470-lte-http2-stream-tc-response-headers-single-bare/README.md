# ruletype-firewall-470-lte-http2-stream-tc-response-headers-single-bare

LTE (`<`) state matrix, http2:stream tc `response_headers`, case `single-bare`.

Bare < rule: the prior states are auto-accepted and the rule accepts the flow at S.

The opposite direction and the untested http2 tx type carry
scaffolding `accept:hook <last-state` rules so their default policies
do not drop the flow before the tested state is reached.
