# ruletype-firewall-479-lte-http2-stream-tc-response-data-multi-same-bare

LTE (`<`) state matrix, http2:stream tc `response_data`, case `multi-same-bare`.

Two bare < rules at S: the first one accepts.

The opposite direction and the untested http2 tx type carry
scaffolding `accept:hook <last-state` rules so their default policies
do not drop the flow before the tested state is reached.
