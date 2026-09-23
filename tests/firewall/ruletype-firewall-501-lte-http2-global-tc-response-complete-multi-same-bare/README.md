# ruletype-firewall-501-lte-http2-global-tc-response-complete-multi-same-bare

LTE (`<`) state matrix, http2:global tc `response_complete`, case `multi-same-bare`.

Two bare < rules at S: the first one accepts.

The opposite direction and the untested http2 tx type carry
scaffolding `accept:hook <last-state` rules so their default policies
do not drop the flow before the tested state is reached.
