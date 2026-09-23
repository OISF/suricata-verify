# ruletype-firewall-486-lte-http2-stream-tc-response-closed-multi-states

LTE (`<`) state matrix, http2:stream tc `response_closed`, case `multi-states`.

Two bare < rules at different states: the rule for the earlier state accepts.

The opposite direction and the untested http2 tx type carry
scaffolding `accept:hook <last-state` rules so their default policies
do not drop the flow before the tested state is reached.
