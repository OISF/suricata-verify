# ruletype-firewall-538-lte-http2-stream-tc-response-headers-multi-out-of-scope-sibling-nomatch

LTE (`<`) state matrix, http2:stream tc `response_headers`, case `multi-out-of-scope-sibling-nomatch`.

A failing keyword rule at S and an out of scope sibling last by sid: the sibling neither covers S nor hides the state default.

The opposite direction and the untested http2 tx type carry
scaffolding `accept:hook <last-state` rules so their default policies
do not drop the flow before the tested state is reached.
