# ruletype-firewall-499-lte-http2-global-tc-response-complete-single-bare

LTE (`<`) state matrix, http2:global tc `response_complete`, case `single-bare`.

Bare < rule: the prior states are auto-accepted and the rule accepts the flow at S.

The opposite direction and the untested http2 tx type carry
scaffolding `accept:hook <last-state` rules so their default policies
do not drop the flow before the tested state is reached.
