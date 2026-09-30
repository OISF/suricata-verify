# ruletype-firewall-496-lte-http2-global-ts-request-complete-single-ip-nomatch

LTE (`<`) state matrix, http2:global ts `request_complete`, case `single-ip-nomatch`.

Out of scope < rule: it provides no pending coverage, so the default policy for S is applied.

The opposite direction and the untested http2 tx type carry
scaffolding `accept:hook <last-state` rules so their default policies
do not drop the flow before the tested state is reached.
