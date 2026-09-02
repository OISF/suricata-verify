Test that an LTE HTTP/1 request-body rule remains provisional while more body
data can arrive at the same parser progress.

The POST body is split across three TCP segments. The first body segment
contains the fast-pattern `first-body-`, making the LTE rule a candidate, but
not the later required content `second-body`. The second segment supplies that
content while the transaction is still at `request_body`; the final segment
completes the declared body.

The rule must remain eligible after the first segment, match on the second, and
accept the flow. Treating the first provisional `NO_MATCH` as `CANT_MATCH`
invokes the flow-scoped default drop before the later body data arrives.
