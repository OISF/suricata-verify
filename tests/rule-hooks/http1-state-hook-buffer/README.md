State hook combined with a buffer registered at another state.

`http.header` is registered at the request-headers state, so a rule hooked at
`http1:request_trailer` needs that engine clamped to the hook to be accepted. Before the fix the
rule was rejected while loading, and the transaction was never inspected at the trailer state.

Chunked POST with a `Server-Timing` trailer. Only the hook rule alerting is asserted; matching
trailer *content* is separate work (trailer buffers), so it is not covered here.

With the trailer buffers in place the rule is decided at the state its buffer completes
in, not at the hooked state; the timing question is covered by
`http1-state-hook-buffer-timing`.
