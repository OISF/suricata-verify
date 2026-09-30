Test that auto-accept-prior-states (`<`) on a catch-all accept covers the prior app-layer hook when a lower-SID same-hook drop rule with a matching prefilter leads the candidate list.
Rules drop TLS SNI "www.google.com" (sid:200) and accept other SNI via `accept:flow tls:<client_hello_done` (sid:201), with no explicit `accept:hook tls:client_in_progress`.
Expected: sid:200 drops the flow with an alert. Actual (buggy): the flow is dropped by the default app policy at client_in_progress and sid:200 never fires. Asserts the expected behaviour, so currently FAILS.
Workaround: add `accept:hook tls:<client_in_progress` to explicitly cover the prior hook.

