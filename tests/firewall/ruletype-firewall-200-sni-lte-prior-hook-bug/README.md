Test that auto-accept-prior-states (`<`) on a catch-all accept covers the prior app-layer hook when a lower-SID same-hook drop rule with a matching prefilter leads the candidate list.
Rules drop TLS SNI "www.google.com" (sid:200) and accept other SNI via `accept:flow tls:<client_hello` (sid:201), with no explicit `accept:hook tls:client_started`.
Expected: sid:200 drops the flow with an alert. Before the fix, the flow was dropped by the default app policy at client_started and sid:200 never fired; regression test for that bug.

