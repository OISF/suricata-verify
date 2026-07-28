Test that a sub state with no default-policy of its own falls through to the
per-protocol default-policy.


app.http2.default-policy is drop:flow and app.http2.stream.default-policy is
accept:hook. Only stream has a default of its own but the connection-level
global sub state does not, so its hooks fall through one tier and drop the flow
at packet 4, before any stream hook gets a turn and before the http2 parser
registers the flow. The alert shows that it picked up the protocol default.