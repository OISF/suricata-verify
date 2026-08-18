Test that the global default-policy supplies the policy for every hook, packet
and app-layer alike.

It is the last tier consulted, so with no rules and nothing more specific
configured it decides all of them. The built-ins it displaces would otherwise
drop: drop:packet at the filter hook and drop:flow at the app hooks. Instead the
TLS session runs to completion with all 62 packets accepted, no drop events, and
no action recorded on the flow.
