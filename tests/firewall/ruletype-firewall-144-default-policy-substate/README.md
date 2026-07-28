Test that a sub state's default-policy takes precedence over the per-protocol
default-policy.

Also test that a packet filter and sub state with no default-policy of its own
(http2.global) falls through default-policy to up to the global level.