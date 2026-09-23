Test that a dataset of type `ip`, declared in the `datasets:` section of the
configuration, accepts plain IPv4 addresses (dotted-quad notation) in the file
it loads, and that the loaded entries match IPv4 traffic.

Before this was supported, a bare `1.1.1.1` in a `type: ip` set was rejected
with "invalid Ipv6 value" and engine initialization failed; only the
`::ffff:1.1.1.1` notation was accepted.
