Test that a default app policy of accept:flow,alert behaves like accept:flow:
it should accept the flow and stop evaluating later firewall app defaults, while
still logging the default-policy alert.
