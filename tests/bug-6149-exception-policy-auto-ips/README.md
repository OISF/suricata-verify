Test
====

Check and capture the behavior when Suricata is run with `exception-policy:
auto` set in IPS mode.

Behavior
========

We expect the master switch for exception policy to be set to `drop-flow` in this
case, as that's the default value in IPS.

We also don't expect to see any Warning message in that case, as that's expected
behavior. We will see an info log output, as that's the level specified for this
test.
